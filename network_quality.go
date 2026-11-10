package tlsforge

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/networkquality"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	quic "github.com/igor-lemon/quic-go-utls"
	tls_client "github.com/igor-lemon/tls-client"
)

// NetworkContext describes actual metadata, separately from browser persona or estimates.
type NetworkContext = networkquality.Context

type networkObserver struct {
	state    *networkquality.State
	policy   networkquality.Policy
	sequence atomic.Uint64
	initial  *NetworkContext
	input    func(networkquality.EnvironmentPolicy, *NetworkContext) (NetworkContext, error)
}

func newNetworkObserver(p *profile.Profile, initial *NetworkContext) (*networkObserver, error) {
	if p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" {
		if initial != nil {
			return nil, fmt.Errorf("network context requires an estimated network_hints profile")
		}
		return nil, nil
	}
	pol := p.NetworkHints.Policy.Clone()
	input := pol.Environment.Fallback.Clone()
	if current, err := networkInput(pol.Environment, initial); err == nil {
		input = current
	} else if initial != nil {
		return nil, err
	}
	state, err := networkquality.NewState(pol, input, time.Now, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &networkObserver{state: state, policy: pol, initial: initial, input: networkInput}, nil
}
func (c *Client) prepareNetwork(input *NetworkContext) error {
	load := networkInput
	if c.network != nil {
		load = c.network.input
	}
	return c.prepareNetworkFrom(input, load)
}

func (c *Client) prepareNetworkFrom(input *NetworkContext, load func(networkquality.EnvironmentPolicy, *NetworkContext) (NetworkContext, error)) error {
	n := c.network
	if n == nil {
		if input != nil {
			return fmt.Errorf("network context requires an estimated network_hints profile")
		}
		return nil
	}
	if input == nil {
		input = n.initial
	}
	current, err := load(n.policy.Environment, input)
	if err != nil {
		return fmt.Errorf("profile %q: %w", c.profile.Name, err)
	}
	if err := n.state.ChangeNetwork(current); err != nil {
		return err
	}
	n.state.Bootstrap()
	return nil
}

func (c *Client) networkHintValues(host string) Header {
	values := Header(c.profile.ClientHints).Clone()
	if c.network != nil {
		hints := c.network.state.Hints(gurlHost(host))
		for _, name := range []string{"rtt", "downlink", "ect"} {
			values.Set(name, hints[name])
		}
	}
	return values
}

// gurlHost is host as Chromium's GURL::GetHost says it, which its client
// hints' noise is drawn from (content/browser/client_hints, 156): an IPv6
// address in its brackets.
func gurlHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func (n *networkObserver) publicHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return n.policy.Addresses.LocalhostPublic
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return n.policy.Addresses.Public(ip)
	}
	return n.policy.Addresses.MissingResolutionPublic
}
func (n *networkObserver) publicIP(ip net.IP) bool {
	address, _ := netip.AddrFromSlice(ip)
	return n.policy.Addresses.Public(address)
}
func (n *networkObserver) publicPeer(peer net.Addr) bool {
	if peer == nil {
		return false
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return false
	}
	return n.publicIP(net.ParseIP(host))
}
func ownedNetworkObserver(n *networkObserver, own bool) *networkObserver {
	if own {
		return n
	}
	return nil
}
func (n *networkObserver) wrapTCP(conn net.Conn) net.Conn {
	return &networkConn{Conn: conn, owner: n, id: n.sequence.Add(1) << 1}
}
func (n *networkObserver) transport(observeTCP bool) *tls_client.NetworkObserver {
	return &tls_client.NetworkObserver{
		TCPConnection: func(_ context.Context, conn net.Conn) net.Conn {
			if !observeTCP {
				return conn
			}
			return n.wrapTCP(conn)
		},
		QUIC: func(event quic.NetworkEvent) {
			id := uint64(event.ConnectionID)<<1 | 1
			if event.ReceivedBytes > 0 {
				n.state.Received(event.ReceivedBytes)
			}
			if event.RTT > 0 {
				n.state.ObserveTransport(id, "quic", n.publicPeer(event.RemoteAddr), event.RTT)
			}
			if event.Closed {
				n.state.ForgetSocket(id)
			}
		},
		HTTP2RTT: func(peer net.Addr, rtt time.Duration) {
			if n.policy.Socket.AllowPrivate || n.publicPeer(peer) {
				n.state.ObserveEndToEnd(rtt)
			}
		},
	}
}

type networkConn struct {
	net.Conn
	owner  *networkObserver
	id     uint64
	closed sync.Once
}

// Preserve access to the physical socket for kernel options and diagnostics.
// Reading through this interface does not replace the observed wire I/O path.
func (c *networkConn) SyscallConn() (syscall.RawConn, error) {
	if socket, ok := c.Conn.(syscall.Conn); ok {
		return socket.SyscallConn()
	}
	return nil, fmt.Errorf("underlying connection %T does not expose syscall.Conn", c.Conn)
}

func (c *networkConn) Read(p []byte) (int, error) {
	return c.readWithRTT(p, networkTCPRTT)
}

func (c *networkConn) readWithRTT(p []byte, rttOf func(net.Conn) (time.Duration, bool)) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.owner.state.Received(n)
		if c.owner.policy.Socket.TCPSource == "kernel-tcp-info" {
			if rtt, ok := rttOf(c.Conn); ok {
				c.owner.state.ObserveTransport(c.id, "tcp", c.owner.publicPeer(c.RemoteAddr()), rtt)
			}
		}
	}
	return n, err
}
func (c *networkConn) Close() error {
	err := c.Conn.Close()
	c.closed.Do(func() { c.owner.state.ForgetSocket(c.id) })
	return err
}

type networkCreatedKey struct{}
type networkRecordKey struct{}

// networkRecord survives the response's Request replacement and records early
// EOF/no-body callbacks until the cache has classified a conditional 304.
type networkRecord struct {
	mu                           sync.Mutex
	owner                        *networkObserver
	id                           uint64
	method                       string
	meta                         networkquality.RequestMeta
	start                        networkquality.StartInfo
	sent, headers                time.Time
	ready, started, done, cached bool
	nextStep, headerObserved     bool
}

func (c *Client) networkRoundTrip(ch *chain, req *fhttp.Request, next fhttp.RoundTripper) (*fhttp.Response, error) {
	if c.network == nil {
		return c.session.cache.roundTrip(ch, req, next)
	}
	n := c.network
	created, _ := req.Context().Value(networkCreatedKey{}).(time.Time)
	if created.IsZero() {
		created = time.Now()
	}
	record := &networkRecord{owner: n, id: n.sequence.Add(1), method: req.Method, start: n.state.CaptureStart(), meta: networkquality.RequestMeta{Created: created, Method: req.Method, Public: n.publicHost(req.URL.Hostname()), Navigation: ch.browser != nil && (ch.browser.kind == KindNavigation || ch.browser.kind == KindForm)}}
	ctx := context.WithValue(req.Context(), networkRecordKey{}, record)
	trace := &httptrace.ClientTrace{
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if len(info.Addrs) > 0 {
				record.mu.Lock()
				record.meta.Public = n.publicIP(info.Addrs[0].IP)
				record.mu.Unlock()
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			record.mu.Lock()
			if c.proxy == "" && info.Conn != nil {
				record.meta.Public = n.publicPeer(info.Conn.RemoteAddr())
			}
			record.mu.Unlock()
		},
		WriteHeadersStart: func(method string) {
			if method == record.method {
				record.mu.Lock()
				record.sent = time.Now()
				record.mu.Unlock()
			}
		},
		GotResponseHeaders: func(method string, _ int) {
			if method == record.method {
				record.mu.Lock()
				record.headers = time.Now()
				record.mu.Unlock()
			}
		},
		GotResponseBodyBytes: func(method string, amount int) {
			if method == record.method {
				record.activity(amount)
			}
		},
		GotResponseBodyDone: func(method string) {
			if method == record.method {
				record.complete()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	if n.policy.Compute.TransactionStart == "request" {
		record.mu.Lock()
		record.beginLocked()
		record.mu.Unlock()
	}
	res, err := c.session.cache.roundTrip(ch, req, next)
	record.finish(err != nil)
	return res, err
}
func (r *networkRecord) beginLocked() {
	if !r.started {
		r.started = true
		r.owner.state.StartRequestAt(r.id, r.meta, r.start)
	}
}
func (r *networkRecord) deliverHeadersLocked() {
	if r.headerObserved || r.headers.IsZero() {
		return
	}
	r.headerObserved = true
	r.owner.state.Headers(r.id, r.meta, r.sent, r.headers)
}
func (r *networkRecord) finish(failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = true
	r.meta.Cached = r.cached
	if r.owner.policy.Compute.TransactionStart != "next-step" || r.nextStep || r.done || failed {
		r.beginLocked()
	}
	if r.owner.policy.Compute.HeaderDelivery == "headers" || r.nextStep || r.done || failed {
		r.deliverHeadersLocked()
	}
	if r.done || failed {
		r.owner.state.CompleteRequest(r.id)
	}
}
func (r *networkRecord) activity(amount int) {
	if amount <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextStep = true
	if r.ready {
		r.beginLocked()
		r.deliverHeadersLocked()
		r.owner.state.BodyActivity(r.id, amount)
	}
}
func (r *networkRecord) complete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	r.nextStep = true
	if r.ready {
		r.beginLocked()
		r.deliverHeadersLocked()
		r.owner.state.CompleteRequest(r.id)
	}
}

func markNetworkCached(req *fhttp.Request) {
	if record, ok := req.Context().Value(networkRecordKey{}).(*networkRecord); ok {
		record.mu.Lock()
		record.cached = true
		record.mu.Unlock()
	}
}

func validateNetworkHeaderInputs(p *profile.Profile, headers Header) error {
	if p == nil || p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" {
		return nil
	}
	for _, name := range []string{"rtt", "downlink", "ect"} {
		if headers.Has(name) {
			return fmt.Errorf("profile %q estimated network_hints conflicts with caller literal %s", p.Name, name)
		}
	}
	return nil
}

// Validation checks syntax and known missing inputs without changing estimator
// state or sampling the host. Availability of system metadata is checked by Do.
func (c *Client) validateNetworkRequest(req *Request) error {
	if err := validateNetworkHeaderInputs(c.profile, req.Header); err != nil {
		return err
	}
	if c.network == nil {
		if req.Network != nil {
			return fmt.Errorf("network context requires an estimated network_hints profile")
		}
		return nil
	}
	input := req.Network
	if input == nil {
		input = c.network.initial
	}
	if input != nil {
		return input.Validate()
	}
	if c.network.policy.Environment.Source == "context" {
		_, err := networkInput(c.network.policy.Environment, nil)
		return err
	}
	return nil
}

// Cached responses have no transport body to observe. Reuse the cache's existing
// body type for activity/ownership only, without treating memory bytes as network bytes.
func observedCacheBody(req *fhttp.Request, body io.ReadCloser) io.ReadCloser {
	record, ok := req.Context().Value(networkRecordKey{}).(*networkRecord)
	if !ok {
		return body
	}
	return &cacheBody{ReadCloser: body, observedRead: record.activity, observedDone: record.complete}
}
