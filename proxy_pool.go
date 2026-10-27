package tlsforge

import (
	"context"
	"errors"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"net"
	"net/url"
	"sync"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/fhttp/httptrace"

	utls "github.com/igor-lemon/utls"
)

// A pool belongs to one proxy and top-level site. Origin credential modes
// retain separate inner pools but share this proxy-authenticated outer hop.
// Its outer H2 connections carry both ordinary requests and CONNECT streams.
// Inner origin TLS connections own only their stream, never the proxy socket.
type proxyH2Pool struct {
	mu    sync.Mutex
	conns []*proxyH2Conn
	h1    bool // last observed proxy ALPN; under mu
	dial  chan struct{}
	cache proxyTLSCache
}

func newProxyH2Pool(policies ...behavior.Policy) *proxyH2Pool {
	return &proxyH2Pool{dial: make(chan struct{}, 1), cache: newProxyTLSCache(policies...)}
}

type proxyH2Conn struct {
	conn      net.Conn
	client    *http2.ClientConn
	active    int // requests until body close/EOF, or tunnels until Close
	retiring  bool
	transport *http2.Transport
}

func (d *connectDialer) takeProxyH2() *proxyH2Conn {
	d.proxyPool.mu.Lock()
	defer d.proxyPool.mu.Unlock()
	kept := d.proxyPool.conns[:0]
	var chosen *proxyH2Conn
	for _, p := range d.proxyPool.conns {
		usable := !p.retiring && p.client.CanTakeNewRequest()
		if usable || p.active > 0 {
			kept = append(kept, p)
		}
		if chosen == nil && usable {
			chosen = p
			p.active++
		}
	}
	d.proxyPool.conns = kept
	return chosen
}

func (d *connectDialer) releaseProxyH2(p *proxyH2Conn) {
	d.proxyPool.mu.Lock()
	p.active--
	close := p.retiring && p.active == 0
	d.proxyPool.mu.Unlock()
	if close {
		_ = p.client.Close()
	}
}

func (d *connectDialer) adoptProxyH2(conn net.Conn) (*proxyH2Conn, error) {
	prof, err := d.identity.profile.ClientProfile()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	transport := &http2.Transport{AllowHTTP: true, Behavior: d.identity.profile.RuntimeBehavior().Clone(),
		Settings: prof.GetSettings(), SettingsOrder: prof.GetSettingsOrder(), ConnectionFlow: prof.GetConnectionFlow(), ConnectionFlowSet: prof.GetConnectionFlowSet(),
		HeaderPriority: prof.GetHeaderPriority(), PseudoHeaderOrder: prof.GetPseudoHeaderOrder(), Priorities: prof.GetPriorities(),
		DisableCompression: true, WindowUpdateDelay: prof.GetWindowUpdateDelay(), HeaderRepresentation: prof.GetHeaderRepresentation(),
		MaxEncoderHeaderTableSize: prof.GetMaxEncoderHeaderTableSize(), MaxHeaderFramePayload: prof.GetMaxHeaderFramePayload(),
		MaxDataFramePayload: prof.GetMaxDataFramePayload(), StrictMaxConcurrentStreams: prof.GetStrictMaxConcurrentStreams(),
		InitialStreamID: prof.GetStreamID(), IdleConnTimeout: policyDuration(d.identity.profile.RuntimeBehavior(), "proxy.idle_timeout_ms"), ConnPool: d.proxyPool}
	if enabled, known := transport.Settings[http2.SettingEnablePush]; !known || enabled != 0 {
		transport.PushHandler = &http2.DefaultPushHandler{}
	}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	p := &proxyH2Conn{conn: conn, client: cc, active: 1, transport: transport}
	d.proxyPool.mu.Lock()
	d.proxyPool.conns = append(d.proxyPool.conns, p)
	d.proxyPool.mu.Unlock()
	return p, nil
}

func (d *connectDialer) lockProxyDial(ctx context.Context) error {
	select {
	case d.proxyPool.dial <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *connectDialer) unlockProxyDial() { <-d.proxyPool.dial }

// Only unknown/H2 cold discovery is serialized. Observing H1 is an actual
// negotiated connection state, never a browser preset or a forced ALPN value.
func (d *connectDialer) proxyIsH1() bool {
	d.proxyPool.mu.Lock()
	defer d.proxyPool.mu.Unlock()
	return d.proxyPool.h1
}

func (d *connectDialer) proxyProtocol(h1 bool) {
	d.proxyPool.mu.Lock()
	d.proxyPool.h1 = h1
	d.proxyPool.mu.Unlock()
}

func (d *connectDialer) lockProxyDiscovery(ctx context.Context) (func(), error) {
	if d.proxyIsH1() {
		return func() {}, nil
	}
	if err := d.lockProxyDial(ctx); err != nil {
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(d.unlockProxyDial) }
	if d.proxyIsH1() {
		release()
	}
	return release, nil
}

func (d *connectDialer) chromeTunnel(ctx context.Context, network, address string) (net.Conn, error) {
	if p := d.takeProxyH2(); p != nil {
		return d.openProxyStream(ctx, p, address)
	}
	release, err := d.lockProxyDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if p := d.takeProxyH2(); p != nil {
		release()
		return d.openProxyStream(ctx, p, address)
	}
	conn, err := d.reach(ctx, network)
	if err != nil {
		release()
		return nil, err
	}
	d.proxyProtocol(!speaksH2(conn))
	if !speaksH2(conn) {
		release()
		opened, err := d.open(ctx, conn, address)
		if err != nil {
			_ = conn.Close()
		}
		return opened, err
	}
	p, err := d.adoptProxyH2(conn)
	release()
	if err != nil {
		return nil, err
	}
	return d.openProxyStream(ctx, p, address)
}

// ProxyHTTP2Protocol is called only after the forwarding transport's proxy TLS
// handshake negotiated H2. The connection is registered under this proxy, not
// the destination authority, so another origin can use the same outer channel.
func (d *connectDialer) ProxyHTTP2Protocol(conn *utls.Conn) fhttp.RoundTripper {
	p, err := d.adoptProxyH2(conn)
	if err != nil {
		return proxyRoundTripError{err}
	}
	d.releaseProxyH2(p)
	return proxyH2RoundTripper{d}
}

type proxyRoundTripError struct{ err error }

func (r proxyRoundTripError) RoundTrip(*fhttp.Request) (*fhttp.Response, error) { return nil, r.err }

type proxyH2RoundTripper struct{ d *connectDialer }

func (r proxyH2RoundTripper) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	p := r.d.takeProxyH2()
	if p == nil {
		return nil, http2.ErrNoCachedConn
	}
	return r.d.proxyRoundTrip(req, p)
}

// RoundTripProxyHTTP reuses an outer H2 connection before falling back to the
// H1 transport, which negotiates proxy ALPN. A cold dial is serialized with
// CONNECT setup; a waiter can cancel without affecting the dial's owner.
func (d *connectDialer) RoundTripProxyHTTP(req *fhttp.Request, fallback fhttp.RoundTripper) (*fhttp.Response, error) {
	if p := d.takeProxyH2(); p != nil {
		res, err := d.proxyRoundTrip(req, p)
		if !errors.Is(err, http2.ErrNoCachedConn) {
			return res, err
		}
		var replayErr error
		req, replayErr = proxyReplay(req)
		if replayErr != nil {
			return nil, replayErr
		}
	}
	release, err := d.lockProxyDiscovery(req.Context())
	if err != nil {
		return nil, err
	}
	defer release()
	if p := d.takeProxyH2(); p != nil {
		release()
		res, err := d.proxyRoundTrip(req, p)
		if !errors.Is(err, http2.ErrNoCachedConn) {
			return res, err
		}
		var replayErr error
		req, replayErr = proxyReplay(req)
		if replayErr != nil {
			return nil, replayErr
		}
	}
	// fhttp invokes GotConn after proxy ALPN/adoption and before writing the
	// request. Compose with the caller's trace; failure paths release below.
	traced := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		d.proxyProtocol(!speaksH2(info.Conn))
		release()
	}})
	return fallback.RoundTrip(req.WithContext(traced))
}

func proxyReplay(req *fhttp.Request) (*fhttp.Request, error) {
	if req.Body == nil || req.Body == fhttp.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, http2.ErrNoCachedConn
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	copy := *req
	copy.Body = body
	return &copy, nil
}

// Keep fhttp's bounded, body-replay-safe H2 retry policy. The custom pool
// never dials: a missing cached proxy connection returns to ALPN negotiation.
type proxyLeaseKey struct{}
type proxyLease struct {
	d     *connectDialer
	first *proxyH2Conn
	peers []*proxyH2Conn
}

func (p *proxyH2Pool) GetClientConn(req *fhttp.Request, _ string) (*http2.ClientConn, error) {
	lease, ok := req.Context().Value(proxyLeaseKey{}).(*proxyLease)
	if !ok || lease.d.proxyPool != p {
		return nil, http2.ErrNoCachedConn
	}
	if first := lease.first; first != nil {
		lease.first = nil
		return first.client, nil
	}
	next := lease.d.takeProxyH2()
	if next == nil {
		return nil, http2.ErrNoCachedConn
	}
	lease.peers = append(lease.peers, next)
	return next.client, nil
}
func (p *proxyH2Pool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.conns {
		if v.client == cc {
			v.retiring = true
		}
	}
}
func (d *connectDialer) proxyRoundTrip(req *fhttp.Request, p *proxyH2Conn) (*fhttp.Response, error) {
	lease := &proxyLease{d: d, first: p, peers: []*proxyH2Conn{p}}
	copy := req.WithContext(context.WithValue(req.Context(), proxyLeaseKey{}, lease))
	release := func() {
		for _, v := range lease.peers {
			d.releaseProxyH2(v)
		}
	}
	res, err := p.transport.RoundTrip(copy)
	if err != nil {
		release()
		return nil, err
	}
	res.Body = &proxyResponseBody{ReadCloser: res.Body, release: release}
	return res, nil
}

type proxyResponseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *proxyResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *proxyResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

func (d *connectDialer) CloseIdleProxyConnections() {
	d.proxyPool.mu.Lock()
	var idle []*proxyH2Conn
	for _, p := range d.proxyPool.conns {
		p.retiring = true
		if p.active == 0 {
			idle = append(idle, p)
		}
	}
	d.proxyPool.mu.Unlock()
	for _, p := range idle {
		_ = p.client.Close()
	}
}

// connectAnswered is told of each CONNECT a proxy's HTTP/2 connection has
// answered, before the dial's end is looked at: the seam a test ends a dial
// through at that moment, which nothing else can reach.
var connectAnswered = func() {}

func (d *connectDialer) openProxyStream(ctx context.Context, p *proxyH2Conn, address string) (*tunnel, error) {
	// Dial cancellation applies through the CONNECT response, as for
	// net.DialContext. Afterwards the stream belongs to the returned Conn.
	// Cancelling the first origin request must not destroy a reusable tunnel.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	// The proxy CONNECT has its own measured priority (weight 147), not
	// the origin request's navigation/fetch priority on the inner channel.
	streamCtx = http2.WithHeaderPriority(streamCtx, priorityFrom(d.identity.profile.RuntimeBehavior(), "proxy.connect_priority"))
	stop := context.AfterFunc(ctx, cancel)
	reader, writer := io.Pipe()
	ask := (&fhttp.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: address}, Host: address, Header: d.header.Clone(), Body: reader, ContentLength: -1}).WithContext(streamCtx)
	ask.Header.Del("Proxy-Connection")
	ask.Header[fhttp.PHeaderOrderKey] = d.identity.profile.RuntimeBehavior().Strings("proxy.connect_pseudo_order")
	answer, err := d.proxyRoundTrip(ask, p)
	connectAnswered()
	if !stop() && err == nil {
		_ = answer.Body.Close()
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	if answer.StatusCode != 200 {
		cancel()
		_ = answer.Body.Close()
		_ = writer.Close()
		return nil, fmt.Errorf("proxy responded with non 200 code: %s", answer.Status)
	}
	stream := &proxyStream{Conn: p.conn, reader: answer.Body, writer: writer, cancel: cancel}
	opened := &tunnel{Conn: stream, reader: stream, header: answerHeader(answer.Header), id: tunnels.Add(1)}
	if r := requestLogOf(ctx); r != nil {
		r.proxyAnswer(answer, opened.id)
	}
	return opened, nil
}
