package tlsforge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/net/dns/dnsmessage"
)

// resolving is how a client with no proxy finds a site, as Chrome's host
// resolver finds one for a direct connection (measured on Chrome 155,
// testdata/chrome155-ech-dns.json): its addresses, asked of the DNS server
// WithDNSServer names, else as the profile says (dns.resolver): by a client
// of tls-forge's own of the machine's DNS servers ("built-in", as Chrome's
// built-in DNS client asks them: kAsyncDns, InsecureDnsMode kEnabledBuiltIn),
// or by the machine's resolver; and, where the profile asks for them
// (dns.https_records), its HTTPS records (RFC 9460), asked of the same
// servers alongside the addresses, whose ECH configs the connection offers
// (tls.ech). A name the network does not answer, localhost or one under it
// and one under .local, is always the machine's resolver's, as Chrome
// resolves it itself or by its system task.
//
// Once the addresses are in, a connection waits for the records no longer
// than dns.https_wait_percent of the time the lookup has taken so far, but
// at least dns.https_wait_min_ms and at most dns.https_wait_max_ms
// (Chromium's HostResolverDnsTask::MaybeStartTimeoutTimer), and goes on
// without them when they are not in by then. Records found are kept for
// their time to live, as Chrome's host cache keeps them, so that a
// connection made again, after a server refused its ECH, asks for nothing.
type resolving struct {
	server       string        // the DNS server asked instead of the machine's, or ""
	resolver     *net.Resolver // the resolver of names the network answers: the machine's, its own, or the server's
	queryRD      bool
	queryPayload uint16
	queryTimeout time.Duration
	https        bool
	percent      int
	min, max     time.Duration
	mu           sync.Mutex
	kept         map[string]keptHTTPS // by the name asked about
}

// keptHTTPS is what a name's HTTPS records said, until when.
type keptHTTPS struct {
	answer httpsAnswer
	until  time.Time
}

// newResolving is how a client resolves: with server ("" for the machine's
// servers), and as policy says of its resolver and of HTTPS records.
func newResolving(server string, p behavior.Policy) *resolving {
	r := &resolving{server: server, resolver: machineResolver, https: p.Flag("dns.https_records"),
		kept:         map[string]keptHTTPS{},
		queryRD:      p.Flag("dns.https_query_recursion_desired"),
		queryPayload: uint16(p.Uint("dns.https_query_udp_payload_bytes")),
		queryTimeout: time.Duration(p.Uint("dns.https_query_timeout_ms")) * time.Millisecond,
		percent:      p.Int("dns.https_wait_percent"),
		min:          time.Duration(p.Uint("dns.https_wait_min_ms")) * time.Millisecond,
		max:          time.Duration(p.Uint("dns.https_wait_max_ms")) * time.Millisecond}
	switch {
	case server != "":
		var d net.Dialer
		r.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, server)
		}}
	case p.Text("dns.resolver") == "built-in" && len(systemDNSServers()) > 0:
		r.resolver = builtInResolver
	default:
		// The machine's resolver asks for addresses alone: no records, as
		// Chrome's built-in client asks none where the machine names no
		// server (CanUseInsecureDnsTransactions) and its system task none.
		r.https = false
	}
	return r
}

// systemDNSServers are the DNS servers the machine names, each on port 53
// (machineDNSServers): the HTTPS records' when no server was named.
var systemDNSServers = machineDNSServers

// machineResolver is the machine's own resolver.
var machineResolver = net.DefaultResolver

// builtInResolver asks the machine's DNS servers itself, as Go's resolver
// reads them (resolv.conf, or the adapters' on Windows), the hosts file
// first, as Chrome's built-in client does: what the server answers, not what
// a cache of the machine's kept, and as late as the server answers.
var builtInResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, server string) (net.Conn, error) {
	return dialDNS(ctx, network, server)
}}

// dialDNS opens a connection to a DNS server, every query's: the addresses'
// and the HTTPS records'.
var dialDNS = func(ctx context.Context, network, server string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, server)
}

// resolverFor is the resolver that finds host's addresses: the machine's
// for a name the network does not answer (networkName), unless a server was
// named, else the client's.
func (r *resolving) resolverFor(host string) *net.Resolver {
	if r.server == "" && !networkName(host) {
		return machineResolver
	}
	return r.resolver
}

// networkName says whether the network answers for host: a name, not an
// address, localhost or a name under it, which Chrome answers itself (its
// ResolveLocalHostname), or one under .local, which Chrome leaves to the
// system (ResemblesMulticastDNSName).
func networkName(host string) bool {
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	return name != "localhost" && !strings.HasSuffix(name, ".localhost") && !strings.HasSuffix(name, ".local")
}

// dnsServerOf is the server WithDNSServer names, with its port: an IP
// address, and 53 when it says none; "" for the machine's.
func dnsServerOf(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	if addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")); err == nil {
		return net.JoinHostPort(addr.String(), "53"), nil
	}
	server, err := netip.ParseAddrPort(address)
	if err != nil || server.Port() == 0 {
		return "", fmt.Errorf("tlsforge: DNS server %q is no IP address, with or without a port", address)
	}
	return server.String(), nil
}

// lookupNames finds the addresses of host as a connection to it does, with
// the resolver that says what it does to the trace of the request it is
// for: Chrome looks a name up before it sends a request over an HTTP/2
// connection to another, at an address the name has, on its certificate.
func (r *resolving) lookupNames(ctx context.Context, host string) ([]netip.Addr, error) {
	if known := preparedDNSFor(ctx, host); known != nil {
		return slices.Clone(known.addrs), known.err
	}
	return r.resolverFor(host).LookupNetIP(ctx, "ip", host)
}

// wait is how long a connection waits for the HTTPS records of a lookup
// that has taken elapsed when the addresses are in.
func (r *resolving) wait(elapsed time.Duration) time.Duration {
	w := elapsed * time.Duration(r.percent) / 100
	if r.max > 0 {
		w = min(w, r.max)
	}
	return max(w, r.min)
}

// asksFor says whether the HTTPS records of host are asked for: a name the
// network answers for.
func (r *resolving) asksFor(host string) bool {
	return r.https && networkName(host)
}

// httpsQueryName is the name whose HTTPS records say how to reach port of
// host over https (Chromium's GetNameForHttpsQuery): the name itself for
// 443, else the name with the port and _https before it.
func httpsQueryName(host string, port int) string {
	if port == 443 {
		return host
	}
	return "_" + strconv.Itoa(port) + "._https." + host
}

// httpsLookup is a lookup of the HTTPS records for a connection to port of
// host, going on while the connection is dialed.
type httpsLookup struct {
	r       *resolving
	began   time.Time
	cancel  context.CancelFunc
	done    chan struct{}
	answer  httpsAnswer
	settled sync.Once
	// What came in time: a record Chrome takes, and the configs the
	// connection offers ECH with; whether one names h3, and the configs of
	// that one, which a QUIC connection offers.
	record  bool
	taken   []byte
	h3      bool
	h3taken []byte
}

// httpsAnswer is what the HTTPS records of a name say of a connection to
// one of its ports: whether there is one Chrome takes, and the ECH configs of
// the one the connection takes; whether one names h3, and that one's ECH
// configs, which a QUIC connection takes; for how long, the least time to
// live of the records it read.
type httpsAnswer struct {
	record    bool
	configs   []byte
	h3        bool
	h3configs []byte
	ttl       time.Duration
	err       error
}

// ask starts looking up the HTTPS records for address (host:port), or is nil
// when the profile asks for none or host is not a name to ask about.
func (r *resolving) ask(ctx context.Context, address string) *httpsLookup {
	host, portText, err := net.SplitHostPort(address)
	port, perr := strconv.Atoi(portText)
	if r == nil || err != nil || perr != nil || !r.asksFor(host) {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &httpsLookup{r: r, began: time.Now(), cancel: cancel, done: make(chan struct{})}
	name := httpsQueryName(host, port)
	r.mu.Lock()
	kept, ok := r.kept[name]
	r.mu.Unlock()
	if ok && time.Now().Before(kept.until) {
		l.answer = kept.answer
		close(l.done)
		return l
	}
	go func() {
		defer close(l.done)
		l.answer = r.httpsRecords(ctx, host, port)
		if l.answer.ttl > 0 {
			r.mu.Lock()
			r.kept[name] = keptHTTPS{l.answer, time.Now().Add(l.answer.ttl)}
			r.mu.Unlock()
		}
	}()
	return l
}

// settle waits, once the addresses are in, for the records as long as the
// profile says, and takes the configs they gave by then: none after.
func (l *httpsLookup) settle(ctx context.Context) {
	l.settled.Do(func() {
		timer := time.NewTimer(l.r.wait(time.Since(l.began)))
		defer timer.Stop()
		select {
		case <-l.done:
			l.record, l.taken = l.answer.record, l.answer.configs
			l.h3, l.h3taken = l.answer.h3, l.answer.h3configs
		case <-timer.C:
		case <-ctx.Done():
		}
		l.cancel()
	})
}

// control is a dialer's hook that settles the lookup before the dialer
// connects to the first address it found, and then runs then's.
func (l *httpsLookup) control(then func(context.Context, string, string, syscall.RawConn) error) func(context.Context, string, string, syscall.RawConn) error {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		l.settle(ctx)
		if then != nil {
			return then(ctx, network, address, c)
		}
		return nil
	}
}

// dnsUpgrade sends a request to plain http to https where the name's HTTPS
// records say so, as Chrome's host resolver fails such a request with
// ERR_DNS_NAME_HTTPS_ONLY and its URLRequestHttpJob redirects it (307,
// Non-Authoritative-Reason: DNS) before anything is sent: the redirect is
// followed as any other is, so the request after it is a redirect's hop,
// as Chrome sent it (measured on Chrome 155, its fields in a redirected
// order). Any other request goes to next.
type dnsUpgrade struct {
	r    *resolving
	next fhttp.RoundTripper
}

func (u dnsUpgrade) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	if req.URL.Scheme != "http" {
		return u.next.RoundTrip(req)
	}
	upgrade, known := u.r.upgrades(req.Context(), req.URL.Hostname(), req.URL.Port())
	to := *shownURL(req)
	if upgrade {
		to.Scheme = "https"
		if to.Port() == "80" {
			to.Host = to.Hostname()
		}
	}
	if known != nil {
		prepareDNS(req.Context(), known, originOf(&to), upgrade)
	}
	if !upgrade {
		return u.next.RoundTrip(req)
	}
	return &fhttp.Response{Status: "307 Internal Redirect", StatusCode: fhttp.StatusTemporaryRedirect, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1, Header: fhttp.Header{"Location": {to.String()}, "Non-Authoritative-Reason": {"DNS"}},
		Body: fhttp.NoBody, Request: req}, nil
}

// upgrades resolves once for a plain HTTP hop and returns its result for the
// actual connection. Only this hop (or its immediate synthetic HTTPS redirect)
// may consume it; no browser-wide address cache is introduced.
func (r *resolving) upgrades(ctx context.Context, host, port string) (bool, *resolvedName) {
	if port == "" || port == "80" {
		port = "443"
	}
	l := r.ask(ctx, net.JoinHostPort(host, port))
	if l == nil {
		return false, nil
	}
	addrs, err := r.lookupNames(ctx, host)
	known := &resolvedName{host: host, addrs: slices.Clone(addrs), https: l, err: err}
	if err != nil {
		l.cancel()
		return false, known
	}
	l.settle(ctx)
	return l.record, known
}

// httpsRecords asks the servers for the HTTPS records of host for a
// connection to its port.
func (r *resolving) httpsRecords(ctx context.Context, host string, port int) httpsAnswer {
	servers := []string{r.server}
	if r.server == "" {
		servers = systemDNSServers()
	}
	name := httpsQueryName(host, port)
	query, id, err := httpsQuery(name, r.queryRD, r.queryPayload)
	if err != nil {
		return httpsAnswer{err: err}
	}
	var errs []error
	for _, server := range servers {
		exchangeContext, cancel := context.WithTimeout(ctx, r.queryTimeout)
		reply, err := exchangeDNS(exchangeContext, server, query, id)
		cancel()
		if err == nil {
			return httpsOf(reply, host, name, port)
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return httpsAnswer{err: errors.Join(errs...)}
}

// httpsQuery is a DNS query for the HTTPS records of name, with its ID: one
// question and explicit profile-owned RD and EDNS0 payload choices. Query ID
// and the question name are derived anew for this transaction.
func httpsQuery(name string, recursionDesired bool, udpPayloadBytes uint16) ([]byte, uint16, error) {
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, 0, fmt.Errorf("tlsforge: %q is no name to ask about: %w", name, err)
	}
	var idBytes [2]byte
	_, _ = io.ReadFull(rand.Reader, idBytes[:])
	id := binary.BigEndian.Uint16(idBytes[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: recursionDesired})
	b.EnableCompression()
	var opt dnsmessage.ResourceHeader
	err = errors.Join(b.StartQuestions(),
		b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}),
		b.StartAdditionals(), opt.SetEDNS0(int(udpPayloadBytes), dnsmessage.RCodeSuccess, false), b.OPTResource(opt, dnsmessage.OPTResource{}))
	msg, finished := b.Finish()
	if err = errors.Join(err, finished); err != nil {
		return nil, 0, fmt.Errorf("tlsforge: %q is no name to ask about: %w", name, err)
	}
	return msg, id, nil
}

// exchangeDNS asks server the query over UDP, and over TCP when the answer is
// cut short, and returns the answer to it: one with its ID.
var exchangeDNS = func(ctx context.Context, server string, query []byte, id uint16) ([]byte, error) {
	reply, err := exchangeOver(ctx, "udp", server, query, id)
	if err != nil || reply[2]&0x02 == 0 {
		return reply, err
	}
	return exchangeOver(ctx, "tcp", server, query, id)
}

func exchangeOver(ctx context.Context, network, server string, query []byte, id uint16) ([]byte, error) {
	conn, err := dialDNS(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	framed := network == "tcp"
	out := query
	if framed {
		out = binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		out = append(out, query...)
	}
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	for {
		reply := make([]byte, 65535)
		var n int
		if framed {
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return nil, err
			}
			reply = reply[:binary.BigEndian.Uint16(size[:])]
			n, err = io.ReadFull(conn, reply)
		} else {
			n, err = conn.Read(reply)
		}
		if err != nil {
			return nil, err
		}
		// An answer to another query is not this one's: over UDP the next
		// datagram may be.
		if n >= 12 && binary.BigEndian.Uint16(reply) == id && reply[2]&0x80 != 0 {
			return reply[:n], nil
		}
		if framed {
			return nil, fmt.Errorf("tlsforge: %s answered another query", server)
		}
	}
}

// httpsSupportedKeys are the service parameters Chrome's HTTPS record parser
// knows (ServiceFormHttpsRecordRdata::IsCompatible): a record that makes
// another mandatory is passed over.
var httpsSupportedKeys = []dnsmessage.SVCParamKey{dnsmessage.SVCParamALPN, dnsmessage.SVCParamNoDefaultALPN,
	dnsmessage.SVCParamPort, dnsmessage.SVCParamIPv4Hint, dnsmessage.SVCParamECH, dnsmessage.SVCParamIPv6Hint}

// httpsOf is what reply, the answer to the HTTPS query for name, says of a
// connection to port of host, as Chromium's DnsResponseResultExtractor and
// host cache read it. The records are those of the name the answer's CNAMEs
// lead name to. Any of them whose mandatory parameters Chrome's parser knows
// is a record that sends plain http to https; an AliasMode one leaves the
// connection nothing else, and so does every one saying no-default-alpn
// (ExtractHttpsResults: a domain gives one with its default ALPN, or none is
// taken). Of the ServiceMode ones, a TCP connection takes the one of the
// lowest priority (the first of equals) that is for its port, offers HTTP/2
// or HTTP/1.1, and names the server the addresses are for (host's canonical
// name: "." names it in a record of a name with no port before it), and
// offers ECH with its configs; a QUIC connection the first such one whose
// alpn names h3 (QuicSessionPool::SelectQuicVersion), and its configs.
func httpsOf(reply []byte, host, name string, port int) httpsAnswer {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err == nil && h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		err = fmt.Errorf("tlsforge: the HTTPS records of %s: %v", name, h.RCode)
	}
	if err == nil {
		err = p.SkipAllQuestions()
	}
	type record struct {
		owner string
		svcb  dnsmessage.SVCBResource
		ttl   time.Duration
	}
	var records []record
	cnames := map[string]string{}
	for err == nil {
		var rh dnsmessage.ResourceHeader
		if rh, err = p.AnswerHeader(); err != nil {
			break
		}
		owner := strings.ToLower(rh.Name.String())
		ttl := time.Duration(rh.TTL) * time.Second
		switch rh.Type {
		case dnsmessage.TypeCNAME:
			var c dnsmessage.CNAMEResource
			if c, err = p.CNAMEResource(); err == nil {
				cnames[owner] = strings.ToLower(c.CNAME.String())
			}
		case dnsmessage.TypeHTTPS:
			var r dnsmessage.HTTPSResource
			if r, err = p.HTTPSResource(); err == nil {
				records = append(records, record{owner, r.SVCBResource, ttl})
			}
		default:
			err = p.SkipAnswer()
		}
	}
	if !errors.Is(err, dnsmessage.ErrSectionDone) {
		return httpsAnswer{err: err}
	}
	canonical := fqdn(name)
	for hops := 0; cnames[canonical] != "" && hops < 8; hops++ {
		canonical = cnames[canonical]
	}
	// The addresses are for the name host's CNAMEs lead to: the records' own
	// where it is the name asked about, host itself for a name of a port.
	addresses := fqdn(host)
	if fqdn(name) == addresses {
		addresses = canonical
	}
	var answer httpsAnswer
	var best, quic *dnsmessage.SVCBResource
	alias, defaultALPN := false, false
	for i, r := range records {
		if r.owner != canonical || !httpsKnown(r.svcb) {
			continue
		}
		if !answer.record || r.ttl < answer.ttl {
			answer.ttl = r.ttl
		}
		answer.record = true
		if r.svcb.Priority == 0 {
			alias = true
			continue
		}
		target := strings.ToLower(r.svcb.Target.String())
		if target == "." {
			target = r.owner
		}
		if target != addresses || !forPort(r.svcb, port) {
			continue
		}
		_, noDefault := r.svcb.GetParam(dnsmessage.SVCParamNoDefaultALPN)
		defaultALPN = defaultALPN || !noDefault
		if httpsFor(r.svcb) && (best == nil || r.svcb.Priority < best.Priority) {
			best = &records[i].svcb
		}
		if namesH3(r.svcb) && (quic == nil || r.svcb.Priority < quic.Priority) {
			quic = &records[i].svcb
		}
	}
	if alias || !defaultALPN {
		return answer
	}
	if best != nil {
		answer.configs, _ = best.GetParam(dnsmessage.SVCParamECH)
	}
	if quic != nil {
		answer.h3 = true
		answer.h3configs, _ = quic.GetParam(dnsmessage.SVCParamECH)
	}
	return answer
}

// fqdn is name in lower case with its final dot.
func fqdn(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}

// httpsKnown says whether Chrome's parser knows every parameter r makes
// mandatory.
func httpsKnown(r dnsmessage.SVCBResource) bool {
	mandatory, _ := r.GetParam(0)
	for i := 0; i+1 < len(mandatory); i += 2 {
		if !slices.Contains(httpsSupportedKeys, dnsmessage.SVCParamKey(binary.BigEndian.Uint16(mandatory[i:]))) {
			return false
		}
	}
	return true
}

// forPort says whether r is for a connection to port: it says no other.
func forPort(r dnsmessage.SVCBResource, port int) bool {
	p, ok := r.GetParam(dnsmessage.SVCParamPort)
	return !ok || len(p) == 2 && int(binary.BigEndian.Uint16(p)) == port
}

// httpsFor says whether a TCP connection may take r: it offers HTTP/2 or
// HTTP/1.1 (by default, without no-default-alpn).
func httpsFor(r dnsmessage.SVCBResource) bool {
	if _, noDefault := r.GetParam(dnsmessage.SVCParamNoDefaultALPN); !noDefault {
		return true
	}
	return slices.ContainsFunc(alpnOf(r), func(p string) bool { return p == "h2" || p == "http/1.1" })
}

// namesH3 says whether r's alpn names h3, which a QUIC connection takes it for.
func namesH3(r dnsmessage.SVCBResource) bool {
	return slices.Contains(alpnOf(r), "h3")
}

// alpnOf are the protocols r's alpn names, as far as they read.
func alpnOf(r dnsmessage.SVCBResource) []string {
	alpn, _ := r.GetParam(dnsmessage.SVCParamALPN)
	var names []string
	for len(alpn) > 0 && int(alpn[0]) < len(alpn) {
		names = append(names, string(alpn[1:1+alpn[0]]))
		alpn = alpn[1+alpn[0]:]
	}
	return names
}
