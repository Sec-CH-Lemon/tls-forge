package tlsforge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// HTTP/3 where a name's HTTPS record names h3, as Chrome 155 goes over it
// (bench/h3 in ../net-fp-server/captures/review-20261023, cohorts h3a and h3b):
// QUIC raced by TCP, the first up taking the request.

// h3Site is an https origin on one loopback port, TCP (HTTP/2 and HTTP/1.1)
// and UDP (HTTP/3), whose every answer says the protocol it came over, and
// " ech" after it where its QUIC server opened an inner hello; with tcpLag,
// its TCP server's first word comes that late; with quicLag, every datagram of
// its QUIC server's, through a relay of the port's own.
type h3Site struct {
	port      string
	quicConns atomic.Int32
	tcpConns  atomic.Int32
	tcpClosed atomic.Int32
}

func startH3Site(t *testing.T, tcpLag, quicLag time.Duration, echKeys ...tls.EncryptedClientHelloKey) *h3Site {
	t.Helper()
	s := &h3Site{}
	udp, tcp := udpAndTCP(t)
	_, s.port, _ = net.SplitHostPort(tcp.Addr().String())
	// An answer says what it came over; ?alt is its Alt-Svc.
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if alt := r.URL.Query().Get("alt"); alt != "" {
			w.Header().Set("Alt-Svc", alt)
		}
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.Listener = &slowFirstWord{Listener: tcp, lag: tcpLag}
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		switch state {
		case stdhttp.StateNew:
			s.tcpConns.Add(1)
		case stdhttp.StateClosed:
			s.tcpClosed.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	if quicLag > 0 {
		inner, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go relayLate(udp, inner.LocalAddr().(*net.UDPAddr), quicLag)
		t.Cleanup(func() { _ = udp.Close() })
		udp = inner
	}
	h3 := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if alt := r.URL.Query().Get("alt"); alt != "" {
			w.Header().Set("Alt-Svc", alt)
		}
		said := r.Proto
		if r.TLS != nil && r.TLS.ECHAccepted {
			said += " ech"
		}
		_, _ = io.WriteString(w, said)
	}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}, EncryptedClientHelloKeys: echKeys},
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context { s.quicConns.Add(1); return ctx }}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close() })
	return s
}

// slowFirstWord's connections write their first late.
type slowFirstWord struct {
	net.Listener
	lag time.Duration
}

func (l *slowFirstWord) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || l.lag == 0 {
		return c, err
	}
	return &lateFirst{Conn: c, lag: l.lag}, nil
}

type lateFirst struct {
	net.Conn
	lag  time.Duration
	once sync.Once
}

func (c *lateFirst) Write(b []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.lag) })
	return c.Conn.Write(b)
}

// relayLate passes each sender's datagrams to to from a socket of its own,
// and sends what comes back lag late.
func relayLate(pc net.PacketConn, to *net.UDPAddr, lag time.Duration) {
	var mu sync.Mutex
	ups := map[string]*net.UDPConn{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, up := range ups {
			_ = up.Close()
		}
	}()
	b := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			return
		}
		mu.Lock()
		up := ups[from.String()]
		if up == nil {
			if up, err = net.DialUDP("udp4", nil, to); err != nil {
				mu.Unlock()
				return
			}
			ups[from.String()] = up
			go func() {
				back := make([]byte, 65536)
				for {
					m, err := up.Read(back)
					if err != nil {
						return
					}
					datagram := append([]byte(nil), back[:m]...)
					time.AfterFunc(lag, func() { _, _ = pc.WriteTo(datagram, from) })
				}
			}()
		}
		mu.Unlock()
		_, _ = up.Write(b[:n])
	}
}

// came is what a GET of url came over, by the site's word.
func came(t *testing.T, c *Client, url string) string {
	t.Helper()
	res, err := c.Do(&Request{URL: url})
	if err != nil {
		return "error: " + err.Error()
	}
	return res.Text()
}

func TestARequestGoesOverHTTP3WhereItsNamesRecordNamesH3AsChrome(t *testing.T) {
	// TCP's handshake answered late: QUIC is up first, as a round trip fewer
	// has it on a network.
	site := startH3Site(t, 100*time.Millisecond, 0)
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"h3.h3.test": service(1, "h3.h3.test", alpnParam("h3", "h2"))}, 0, 0)
	c := echClient(t, dns)
	url := "https://h3.h3.test:" + site.port + "/"
	if got := came(t, c, url); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// QUIC had not worked in the session: TCP went at once too, its
	// connection made, though the request went over QUIC; the name asked once,
	// for both.
	if site.tcpConns.Load() != 1 {
		t.Errorf("%d TCP connections, want the one raced", site.tcpConns.Load())
	}
	q := dns.queries()
	slices.Sort(q)
	if want := []string{"A h3.h3.test.", "AAAA h3.h3.test.", "HTTPS _" + site.port + "._https.h3.h3.test."}; !slices.Equal(q, want) {
		t.Errorf("asked %v, want each of %v once", q, want)
	}
	// The next goes on the QUIC connection up.
	if got := came(t, c, url+"again"); got != "HTTP/3.0" {
		t.Errorf("the next came over %q", got)
	}
	if site.quicConns.Load() != 1 || site.tcpConns.Load() != 1 {
		t.Errorf("QUIC connections %d, TCP %d", site.quicConns.Load(), site.tcpConns.Load())
	}
}

func TestARecordWithoutH3OrAProfileWithoutItGoesOverTCPAlone(t *testing.T) {
	site := startH3Site(t, 0, 0)
	// No h3 in the record.
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"h2.h3.test": service(1, "h2.h3.test", alpnParam("h2")),
		"h3.h3.test": service(1, "h3.h3.test", alpnParam("h3", "h2"))}, 0, 0)
	if got := came(t, echClient(t, dns), "https://h2.h3.test:"+site.port+"/"); got != "HTTP/2.0" {
		t.Errorf("no h3: came over %q", got)
	}
	// A profile that does not ask, the record naming h3: the JSON alone says.
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	off := p.Clone()
	off.Behavior["dns.https_h3"] = []byte("false")
	for _, k := range []string{"quic.tcp_wait_cold_ms", "quic.tcp_wait_broken_ms", "quic.tcp_wait_rtt_percent",
		"quic.tcp_wait_default_ms", "quic.tcp_wait_extra_ms", "quic.tcp_wait_max_ms", "quic.tcp_waits_with_connection",
		"quic.retry_over_tcp", "quic.broken_ms", "quic.broken_doublings", "quic.broken_max_ms", "quic.broken_recent_max",
		"quic.server_rtts_max", "http.unused_idle_connection_timeout_ms", "quic.alt_svc", "quic.alt_svc_user_ports",
		"quic.alt_svc_remote_hosts", "quic.alt_svc_tcp_waits_with_h2"} {
		delete(off.Behavior, k)
	}
	if got := came(t, echClient(t, dns, WithProfileValue(off)), "https://h3.h3.test:"+site.port+"/"); got != "HTTP/2.0" {
		t.Errorf("a profile without it: came over %q", got)
	}
	time.Sleep(100 * time.Millisecond)
	if site.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections", site.quicConns.Load())
	}
}

func TestHTTP3OffersTheECHOfItsRecord(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := h3ECHConfig(7, key)
	site := startH3Site(t, 100*time.Millisecond, 0, tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes()})
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.h3.test": service(1, "ech.h3.test",
		alpnParam("h3", "h2"), echParam(string(list.BytesOrPanic())))}, 0, 0)
	if got := came(t, echClient(t, dns), "https://ech.h3.test:"+site.port+"/"); got != "HTTP/3.0 ech" {
		t.Errorf("came over %q, want HTTP/3 with its inner hello opened", got)
	}
}

// h3ECHConfig is an ECHConfig of id and key, public.h3.test its public name.
func h3ECHConfig(id uint8, key *ecdh.PrivateKey) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.h3.test")) })
		b.AddUint16(0)
	})
	return b.BytesOrPanic()
}

func TestAFreshClientKnowsWhatItsSessionKnowsOfQUIC(t *testing.T) {
	first := startH3Site(t, 100*time.Millisecond, 0)
	second := startH3Site(t, 0, 50*time.Millisecond)
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{
		"one.h3.test": service(1, "one.h3.test", alpnParam("h3", "h2")),
		"two.h3.test": service(1, "two.h3.test", alpnParam("h3", "h2"))}, 0, 0)
	c := echClient(t, dns)
	if got := came(t, c, "https://one.h3.test:"+first.port+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	// QUIC worked in the session: a fresh client's TCP waits 300 ms behind its
	// QUIC, which is up 50 ms late, before any TCP.
	fresh, err := c.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if got := came(t, fresh, "https://two.h3.test:"+second.port+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	time.Sleep(400 * time.Millisecond)
	if second.tcpConns.Load() != 0 {
		t.Errorf("%d TCP connections, want none", second.tcpConns.Load())
	}
}

func TestANameResolvedForQUICIsDialedOverTCPWithoutAskingAgain(t *testing.T) {
	n := &resolvedName{host: "www.example.test", addrs: []netip.Addr{netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:127.0.0.3")}}
	got, err := n.resolver().LookupNetIP(context.Background(), "ip", "WWW.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
	if want := []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("::1")}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if _, err := n.resolver().LookupNetIP(context.Background(), "ip", "other.example.test"); err == nil {
		t.Error("another name was found")
	}
	if resolvedFor(context.WithValue(context.Background(), resolvedKey{}, n), "other.example.test") != nil ||
		resolvedFor(context.Background(), "www.example.test") != nil {
		t.Error("a resolution of another name, or none, was taken")
	}
	// What is no query, or is cut short, is answered with nothing.
	if n.reply([]byte{1, 2, 3}) != nil {
		t.Error("garbage answered")
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	header, _ := b.Finish()
	if n.reply(header) != nil {
		t.Error("a query with no question answered")
	}
	for _, sent := range [][]byte{{0}, {0, 9, 1}, binary.BigEndian.AppendUint16(nil, 3), {0, 3, 1, 2, 3}} {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() { n.answer(server); close(done) }()
		_, _ = client.Write(sent)
		_ = client.Close()
		<-done
	}
	// One whose asker went away before the answer.
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { n.answer(server); close(done) }()
	query := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 2, RecursionDesired: true})
	_ = query.StartQuestions()
	_ = query.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := query.Finish()
	_, _ = client.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	_ = client.Close()
	<-done
}

func TestANameThatIsNotAskedOrDoesNotResolveHasNoQUICEndpoint(t *testing.T) {
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{}, 0, 0)
	r := newResolving(dns.addr, p.RuntimeBehavior())
	for _, addr := range []string{"127.0.0.1:443", "localhost:443", "no port", "unknown.invalid:443"} {
		if _, _, h3 := r.quicEndpoint(context.Background(), addr); h3 {
			t.Errorf("%s: an endpoint", addr)
		}
	}
	if _, _, h3 := (*resolving)(nil).quicEndpoint(context.Background(), "www.example.test:443"); h3 {
		t.Error("no resolving: an endpoint")
	}
	// One whose name does not resolve: the server says it has no such name.
	none := startDNS(t, func(dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		return nil, 0, dnsmessage.RCodeNameError
	})
	ctx := context.Background()
	got, _, h3 := newResolving(none.addr, p.RuntimeBehavior()).quicEndpoint(ctx, "gone.h3.test:443")
	if h3 || got != ctx {
		t.Error("a name that does not resolve: an endpoint, or a resolution kept")
	}
	if !strings.Contains(none.queries()[0], "gone.h3.test") {
		t.Errorf("asked %v", none.queries())
	}
}

// refusingQUIC is an https origin on one loopback port whose TCP serves
// HTTP/2 and whose QUIC refuses every handshake (it speaks no protocol a
// client offers), counting the hellos it was sent.
func refusingQUIC(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	hellos := new(atomic.Int32)
	udp, tcp := udpAndTCP(t)
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.Listener = tcp
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	ln, err := (&quic.Transport{Conn: udp}).ListenEarly(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos:   []string{"not-h3"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			hellos.Add(1)
			return nil, nil
		},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = udp.Close() })
	return port, hellos
}

func TestQUICIsBrokenForTheSiteThatSawItFailAlone(t *testing.T) {
	port, hellos := refusingQUIC(t)
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"api.h3.test": service(1, "api.h3.test", alpnParam("h3", "h2"))}, 0, 0)
	c := echClient(t, dns)
	from := func(page string) string {
		t.Helper()
		res, err := c.Do(&Request{URL: "https://api.h3.test:" + port + "/",
			Browser: &BrowserContext{Kind: KindFetch, Initiator: page, Mode: "no-cors"}})
		if err != nil {
			return "error: " + err.Error()
		}
		return res.Text()
	}
	until := func(ok func() bool) bool {
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if ok() {
				return true
			}
		}
		return ok()
	}
	// From a page of one site: QUIC refused where TCP took the request, and
	// QUIC to the origin is not tried again from that site...
	if got := from("https://one.test/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if !until(func() bool { return hellos.Load() == 1 }) {
		t.Fatalf("%d QUIC hellos, want one", hellos.Load())
	}
	time.Sleep(100 * time.Millisecond)
	if got := from("https://one.test/"); got != "HTTP/2.0" {
		t.Fatalf("again: came over %q, want TCP's", got)
	}
	time.Sleep(200 * time.Millisecond)
	if n := hellos.Load(); n != 1 {
		t.Errorf("%d QUIC hellos from the site QUIC broke for, want the first alone", n)
	}
	// ...but from another site's, as Chromium keys what broke by the
	// top-level site (NetworkAnonymizationKey).
	if got := from("https://two.test/"); got != "HTTP/2.0" {
		t.Fatalf("from another site: came over %q, want TCP's", got)
	}
	if !until(func() bool { return hellos.Load() == 2 }) {
		t.Errorf("%d QUIC hellos, want another from the other site", hellos.Load())
	}
}

func TestARequestsQUICAndTCPConnectionsShareOneLookupOfRecordsKeptNoTime(t *testing.T) {
	site := startH3Site(t, 100*time.Millisecond, 0)
	dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		name := strings.TrimSuffix(q.Name.String(), ".")
		switch q.Type {
		case dnsmessage.TypeA:
			return []dnsRecord{{name: name, ttl: 0, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
		case dnsmessage.TypeHTTPS:
			return []dnsRecord{{name: name, ttl: 0, https: service(1, "h3.h3.test", alpnParam("h3", "h2"))}}, 0, 0
		}
		return nil, 0, 0
	})
	c := echClient(t, dns)
	if got := came(t, c, "https://h3.h3.test:"+site.port+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// The TCP connection raced is made with what the QUIC one's lookup
	// found, its records too, however long they may be kept.
	for end := time.Now().Add(2 * time.Second); site.tcpConns.Load() == 0 && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	q := dns.queries()
	slices.Sort(q)
	if want := []string{"A h3.h3.test.", "AAAA h3.h3.test.", "HTTPS _" + site.port + "._https.h3.h3.test."}; !slices.Equal(q, want) {
		t.Errorf("asked %v, want each of %v once", q, want)
	}
}

func TestARequestElsewhereReapsTheTCPConnectionThatLostToQUICAndOneToItsOwnAddressNone(t *testing.T) {
	// QUIC up first: TCP's connection waits unused past its time (50 ms
	// here, Chrome's 60 s). A request on the QUIC connection asks no socket
	// of its own address's; one to another address, any socket, as Chromium's
	// pool cleans up every group then.
	site := startH3Site(t, 100*time.Millisecond, 0)
	other := startH3Site(t, 0, 0)
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"h3.h3.test": service(1, "h3.h3.test", alpnParam("h3", "h2"))}, 0, 0)
	c := echClient(t, dns, WithProfileValue(policyFile(t, map[string]any{"http.unused_idle_connection_timeout_ms": 50})))
	url := "https://h3.h3.test:" + site.port + "/"
	if got := came(t, c, url); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	if !soon(2*time.Second, func() bool { return site.tcpConns.Load() == 1 }) {
		t.Fatal("no TCP connection raced")
	}
	time.Sleep(200 * time.Millisecond)
	if got := came(t, c, url+"again"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want the QUIC connection up", got)
	}
	time.Sleep(100 * time.Millisecond)
	if site.tcpClosed.Load() != 0 {
		t.Fatal("a request on its address's QUIC connection reaped the TCP connection that lost")
	}
	if got := came(t, c, "https://plain.h3.test:"+other.port+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if !soon(2*time.Second, func() bool { return site.tcpClosed.Load() == 1 }) {
		t.Error("a request elsewhere left the TCP connection that lost open past its time")
	}
}

// soon says whether ok comes true within d.
func soon(d time.Duration, ok func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return true
		}
	}
	return ok()
}
