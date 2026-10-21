package tlsforge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tls_client "github.com/igor-lemon/tls-client"
)

// connectProxy stands in for an HTTP proxy: it opens a tunnel for every
// CONNECT and answers with whatever answer makes of the tunnel's number, from
// one. A proxy that hands every connection an address of its own says so in a
// header field; one that turns the request away says that instead.
type connectProxy struct {
	server  *httptest.Server
	tunnels atomic.Int32
	mu      sync.Mutex
	// credentials are the Proxy-Authorization of each CONNECT, and asked the
	// Respond-With.
	credentials []string
	asked       []string
	forwarded   []string
}

func startConnectProxy(t *testing.T, secure bool, answer func(n int32) string) *connectProxy {
	t.Helper()
	var over *tls.Config
	if secure {
		over = &tls.Config{}
	}
	return startConnectProxyOver(t, over, answer)
}

// startConnectProxyOver is startConnectProxy spoken to over TLS as over says,
// or in the clear for none.
func startConnectProxyOver(t *testing.T, over *tls.Config, answer func(n int32) string) *connectProxy {
	t.Helper()
	p := &connectProxy{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			if !r.URL.IsAbs() || (r.URL.Hostname() != "127.0.0.1" && r.URL.Hostname() != "localhost") {
				http.Error(w, "owned absolute-form URLs only", http.StatusBadRequest)
				return
			}
			p.mu.Lock()
			p.forwarded = append(p.forwarded, r.RequestURI)
			p.credentials = append(p.credentials, r.Header.Get("Proxy-Authorization"))
			p.mu.Unlock()
			copy := r.Clone(r.Context())
			copy.RequestURI = ""
			copy.Header.Del("Proxy-Authorization")
			copy.Header.Del("Proxy-Connection")
			transport := &http.Transport{DisableKeepAlives: true}
			answer, err := transport.RoundTrip(copy)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			defer answer.Body.Close()
			for name, values := range answer.Header {
				w.Header()[name] = values
			}
			w.WriteHeader(answer.StatusCode)
			_, _ = io.Copy(w, answer.Body)
			return
		}
		p.mu.Lock()
		p.credentials = append(p.credentials, r.Header.Get("Proxy-Authorization"))
		p.asked = append(p.asked, r.Header.Get("Respond-With"))
		p.mu.Unlock()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		said := answer(p.tunnels.Add(1))
		if _, err := client.Write([]byte(said)); err != nil || !strings.Contains(said, " 200 ") {
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		go func() { _, _ = io.Copy(upstream, buffered) }()
		_, _ = io.Copy(client, upstream)
	})
	p.server = httptest.NewUnstartedServer(handler)
	if over != nil {
		p.server.TLS = over
		p.server.StartTLS()
	} else {
		p.server.Start()
	}
	t.Cleanup(p.server.Close)
	return p
}

// url is the proxy's, with credentials.
func (p *connectProxy) url() string {
	return strings.Replace(p.server.URL, "://", "://user:s3cr3t@", 1)
}

// exitAnswer is a proxy that says where each tunnel comes out, a new address
// for every one.
func exitAnswer(n int32) string {
	return fmt.Sprintf("HTTP/1.1 200 Connection established\r\nX-Exit-IP: 203.0.113.%d\r\nX-Exit-Country: PL\r\n\r\n", n)
}

func TestATunnelKeepsWhatTheProxyAnswered(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	client := newTestClient(t, WithProxy(via.url()))

	var first recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: first.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(first.conns) != 1 {
		t.Fatalf("connections reported = %d", len(first.conns))
	}
	conn := first.conns[0]
	// The socket goes to the proxy, and the proxy said where the tunnel came
	// out, in the order and the case the header fields of a response have.
	if conn.RemoteAddr != strings.TrimPrefix(via.server.URL, "http://") || conn.TLSVersion != "TLS 1.3" {
		t.Errorf("the connection was reported as %+v", conn)
	}
	want := Header{{Name: "x-exit-country", Value: "PL"}, {Name: "x-exit-ip", Value: "203.0.113.1"}}
	if !equalHeader(conn.ProxyHeader, want) {
		t.Errorf("the proxy's answer was reported as %v, want %v", conn.ProxyHeader, want)
	}
	if got := via.credentials; len(got) != 1 || got[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cr3t")) {
		t.Errorf("the proxy was asked with %q", got)
	}

	// The next request goes out on the same tunnel, which came out where it did.
	var second recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: second.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(second.conns) != 1 || !second.conns[0].Reused || second.conns[0].ProxyHeader.Get("x-exit-ip") != "203.0.113.1" {
		t.Errorf("the second request's connection was reported as %+v", second.conns)
	}
	// The same tunnel, by its number, and another client's is another.
	if conn.Tunnel == 0 || second.conns[0].Tunnel != conn.Tunnel {
		t.Errorf("the tunnels were numbered %d and %d", conn.Tunnel, second.conns[0].Tunnel)
	}
	var third recorded
	other := newTestClient(t, WithProxy(via.url()))
	if _, err := other.Do(&Request{URL: server.URL() + "/api/all", Trace: third.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(third.conns) != 1 || third.conns[0].Tunnel == conn.Tunnel || third.conns[0].Tunnel == 0 {
		t.Errorf("another tunnel was numbered %+v", third.conns)
	}
}

func TestATunnelAsksWhatTheClientAsks(t *testing.T) {
	// A proxy that says where the tunnel comes out only when the CONNECT asks.
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	asked := Header{{Name: "Respond-With", Value: "ip,country"}}
	client := newTestClient(t, WithProxy(via.server.URL), WithProxyHeader(asked))
	asked[0].Value = "changed afterwards"

	if _, err := client.Get(server.URL()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := via.asked; len(got) != 1 || got[0] != "ip,country" {
		t.Errorf("the proxy was asked %q", got)
	}
	// What goes to the proxy goes no further.
	res, err := client.Get(server.URL() + "/api/all")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(strings.ToLower(string(res.Body)), "respond-with") {
		t.Errorf("the site was told what the proxy was asked: %s", res.Body)
	}
}

func TestAPlainHTTPURLUsesAbsoluteFormAtTheProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	t.Cleanup(server.Close)
	via := startConnectProxy(t, false, exitAnswer)
	client := newTestClient(t, WithProxy(via.server.URL))

	var seen recorded
	res, err := client.Do(&Request{URL: server.URL, Trace: seen.trace()})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(res.Body) != "plain" {
		t.Errorf("body = %q", res.Body)
	}
	if len(seen.conns) != 1 || seen.conns[0].Tunnel != 0 || len(seen.conns[0].ProxyHeader) != 0 {
		t.Errorf("the connection was reported as %+v", seen.conns)
	}
	if via.tunnels.Load() != 0 || len(via.forwarded) != 1 || via.forwarded[0] != server.URL+"/" {
		t.Errorf("forwarded %v;CONNECTs %d", via.forwarded, via.tunnels.Load())
	}
	// Without credentials, nothing is claimed for them.
	if got := via.credentials; len(got) != 1 || got[0] != "" {
		t.Errorf("the proxy was asked with %q", got)
	}
}

func TestATunnelThroughAnHTTPSProxy(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, true, exitAnswer)
	roots := x509.NewCertPool()
	roots.AddCert(via.server.Certificate())
	original := proxyRoots
	t.Cleanup(func() { proxyRoots = original })
	proxyRoots = roots

	client := newTestClient(t, WithProxy(via.url()))
	var seen recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: seen.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(seen.conns) != 1 || seen.conns[0].ProxyHeader.Get("x-exit-ip") != "203.0.113.1" {
		t.Errorf("the connection was reported as %+v", seen.conns)
	}
}

func TestATunnelTheProxyWillNotOpen(t *testing.T) {
	server := startEcho(t)
	for _, tc := range []struct {
		name, answer, want string
	}{
		{"turned away", "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", "407 Proxy Authentication Required"},
		// Hung up on without an answer.
		{"no answer", "", "EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			via := startConnectProxy(t, false, func(int32) string { return tc.answer })
			client := newTestClient(t, WithProxy(via.server.URL))
			if _, err := client.Get(server.URL()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one that says %q", err, tc.want)
			}
		})
	}

	// Nothing to talk to.
	client := newTestClient(t, WithProxy("http://"+refused(t)), WithTimeout(2*time.Second))
	if _, err := client.Get(server.URL()); err == nil {
		t.Error("a proxy that is not there opened a tunnel")
	}
}

func TestATunnelThatIsNoLongerWanted(t *testing.T) {
	// A proxy that takes the request and never answers it holds the request no
	// longer than the request is wanted.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()

	client := newTestClient(t, WithProxy("http://"+listener.Addr().String()))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, err := client.Do(&Request{Context: ctx, URL: "https://example.test/"}); err == nil {
		t.Fatal("a proxy that never answered opened a tunnel")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("the request waited %s on a proxy it no longer wanted", took)
	}
}

func TestATunnelKeepsWhatCameWithTheAnswer(t *testing.T) {
	// A proxy that starts on the tunnel in the same write as its answer: what
	// was read along with the answer is the tunnel's, and comes first.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\nalready"))
		_, _ = conn.Write([]byte(" here"))
	}()

	u, _ := url.Parse("http://" + listener.Addr().String())
	conn, err := newConnectDialer(u, 5*time.Second, nil, nil).DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got, _ := io.ReadAll(conn)
	if string(got) != "already here" {
		t.Errorf("the tunnel began with %q", got)
	}
	if header := conn.(*tunnel).header; len(header) != 0 {
		t.Errorf("an answer with no header fields was kept as %v", header)
	}
}

// unwritable is a connection that takes nothing.
type unwritable struct{ net.Conn }

func (unwritable) Write([]byte) (int, error)        { return 0, errors.New("broken pipe") }
func (unwritable) SetDeadline(time.Time) error      { return nil }
func (unwritable) SetReadDeadline(time.Time) error  { return nil }
func (unwritable) SetWriteDeadline(time.Time) error { return nil }

func TestATunnelThatCannotBeAskedFor(t *testing.T) {
	u, _ := url.Parse("http://proxy.test")
	if _, err := newConnectDialer(u, time.Second, nil, nil).open(context.Background(), unwritable{}, "example.test:443"); err == nil ||
		!strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("err = %v", err)
	}
}

func TestConnectDialerSettings(t *testing.T) {
	plain, _ := url.Parse("http://proxy.test")
	secure, _ := url.Parse("https://proxy.test")
	named, _ := url.Parse("https://proxy.test:8443")
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	extra := map[string][]string{"X-Session": {"7"}}
	for _, tc := range []struct {
		u       *url.URL
		address string
		secure  bool
	}{
		// The port the scheme has when the URL names none.
		{plain, "proxy.test:80", false},
		{secure, "proxy.test:443", true},
		{named, "proxy.test:8443", true},
	} {
		d := newConnectDialer(tc.u, time.Second, local, extra)
		if d.address != tc.address || d.secure != tc.secure || d.name != "proxy.test" || d.dialer.LocalAddr != local ||
			d.header.Get("X-Session") != "7" || d.header.Get("Proxy-Authorization") != "" {
			t.Errorf("%s: %+v", tc.u, d)
		}
	}
	// No address of its own to dial from when none was given.
	if d := newConnectDialer(plain, time.Second, nil, nil); d.dialer.LocalAddr != nil {
		t.Errorf("dialling from %v", d.dialer.LocalAddr)
	}
	// And the same for a site dialled with nothing between.
	if d := newDirectDialer(time.Second, local); d.dialer.LocalAddr != local || d.dialer.Timeout != time.Second {
		t.Errorf("dialling directly with %+v", d.dialer)
	}
	if d := newDirectDialer(time.Second, nil); d.dialer.LocalAddr != nil {
		t.Errorf("dialling directly from %v", d.dialer.LocalAddr)
	}
}

func TestANameIsLookedUpAsADirectDialerLooksItUp(t *testing.T) {
	// The machine's resolver, which gives an address back as it was asked
	// for it, an IPv4 one written as IPv6.
	got, err := lookupNames(context.Background(), "127.0.0.1")
	if err != nil || len(got) != 1 || got[0].Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("127.0.0.1 is found at %v, %v", got, err)
	}
	// IPv6 as well as IPv4, as a dialer of TCP looks for both.
	if got, err := lookupNames(context.Background(), "::1"); err != nil || len(got) != 1 || got[0] != netip.IPv6Loopback() {
		t.Errorf("::1 is found at %v, %v", got, err)
	}
	if _, err := lookupNames(context.Background(), "nowhere.invalid"); err == nil {
		t.Error("nowhere.invalid is found")
	}
}

func TestTheProxiesTheTransportIsLeftWith(t *testing.T) {
	// A SOCKS proxy, and a URL that does not parse, are the transport's: it
	// knows what to say about them, and hands the request's tap each
	// connection it dials to the proxy.
	for _, proxyURL := range []string{"socks5://127.0.0.1:1080", "://not a url", "http://"} {
		if got := dialOptions(proxyURL, true, nil); len(got) != 2 {
			t.Errorf("%q is given %d options, want the transport's two", proxyURL, len(got))
		}
	}
	// An HTTP proxy is tunnelled here, and without HTTP/3, which it cannot carry.
	if got := dialOptions("http://proxy.test:8080", true, nil); len(got) != 2 {
		t.Errorf("an HTTP proxy is given %d options", len(got))
	}
	// No proxy is dialled here, and names are looked up for HTTP/2 to carry
	// requests to others, unless the caller has options of its own for the
	// transport, which may say how to dial.
	if got := dialOptions("", true, nil); len(got) != 2 {
		t.Errorf("a client without a proxy is given %d options", len(got))
	}
	if got := dialOptions("", false, nil); len(got) != 0 {
		t.Errorf("a client with transport options of its own is given %d options", len(got))
	}
}

// equalHeader says two headers hold the same fields in the same order.
func equalHeader(a, b Header) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAnHTTPSProxyTheSystemDoesNotTrustIsRefused(t *testing.T) {
	// Its certificate is checked against the system's roots, and skipping the
	// sites' certificates, which newTestClient does, does not reach it: a
	// proxy is who the password is given to.
	server := startEcho(t)
	via := startConnectProxy(t, true, exitAnswer)
	client := newTestClient(t, WithProxy(via.url()))
	_, err := client.Get(server.URL())
	var refused *tls.CertificateVerificationError
	if !errors.As(err, &refused) {
		t.Fatalf("Get() = %v, want the proxy's certificate refused", err)
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("the error says the proxy's password: %v", err)
	}
	if got := via.tunnels.Load(); got != 0 {
		t.Errorf("%d tunnels were asked of a proxy that was not trusted", got)
	}
}

func TestAProxyGivenAsATransportOptionIsTheTransportsToDial(t *testing.T) {
	// Without WithProxy, tls-forge has no proxy to dial: the transport opens
	// the tunnel its own way, and the log's proxy records and the exit header
	// fields of the tunnel's answer go with tls-forge's dialer.
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log), WithTransportOption(tls_client.WithProxyUrl(via.server.URL)))
	var seen recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: seen.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := via.tunnels.Load(); got != 1 {
		t.Errorf("the proxy opened %d tunnels", got)
	}
	if len(seen.conns) != 1 || len(seen.conns[0].ProxyHeader) != 0 {
		t.Errorf("the connection was reported as %+v", seen.conns)
	}
	if said := book.with(t, "proxy connect"); len(said) != 0 {
		t.Errorf("tls-forge's dialer opened the tunnel: %v", said)
	}
}
