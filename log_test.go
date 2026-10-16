package tlsforge

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	utls "github.com/bogdanfinn/utls"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// logBook is a log a test reads back: every record as the JSON handler writes
// it. Behind a lock, because a request logs from whichever goroutine is doing
// the work.
type logBook struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBook) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func newLogBook(level slog.Level) (*logBook, *slog.Logger) {
	book := &logBook{}
	return book, slog.New(slog.NewJSONHandler(book, &slog.HandlerOptions{Level: level}))
}

func (b *logBook) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// entry is one record, its fields as JSON reads them, every value said as
// fmt.Sprint says it.
type entry map[string]any

func (e entry) get(key string) string {
	if value, ok := e[key]; ok {
		return fmt.Sprint(value)
	}
	return ""
}

func (b *logBook) entries(t *testing.T) []entry {
	t.Helper()
	var out []entry
	for _, line := range strings.Split(strings.TrimSpace(b.text()), "\n") {
		if line == "" {
			continue
		}
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("a record that is not JSON: %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// with are the records of a message that have these fields, in order.
func (b *logBook) with(t *testing.T, msg string, fields ...string) []entry {
	t.Helper()
	var out []entry
	for _, e := range b.entries(t) {
		if e.get("msg") != msg {
			continue
		}
		matches := true
		for i := 0; i+1 < len(fields); i += 2 {
			if e.get(fields[i]) != fields[i+1] {
				matches = false
			}
		}
		if matches {
			out = append(out, e)
		}
	}
	return out
}

// one is the record of a message that has these fields, when there is exactly
// one.
func (b *logBook) one(t *testing.T, msg string, fields ...string) entry {
	t.Helper()
	found := b.with(t, msg, fields...)
	if len(found) != 1 {
		t.Fatalf("%d records %q with %v, want one:\n%s", len(found), msg, fields, b.text())
	}
	return found[0]
}

// messages are the messages written, in order.
func (b *logBook) messages(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range b.entries(t) {
		out = append(out, e.get("msg"))
	}
	return out
}

// inOrder says want comes in got in that order, whatever else is between.
func inOrder(got, want []string) bool {
	next := 0
	for _, msg := range got {
		if next < len(want) && msg == want[next] {
			next++
		}
	}
	return next == len(want)
}

func TestALogFollowsARequestOntoTheWire(t *testing.T) {
	server := startEcho(t)
	book, log := newLogBook(LevelTrace)
	client := newTestClient(t, WithLogger(log))

	res, err := client.Do(&Request{URL: server.URL() + "/api/all",
		Header: NewHeader("cookie", "session=s3cr3t-cookie", "authorization", "Bearer s3cr3t-token")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Each step as it happened: the client, then the lookup of the name, the
	// dial, the handshake and what was sent over it, and the answer.
	want := []string{"client", "profile handshake", "profile http2", "profile headers", "request",
		"dns lookup", "dns answer", "dial", "dialed", "connected", "client hello", "certificate",
		"handshake extras", "request sent", "first byte", "response headers", "response"}
	if got := book.messages(t); !inOrder(got, want) {
		t.Fatalf("records %v, want %v in that order", got, want)
	}

	about := book.one(t, "client")
	id := about.get("client")
	if about.get("profile") != client.Profile().Name || about.get("verify_certificates") != "false" ||
		about.get("level") != "INFO" || about.get("proxy") != "" {
		t.Errorf("the client was said as %v", about)
	}
	asked := book.one(t, "request")
	if asked.get("client") != id || asked.get("request") != "1" || asked.get("method") != "GET" ||
		asked.get("url") != server.URL()+"/api/all" || asked.get("proxy") != "" || asked.get("body_bytes") != "" {
		t.Errorf("the request was said as %v", asked)
	}
	if answer := book.one(t, "dns answer"); answer.get("host") != "localhost" || answer.get("addrs") == "[]" {
		t.Errorf("the lookup was said as %v", answer)
	}
	connected := book.one(t, "connected")
	if connected.get("tls") != "TLS 1.3" || connected.get("alpn") != "h2" || connected.get("resumed") != "false" ||
		connected.get("server_name") != "localhost" || !strings.Contains(connected.get("conn"), "->") ||
		connected.get("certificate") != "CN=tlsforge echo" || connected.get("level") != "DEBUG" {
		t.Errorf("the connection was said as %v", connected)
	}
	// The handshake that went out is the profile's, and is said at the trace
	// level, as everything that long is.
	hello := book.one(t, "client hello")
	if hello.get("ja4") == "" || hello.get("ja4") != book.one(t, "profile handshake").get("ja4") ||
		hello.get("conn") != connected.get("conn") || hello.get("level") != "DEBUG-4" ||
		hello.get("server_name") != "localhost" ||
		!slices.Contains([]string{"144", "176", "208", "240"}, hello.get("ech_payload_bytes")) {
		t.Errorf("the hello was said as %v", hello)
	}
	if cert := book.one(t, "certificate"); cert.get("depth") != "0" || !strings.Contains(cert.get("dns_names"), "localhost") {
		t.Errorf("the certificate was said as %v", cert)
	}
	// The header fields as they went, with no secret in them.
	sent := book.one(t, "request sent").get("headers")
	for _, field := range []string{":path: /api/all", "cookie: session=***", "authorization: Bearer ***"} {
		if !strings.Contains(sent, field) {
			t.Errorf("sent %s, without %q", sent, field)
		}
	}
	if strings.Contains(book.text(), "s3cr3t") {
		t.Errorf("a secret was written down:\n%s", book.text())
	}
	if head := book.one(t, "response headers"); head.get("status") != "200" || head.get("proto") != "HTTP/2.0" {
		t.Errorf("the answer's head was said as %v", head)
	}
	if done := book.one(t, "response"); done.get("status") != "200" || done.get("bytes") != fmt.Sprint(len(res.Body)) ||
		done.get("level") != "INFO" || done.get("took") == "" {
		t.Errorf("the answer was said as %v", done)
	}
}

func TestALogSaysHowMuchARequestSends(t *testing.T) {
	server := startEcho(t)
	book, log := newLogBook(slog.LevelInfo)
	client := newTestClient(t, WithLogger(log))
	if _, err := client.Do(&Request{Method: "POST", URL: server.URL() + "/api/all", Body: []byte("12345")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if asked := book.one(t, "request"); asked.get("method") != "POST" || asked.get("body_bytes") != "5" {
		t.Errorf("the request was said as %v", asked)
	}
}

func TestALogSaysAConnectionWasReused(t *testing.T) {
	server := startEcho(t)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log))
	for range 2 {
		if _, err := client.Get(server.URL() + "/api/all"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	reused := book.one(t, "reused connection", "request", "2")
	if reused.get("conn") != book.one(t, "connected", "request", "1").get("conn") {
		t.Errorf("the reused connection was said as %v", reused)
	}
	if dials := book.with(t, "dial", "request", "2"); len(dials) != 0 {
		t.Errorf("a reused connection was dialled: %v", dials)
	}
}

func TestALogFollowsARedirect(t *testing.T) {
	server, _ := hopServer(t)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log))
	if _, err := client.Get(server.URL + "/hop"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	hop := book.one(t, "redirect")
	if hop.get("hop") != "1" || hop.get("status") != "302" || hop.get("location") != server.URL+"/landed" ||
		!strings.Contains(hop.get("headers"), "Location: /landed") {
		t.Errorf("the redirect was said as %v", hop)
	}
	sent := book.with(t, "request sent")
	if len(sent) != 2 || !strings.Contains(sent[0].get("headers"), ":path: /hop") ||
		!strings.Contains(sent[1].get("headers"), ":path: /landed") {
		t.Errorf("each hop's request was said as %v", sent)
	}
	if done := book.one(t, "response"); done.get("url") != server.URL+"/landed" {
		t.Errorf("the answer was said as %v", done)
	}

	// A chain that does not end stops where a request lets it, and says so.
	if _, err := client.Get(server.URL + "/loop"); err == nil {
		t.Fatal("a redirect that never ends was followed to an answer")
	}
	stopped := book.one(t, "redirect not followed")
	if stopped.get("hop") != "10" || stopped.get("limit") != "10" || stopped.get("level") != "WARN" {
		t.Errorf("the redirect not followed was said as %v", stopped)
	}
	if failed := book.one(t, "request failed"); failed.get("phase") != "redirect" ||
		!strings.Contains(failed.get("error"), "stopped after 10 redirects") {
		t.Errorf("the failure was said as %v", failed)
	}
}

func TestALogSaysWhereARequestFailed(t *testing.T) {
	t.Run("nothing listens", func(t *testing.T) {
		book, log := newLogBook(slog.LevelDebug)
		client := newTestClient(t, WithLogger(log), WithTimeout(2*time.Second))
		nowhere := refused(t)
		if _, err := client.Get("https://" + nowhere + "/"); err == nil {
			t.Fatal("expected a transport error")
		}
		// A literal address is looked up nowhere.
		if dial := book.one(t, "dial failed"); dial.get("addr") != nowhere || dial.get("level") != "DEBUG" {
			t.Errorf("the dial was said as %v", dial)
		}
		if failed := book.one(t, "request failed"); failed.get("phase") != "connect" || failed.get("timeout") != "false" {
			t.Errorf("the failure was said as %v", failed)
		}
		if lookups := book.with(t, "dns lookup"); len(lookups) != 0 {
			t.Errorf("an address was looked up: %v", lookups)
		}
	})

	t.Run("a certificate nothing vouches for", func(t *testing.T) {
		server := startEcho(t)
		book, log := newLogBook(slog.LevelDebug)
		client, err := New(WithLogger(log))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if _, err := client.Get(server.URL()); err == nil {
			t.Fatal("a certificate made for the run was believed")
		}
		if failed := book.one(t, "request failed"); failed.get("phase") != "tls" ||
			!strings.Contains(failed.get("error"), "certificate") {
			t.Errorf("the failure was said as %v", failed)
		}
		if about := book.one(t, "client"); about.get("verify_certificates") != "true" {
			t.Errorf("the client was said as %v", about)
		}
	})

	t.Run("a name that cannot be looked up", func(t *testing.T) {
		// Looked up through a resolver that reaches nothing, so that the lookup
		// fails here rather than on the network.
		resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no resolver here")
		}}
		book, log := newLogBook(slog.LevelDebug)
		client := newTestClient(t, WithLogger(log),
			WithTransportOption(tls_client.WithDialer(net.Dialer{Resolver: resolver})))
		if _, err := client.Get("https://nowhere.test/"); err == nil {
			t.Fatal("a name nothing resolves was reached")
		}
		if lookup := book.one(t, "dns failed"); lookup.get("host") != "nowhere.test" || lookup.get("level") != "WARN" {
			t.Errorf("the lookup was said as %v", lookup)
		}
		if failed := book.one(t, "request failed"); failed.get("phase") != "dns" {
			t.Errorf("the failure was said as %v", failed)
		}
	})

	t.Run("an answer that never comes", func(t *testing.T) {
		listener := holdingListener(t)
		book, log := newLogBook(slog.LevelDebug)
		client := newTestClient(t, WithLogger(log), WithTimeout(300*time.Millisecond))
		if _, err := client.Get("http://" + listener.Addr().String() + "/"); err == nil {
			t.Fatal("a server that never answered answered")
		}
		// Written, and waited on until the time ran out.
		book.one(t, "request sent")
		if failed := book.one(t, "request failed"); failed.get("phase") != "wait" || failed.get("timeout") != "true" {
			t.Errorf("the failure was said as %v", failed)
		}
	})

	t.Run("a body too large to keep", func(t *testing.T) {
		server := startEcho(t)
		book, log := newLogBook(slog.LevelDebug)
		client := newTestClient(t, WithLogger(log), WithMaxResponseBody(10))
		if _, err := client.Get(server.URL() + "/api/all"); !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err = %v", err)
		}
		// The head came, and is said, before the body that could not be kept.
		book.one(t, "response headers", "status", "200")
		if failed := book.one(t, "request failed"); failed.get("phase") != "body" {
			t.Errorf("the failure was said as %v", failed)
		}
	})

	t.Run("a request never made", func(t *testing.T) {
		book, log := newLogBook(slog.LevelDebug)
		client := newTestClient(t, WithLogger(log))
		if _, err := client.Do(nil); err == nil {
			t.Fatal("a request without a URL was made")
		}
		_ = client.Close()
		if _, err := client.Get("https://example.test/"); err == nil {
			t.Fatal("a closed client made a request")
		}
		// Without a request there is nothing to say it asked for; with one,
		// what it asked for and that it was never made.
		if asked := book.with(t, "request"); len(asked) != 1 || asked[0].get("url") != "https://example.test/" {
			t.Errorf("requests said as %v", asked)
		}
		for _, failed := range book.with(t, "request failed") {
			if failed.get("phase") != "prepare" {
				t.Errorf("the failure was said as %v", failed)
			}
		}
		if failed := book.with(t, "request failed"); len(failed) != 2 {
			t.Errorf("failures said as %v", failed)
		}
	})
}

// holdingListener takes connections and never says anything on them.
func holdingListener(t *testing.T) net.Listener {
	t.Helper()
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
	return listener
}

func TestALogFollowsATunnel(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log), WithProxy(via.url()))

	if _, err := client.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	proxyURL := strings.Replace(via.server.URL, "://", "://user@", 1)
	if asked := book.one(t, "request"); asked.get("proxy") != proxyURL {
		t.Errorf("the request was said as %v", asked)
	}
	ask := book.one(t, "proxy connect", "request", "1")
	if ask.get("proxy") != proxyURL || ask.get("target") != strings.TrimPrefix(server.URL(), "https://") ||
		ask.get("headers") != "[Proxy-Authorization: Basic ***]" {
		t.Errorf("the CONNECT was said as %v", ask)
	}
	answer := book.one(t, "proxy answer", "request", "1")
	if answer.get("status") != "200 Connection established" || answer.get("tunnel") == "" ||
		!strings.Contains(answer.get("headers"), "X-Exit-Ip: 203.0.113.1") {
		t.Errorf("the proxy's answer was said as %v", answer)
	}
	if connected := book.one(t, "connected", "request", "1"); connected.get("tunnel") != answer.get("tunnel") ||
		!strings.HasSuffix(connected.get("conn"), strings.TrimPrefix(via.server.URL, "http://")) {
		t.Errorf("the connection was said as %v", connected)
	}

	// The next connection HTTP/2 dials for no request in particular, and the
	// tunnel it went through is the one the request's connection says.
	client.CloseIdleConnections()
	if _, err := client.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	book.one(t, "idle connections closed")
	background := book.one(t, "proxy answer", "background", "true")
	if connected := book.one(t, "connected", "request", "2"); connected.get("tunnel") != background.get("tunnel") ||
		background.get("tunnel") == answer.get("tunnel") {
		t.Errorf("the second connection was said as %v, its tunnel as %v", connected, background)
	}
	book.one(t, "proxy connect", "background", "true")
	book.one(t, "dialed", "background", "true")

	// Not the password, in any shape.
	secret := base64.StdEncoding.EncodeToString([]byte("user:s3cr3t"))
	if text := book.text(); strings.Contains(text, "s3cr3t") || strings.Contains(text, secret) {
		t.Errorf("the proxy's password was written down:\n%s", text)
	}
}

func TestALogSaysWhyAProxyRefused(t *testing.T) {
	server := startEcho(t)
	long := strings.Repeat("x", 2000)
	for _, tc := range []struct {
		name, answer, body string
	}{
		{"with a reason", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"zone\"\r\n" +
			"Content-Length: 12\r\n\r\nAuth failed.", "Auth failed."},
		// No longer than a kilobyte of it.
		{"at length", "HTTP/1.1 403 Forbidden\r\nContent-Length: 2000\r\n\r\n" + long, long[:1024]},
		// Without a length there is no telling where it ends, and it is not
		// waited for.
		{"without a length", "HTTP/1.1 502 Bad Gateway\r\n\r\nupstream gone", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			via := startConnectProxy(t, false, func(int32) string { return tc.answer })
			book, log := newLogBook(slog.LevelDebug)
			client := newTestClient(t, WithLogger(log), WithProxy(via.server.URL))
			if _, err := client.Get(server.URL()); err == nil {
				t.Fatal("a refused tunnel was used")
			}
			refused := book.one(t, "proxy refused")
			status := strings.TrimPrefix(strings.SplitN(tc.answer, "\r\n", 2)[0], "HTTP/1.1 ")
			if refused.get("status") != status || refused.get("body") != tc.body || refused.get("level") != "WARN" {
				t.Errorf("the refusal was said as %v", refused)
			}
			if failed := book.one(t, "request failed"); failed.get("phase") != "proxy" {
				t.Errorf("the failure was said as %v", failed)
			}
		})
	}
	// Proxy-Authenticate is what a proxy asks for, and is said.
	via := startConnectProxy(t, false, func(int32) string {
		return "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"zone\"\r\n\r\n"
	})
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log), WithProxy(via.server.URL))
	_, _ = client.Get(server.URL())
	if refused := book.one(t, "proxy refused"); !strings.Contains(refused.get("headers"), `Proxy-Authenticate: Basic realm="zone"`) {
		t.Errorf("the refusal was said as %v", refused)
	}

	// Hung up on without a word.
	via = startConnectProxy(t, false, func(int32) string { return "" })
	book, log = newLogBook(slog.LevelDebug)
	client = newTestClient(t, WithLogger(log), WithProxy(via.server.URL))
	if _, err := client.Get(server.URL()); err == nil {
		t.Fatal("a proxy that said nothing opened a tunnel")
	}
	if failed := book.one(t, "proxy connect failed"); !strings.Contains(failed.get("error"), "EOF") {
		t.Errorf("the failure was said as %v", failed)
	}
	if failed := book.one(t, "request failed"); failed.get("phase") != "proxy" {
		t.Errorf("the failure was said as %v", failed)
	}
}

func TestALogSaysACONNECTThatCouldNotBeWritten(t *testing.T) {
	book, log := newLogBook(slog.LevelDebug)
	ctx := newRequestLog(log, "", "proxy").attachDial(context.Background())
	u, _ := url.Parse("http://proxy.test")
	if _, err := newConnectDialer(u, time.Second, nil, nil, nil).open(ctx, unwritable{}, "example.test:443"); err == nil {
		t.Fatal("a CONNECT nobody could write was answered")
	}
	if failed := book.one(t, "proxy connect failed"); !strings.Contains(failed.get("error"), "broken pipe") {
		t.Errorf("the failure was said as %v", failed)
	}
}

func TestALogFollowsAnHTTPSProxy(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, true, exitAnswer)

	// A proxy whose certificate nothing vouches for is never asked.
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log), WithProxy(via.server.URL))
	if _, err := client.Get(server.URL()); err == nil {
		t.Fatal("a proxy nothing vouches for was asked")
	}
	if failed := book.one(t, "proxy tls failed"); !strings.Contains(failed.get("error"), "certificate") {
		t.Errorf("the handshake was said as %v", failed)
	}
	if failed := book.one(t, "request failed"); failed.get("phase") != "proxy" {
		t.Errorf("the failure was said as %v", failed)
	}
	if asked := book.with(t, "proxy connect"); len(asked) != 0 {
		t.Errorf("an unverified proxy was asked: %v", asked)
	}

	roots := x509.NewCertPool()
	roots.AddCert(via.server.Certificate())
	original := proxyRoots
	t.Cleanup(func() { proxyRoots = original })
	proxyRoots = roots

	book, log = newLogBook(slog.LevelDebug)
	client = newTestClient(t, WithLogger(log), WithProxy(via.server.URL))
	if _, err := client.Get(server.URL()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	secure := book.one(t, "proxy tls")
	if secure.get("tls") != "TLS 1.3" || secure.get("alpn") != "http/1.1" || secure.get("certificate") == "" {
		t.Errorf("the handshake with the proxy was said as %v", secure)
	}
	if !inOrder(book.messages(t), []string{"dialed", "proxy tls", "proxy connect", "proxy answer", "connected"}) {
		t.Errorf("records %v", book.messages(t))
	}

	// Nothing there to shake hands with.
	book, log = newLogBook(slog.LevelDebug)
	nowhere := refused(t)
	client = newTestClient(t, WithLogger(log), WithProxy("https://"+nowhere), WithTimeout(2*time.Second))
	if _, err := client.Get(server.URL()); err == nil {
		t.Fatal("a proxy that is not there opened a tunnel")
	}
	book.one(t, "dial failed", "addr", nowhere)
	if failed := book.one(t, "request failed"); failed.get("phase") != "connect" {
		t.Errorf("the failure was said as %v", failed)
	}
}

func TestALogOfAConnectionNoRequestDialled(t *testing.T) {
	// HTTP/2 dials every connection after a client's first apart from the
	// request that needs it, and the log still has the lookup and the dial.
	server := startEcho(t)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log))
	for range 2 {
		if _, err := client.Get(server.URL() + "/api/all"); err != nil {
			t.Fatalf("Get: %v", err)
		}
		client.CloseIdleConnections()
	}
	book.one(t, "dns lookup", "background", "true")
	dialed := book.one(t, "dialed", "background", "true")
	if connected := book.one(t, "connected", "request", "2"); !strings.HasSuffix(connected.get("conn"), dialed.get("addr")) {
		t.Errorf("the connection was said as %v, the dial as %v", connected, dialed)
	}
}

func TestARequestLogsToItsOwnLogger(t *testing.T) {
	server := startEcho(t)
	clientBook, clientLog := newLogBook(slog.LevelDebug)
	ownBook, ownLog := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(clientLog))
	if _, err := client.Do(&Request{URL: server.URL(), Logger: ownLog.With("purpose", "probe")}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	id := clientBook.one(t, "client").get("client")
	if asked := ownBook.one(t, "request"); asked.get("purpose") != "probe" || asked.get("client") != id ||
		asked.get("request") != "" {
		t.Errorf("the request was said as %v", asked)
	}
	if asked := clientBook.with(t, "request"); len(asked) != 0 {
		t.Errorf("the client's log has the request: %v", asked)
	}

	// A client with no logger of its own logs a request that has one.
	quiet := newTestClient(t)
	ownBook, ownLog = newLogBook(slog.LevelDebug)
	if _, err := quiet.Do(&Request{URL: server.URL(), Logger: ownLog}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	ownBook.one(t, "response")
}

func TestALogSaysAsMuchAsItIsAskedFor(t *testing.T) {
	server := startEcho(t)
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log))
	if _, err := client.Get(server.URL()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, msg := range []string{"client hello", "certificate", "handshake extras", "connection wanted"} {
		if found := book.with(t, msg); len(found) != 0 {
			t.Errorf("a debug log has %q: %v", msg, found)
		}
	}
	book.one(t, "connected")

	book, log = newLogBook(slog.LevelInfo)
	client = newTestClient(t, WithLogger(log))
	if _, err := client.Get(server.URL()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := book.messages(t); !slices.Equal(got, []string{"client", "request", "response"}) {
		t.Errorf("an info log has %v", got)
	}
}

func TestALogSaysWhatBecameOfEachClient(t *testing.T) {
	book, log := newLogBook(slog.LevelDebug)
	client := newTestClient(t, WithLogger(log))
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	fresh.CloseIdleConnections()
	_ = fresh.Close()
	parent := book.one(t, "client").get("client")
	made := book.one(t, "fresh client")
	if made.get("from") != parent || made.get("client") == parent || made.get("client") == "" {
		t.Errorf("the fresh client was said as %v, from %s", made, parent)
	}
	book.one(t, "idle connections closed", "client", made.get("client"))
	book.one(t, "client closed", "client", made.get("client"))

	// A client given no logger says nothing, and nor does one made Fresh of it.
	quiet := newTestClient(t)
	fromQuiet, err := quiet.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	if fromQuiet.log != nil || quiet.log != nil {
		t.Error("a client given no logger logs")
	}
	_ = fromQuiet.Close()
}

func TestALogSaysWhatTheClientWears(t *testing.T) {
	// A profile out of the catalogue, which knows a handshake and no headers.
	book, log := newLogBook(slog.LevelDebug)
	newTestClient(t, WithLogger(log), WithProfile("chrome_133"))
	if made := book.one(t, "profile handshake"); made.get("from") != "tls-client's catalogue" ||
		made.get("base") != "chrome_133" {
		t.Errorf("the handshake was said as %v", made)
	}
	if headers := book.one(t, "profile headers"); headers.get("order") != "[]" {
		t.Errorf("the headers were said as %v", headers)
	}
	// Its HTTP/2 preface is the catalogue's, which is where it is kept.
	if preface := book.one(t, "profile http2"); preface.get("akamai") != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Errorf("the HTTP/2 preface was said as %v", preface)
	}
	// One that sends PRIORITY frames says how many.
	book, log = newLogBook(slog.LevelDebug)
	newTestClient(t, WithLogger(log), WithProfile("firefox_117"))
	if preface := book.one(t, "profile http2"); preface.get("priorities") == "0" ||
		!strings.Contains(preface.get("akamai"), ",") {
		t.Errorf("the HTTP/2 preface was said as %v", preface)
	}

	// One read from a file says which, and one through a proxy says which.
	p, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "mine.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	book, log = newLogBook(slog.LevelDebug)
	newTestClient(t, WithLogger(log), WithProfile(path), WithProxy("http://user:s3cr3t@proxy.test:8080"),
		WithFixedExtensionOrder())
	about := book.one(t, "client")
	if about.get("file") != path || about.get("proxy") != "http://user@proxy.test:8080" ||
		about.get("extension_order") != "fixed" {
		t.Errorf("the client was said as %v", about)
	}
	preface := book.one(t, "profile http2")
	if preface.get("akamai") != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" ||
		!strings.Contains(preface.get("settings"), "INITIAL_WINDOW_SIZE=6291456") {
		t.Errorf("the HTTP/2 preface was said as %v", preface)
	}
	if strings.Contains(book.text(), "s3cr3t") {
		t.Errorf("the proxy's password was written down:\n%s", book.text())
	}
}

func TestALogSaysNoECHOfAHelloWithout(t *testing.T) {
	// Safari 16 sends no encrypted_client_hello, so there is no length to say.
	server := startEcho(t)
	book, log := newLogBook(LevelTrace)
	client := newTestClient(t, WithProfile("safari_16_0"), WithLogger(log))
	if _, err := client.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hello := book.one(t, "client hello"); hello.get("ja4") == "" || hello.get("ech_payload_bytes") != "" {
		t.Errorf("the hello was said as %v", hello)
	}
}

func TestALogOverPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	t.Cleanup(server.Close)
	book, log := newLogBook(LevelTrace)
	client := newTestClient(t, WithLogger(log))
	if _, err := client.Get(server.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	// No handshake, so nothing said of one; and HTTP/1.1 keeps its connection
	// for the next request, and says so.
	connected := book.one(t, "connected")
	if connected.get("tls") != "" || connected.get("conn") == "" {
		t.Errorf("the connection was said as %v", connected)
	}
	if found := book.with(t, "client hello"); len(found) != 0 {
		t.Errorf("a plain connection has a hello: %v", found)
	}
	book.one(t, "connection kept for the next request")
	if head := book.one(t, "response headers"); head.get("proto") != "HTTP/1.1" {
		t.Errorf("the answer's head was said as %v", head)
	}
}

func TestRequestLogStepsNoTransportShows(t *testing.T) {
	// A connection that could not be kept, and a request that could not be
	// written, which no server here can be made to cause on cue.
	book, log := newLogBook(slog.LevelDebug)
	r := newRequestLog(log, "http://user:s3cr3t@proxy.test", "send")
	r.putIdleConn(errors.New("too many idle connections"))
	r.wroteRequest(nil, errors.New("write to http://user:s3cr3t@proxy.test failed"))
	if kept := book.one(t, "connection not kept"); kept.get("reason") != "too many idle connections" {
		t.Errorf("the connection was said as %v", kept)
	}
	if sent := book.one(t, "send failed"); sent.get("error") != "write to http://user@proxy.test failed" ||
		sent.get("level") != "WARN" {
		t.Errorf("the failure was said as %v", sent)
	}
	if r.in() != "wait" {
		t.Errorf("phase = %q", r.in())
	}
}

// nowhereConn is a connection that cannot say where either end of it is.
type nowhereConn struct{ net.Conn }

func (nowhereConn) LocalAddr() net.Addr  { return nil }
func (nowhereConn) RemoteAddr() net.Addr { return nil }

func TestConnName(t *testing.T) {
	if got := connName(nowhereConn{}); got != "?->?" {
		t.Errorf("connName = %q", got)
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if got := connName(a); got != "pipe->pipe" {
		t.Errorf("connName = %q", got)
	}
}

func TestSentHello(t *testing.T) {
	if sentHello(nowhereConn{}) != nil {
		t.Error("a connection with no handshake has a hello")
	}
	uconn := &utls.UConn{}
	if sentHello(uconn) != nil {
		t.Error("a handshake not begun has a hello")
	}
	uconn.HandshakeState.Hello = &utls.PubClientHelloMsg{Raw: []byte{1, 0, 0, 1, 3}}
	if sentHello(uconn) != nil {
		t.Error("a hello that does not parse was read")
	}
	p, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	// The profile's own, without the record it was captured in.
	uconn.HandshakeState.Hello = &utls.PubClientHelloMsg{Raw: p.ClientHello[5:]}
	want, err := fingerprint.ParseClientHello(p.ClientHello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if got := sentHello(uconn); got == nil || got.JA4() != want.JA4() {
		t.Errorf("sentHello = %v", got)
	}
}

// timeoutError is an error that says it is a timeout.
type timeoutError struct{}

func (timeoutError) Error() string { return "slow" }
func (timeoutError) Timeout() bool { return true }

func TestIsTimeout(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{context.DeadlineExceeded, true},
		{fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), true},
		{&url.Error{Op: "Get", URL: "x", Err: timeoutError{}}, true},
		{context.Canceled, false},
		{errors.New("refused"), false},
	} {
		if got := isTimeout(tc.err); got != tc.want {
			t.Errorf("isTimeout(%v) = %v", tc.err, got)
		}
	}
}

func TestRefusalBody(t *testing.T) {
	for _, tc := range []struct {
		length int64
		body   string
		want   string
	}{
		{0, "", ""},
		{-1, "unknown", ""},
		{5, "short", "short"},
		{2000, strings.Repeat("y", 2000), strings.Repeat("y", 1024)},
		// Cut short by the proxy: what came is what is said.
		{10, "cut", "cut"},
	} {
		answer := &fhttp.Response{ContentLength: tc.length, Body: io.NopCloser(strings.NewReader(tc.body))}
		if got := refusalBody(answer); got != tc.want {
			t.Errorf("refusalBody(%d, %d bytes) = %d bytes", tc.length, len(tc.body), len(got))
		}
	}
}

func TestSortedHeaderLines(t *testing.T) {
	got := sortedHeaderLines(map[string][]string{
		"Set-Cookie": {"id=abc; Path=/", "theme=dark"},
		"Age":        {"3"},
	})
	want := []string{"Age: 3", "Set-Cookie: id=***; Path=/", "Set-Cookie: theme=***"}
	if !slices.Equal(got, want) {
		t.Errorf("sortedHeaderLines = %q, want %q", got, want)
	}
	// Nothing is a list of nothing rather than no list: JSON says [] for it.
	if got := sortedHeaderLines(nil); got == nil || len(got) != 0 {
		t.Errorf("sortedHeaderLines(nil) = %#v", got)
	}
}

func TestGotConnOfAConnectionWithoutAHelloOfItsOwn(t *testing.T) {
	// A TLS connection the transport did not make with utls has a state and no
	// ClientHello to show, and says the one without the other.
	book, log := newLogBook(LevelTrace)
	r := newRequestLog(log, "", "connect")
	r.gotConn(fhttptrace.GotConnInfo{Conn: statedConn{}})
	if connected := book.one(t, "connected"); connected.get("tls") != "TLS 1.2" {
		t.Errorf("the connection was said as %v", connected)
	}
	// With a connection in hand, what is under way is sending the request.
	if r.in() != "send" {
		t.Errorf("phase = %q", r.in())
	}
	if found := book.with(t, "client hello"); len(found) != 0 {
		t.Errorf("a hello was said: %v", found)
	}
	book.one(t, "handshake extras")
}

// statedConn is a connection with a handshake behind it and no ClientHello.
type statedConn struct{ nowhereConn }

func (statedConn) ConnectionState() utls.ConnectionState {
	return utls.ConnectionState{Version: utls.VersionTLS12}
}
