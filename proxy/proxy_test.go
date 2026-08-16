package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
)

func newCAForTest(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	return ca
}

// errorLog collects what the proxy reports. A plain slice would not do: the
// handler appends from its own goroutine, so both ends need the mutex, and a
// slice returned by value would never see the appends at all.
type errorLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *errorLog) add(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, err)
}

func (l *errorLog) list() []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]error(nil), l.errs...)
}

func startProxy(t *testing.T, client Client, ca *CA) (*Server, *errorLog) {
	t.Helper()
	problems := &errorLog{}
	server, err := Start(Options{CA: ca, Client: client, OnError: problems.add})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, problems
}

// throughProxy is an ordinary Go HTTP client pointed at the proxy and told to
// trust its authority. Go's own TLS is exactly the fingerprint the proxy is
// supposed to replace, which is what makes it the right client for these tests.
func throughProxy(t *testing.T, server *Server, ca *CA) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("the authority is not usable as a trust root")
	}
	proxyURL, err := url.Parse("http://" + server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

// This is the test the package exists for. A proxy that tunnelled CONNECT would
// let Go's own handshake reach the destination, and the destination would see
// Go. The echo server reports what it actually saw.
func TestTheDestinationSeesTheBrowserNotTheCaller(t *testing.T) {
	destination, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	defer destination.Close()

	// What the destination sees when Go talks to it directly.
	direct := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	goJA4 := ja4Of(t, direct, destination.URL()+"/api/all")

	client, err := tlsforge.New(tlsforge.WithInsecureSkipVerify(), tlsforge.WithoutCookieJar())
	if err != nil {
		t.Fatalf("tlsforge.New: %v", err)
	}
	defer client.Close()

	ca := newCAForTest(t)
	server, problems := startProxy(t, client, ca)
	proxied := throughProxy(t, server, ca)
	proxiedJA4 := ja4Of(t, proxied, destination.URL()+"/api/all")

	if proxiedJA4 == goJA4 {
		t.Fatalf("the destination saw the same handshake through the proxy as without it (%s); "+
			"the proxy is tunnelling, not re-originating", proxiedJA4)
	}

	// And it is specifically the browser's, not merely something else.
	measured, err := tlsforge.MeasureSelf(t.Context(), tlsforge.WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("MeasureSelf: %v", err)
	}
	if proxiedJA4 != measured.TLS.JA4 {
		t.Errorf("through the proxy the destination saw %s, want the profile's %s",
			proxiedJA4, measured.TLS.JA4)
	}
	if reported := problems.list(); len(reported) != 0 {
		t.Errorf("proxy reported: %v", reported)
	}
}

func ja4Of(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	var measured capture.Capture
	if err := json.Unmarshal(body, &measured); err != nil {
		t.Fatalf("decoding %q: %v", string(body[:min(len(body), 80)]), err)
	}
	return measured.TLS.JA4
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestTheHeadersAreTheProfilesToo(t *testing.T) {
	destination, err := echo.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()

	client, err := tlsforge.New(tlsforge.WithInsecureSkipVerify(), tlsforge.WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ca := newCAForTest(t)
	server, _ := startProxy(t, client, ca)

	req, err := http.NewRequest("GET", destination.URL()+"/api/all", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A caller announcing itself. The point of the proxy is that none of this
	// reaches the destination except the header it could not have invented.
	req.Header.Set("User-Agent", "curl/8.4.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Api-Key", "secret")

	res, err := throughProxy(t, server, ca).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var measured capture.Capture
	if err := json.Unmarshal(body, &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	seen := measured.HTTP2.Fingerprint()

	if ua, _ := seen.Header("user-agent"); strings.Contains(ua, "curl") {
		t.Errorf("the caller's user-agent reached the destination: %q", ua)
	}
	if ua, _ := seen.Header("user-agent"); !strings.Contains(ua, "Chrome") {
		t.Errorf("user-agent = %q, want the profile's", ua)
	}
	// Cookies and API keys are the caller's business and cannot be invented.
	if cookie, _ := seen.Header("cookie"); cookie != "session=abc" {
		t.Errorf("cookie = %q, want it forwarded", cookie)
	}
	if key, _ := seen.Header("x-api-key"); key != "secret" {
		t.Errorf("x-api-key = %q, want it forwarded", key)
	}
	// The browser's own order, with the extras after it.
	order := seen.HeaderOrder()
	if order[0] != "sec-ch-ua" {
		t.Errorf("header order starts %q, want the profile's first header", order[0])
	}
}

func TestPlainHTTPIsForwardedToo(t *testing.T) {
	var gotUA, gotPath string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotPath = r.Header.Get("User-Agent"), r.URL.Path
		w.Header().Set("X-Custom", "yes")
		_, _ = io.WriteString(w, "plain hello")
	}))
	defer destination.Close()

	client, err := tlsforge.New(tlsforge.WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ca := newCAForTest(t)
	server, _ := startProxy(t, client, ca)

	res, err := throughProxy(t, server, ca).Get(destination.URL + "/plain/path")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if string(body) != "plain hello" {
		t.Errorf("body = %q", body)
	}
	if res.Header.Get("X-Custom") != "yes" {
		t.Errorf("upstream headers were not passed back: %v", res.Header)
	}
	if gotPath != "/plain/path" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotUA, "Chrome") {
		t.Errorf("user-agent = %q, want the profile's", gotUA)
	}
}

func TestARequestBodyIsForwarded(t *testing.T) {
	var got string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
		w.WriteHeader(201)
	}))
	defer destination.Close()

	client, err := tlsforge.New(tlsforge.WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ca := newCAForTest(t)
	server, _ := startProxy(t, client, ca)

	res, err := throughProxy(t, server, ca).Post(destination.URL+"/submit", "application/json",
		strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got != `{"a":1}` {
		t.Errorf("the destination received %q", got)
	}
	if res.StatusCode != 201 {
		t.Errorf("status = %d", res.StatusCode)
	}
}

// failingClient stands in for a destination that cannot be reached.
type failingClient struct{ err error }

func (f failingClient) Do(*tlsforge.Request) (*tlsforge.Response, error) { return nil, f.err }
func (f failingClient) Headers() tlsforge.Header                         { return nil }

func TestAnUnreachableDestinationBecomesA502(t *testing.T) {
	// Dropping the connection would leave the caller guessing between "the proxy
	// is broken" and "the site is down".
	ca := newCAForTest(t)
	server, _ := startProxy(t, failingClient{err: errors.New("dial tcp: refused")}, ca)

	res, err := throughProxy(t, server, ca).Get("https://unreachable.example/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != 502 {
		t.Errorf("status = %d, want 502", res.StatusCode)
	}
	if !strings.Contains(string(body), "refused") {
		t.Errorf("body = %q, want the reason", body)
	}
}

func TestAClientThatDoesNotTrustTheAuthorityIsReported(t *testing.T) {
	ca := newCAForTest(t)
	server, problems := startProxy(t, failingClient{err: errors.New("unused")}, ca)

	proxyURL, _ := url.Parse("http://" + server.Addr())
	untrusting := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}}
	if _, err := untrusting.Get("https://example.invalid/"); err == nil {
		t.Fatal("expected the client to refuse the proxy's certificate")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range problems.list() {
			if strings.Contains(p.Error(), "did not accept the certificate") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("the refusal was not reported: %v", problems.list())
}

func TestStartRejectsAnIncompleteConfiguration(t *testing.T) {
	if _, err := Start(Options{}); err == nil {
		t.Error("expected an error without a certificate authority")
	}
	if _, err := Start(Options{CA: newCAForTest(t)}); err == nil {
		t.Error("expected an error without a client")
	}
	if _, err := Start(Options{
		CA: newCAForTest(t), Client: failingClient{}, Addr: "256.256.256.256:0",
	}); err == nil {
		t.Error("expected an error for an unusable address")
	}
}

func TestStartWithoutAnErrorHandler(t *testing.T) {
	// OnError is optional; the server must not call a nil function.
	server, err := Start(Options{CA: newCAForTest(t), Client: failingClient{}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "this is not a request\r\n\r\n")
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

func TestCloseIsFinal(t *testing.T) {
	server, err := Start(Options{CA: newCAForTest(t), Client: failingClient{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.Close(); err == nil {
		t.Error("expected the second Close to say it was already closed")
	}
}

func TestMergeHeaders(t *testing.T) {
	profile := tlsforge.NewHeader("sec-ch-ua", `"Chromium";v="151"`, "user-agent", "Chrome", "accept", "text/html")
	incoming := http.Header{}
	incoming.Set("User-Agent", "curl/8.4.0")       // the profile owns this
	incoming.Set("Zeta", "1")                      // kept, sorted after the profile
	incoming.Set("Alpha", "2")                     // kept
	incoming.Set("Proxy-Connection", "keep-alive") // hop-by-hop
	incoming.Set("Connection", "close")            // hop-by-hop
	incoming.Set("Content-Length", "10")           // recomputed downstream
	incoming.Set("Host", "elsewhere.example")      // derived from the URL

	merged := mergeHeaders(profile, incoming)
	if got := merged.Get("user-agent"); got != "Chrome" {
		t.Errorf("user-agent = %q, want the profile's", got)
	}
	want := []string{"sec-ch-ua", "user-agent", "accept", "alpha", "zeta"}
	got := merged.Names()
	if len(got) != len(want) {
		t.Fatalf("headers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("headers = %v, want %v", got, want)
		}
	}
}

func TestWriteResponseRecomputesFraming(t *testing.T) {
	var out strings.Builder
	err := writeResponse(&out, 200, map[string][]string{
		"content-type":      {"text/html"},
		"content-length":    {"99999"}, // stale: the body was decompressed
		"transfer-encoding": {"chunked"},
		"connection":        {"close"},
		"set-cookie":        {"a=1", "b=2"},
	}, []byte("hello"))
	if err != nil {
		t.Fatalf("writeResponse: %v", err)
	}
	written := out.String()

	if strings.Contains(written, "99999") || strings.Contains(written, "chunked") {
		t.Errorf("stale framing headers were forwarded:\n%s", written)
	}
	if !strings.Contains(written, "content-length: 5") {
		t.Errorf("content-length was not recomputed:\n%s", written)
	}
	if strings.Count(written, "set-cookie:") != 2 {
		t.Errorf("multi-valued headers were collapsed:\n%s", written)
	}
}

func TestWriteResponseReportsAFailedWrite(t *testing.T) {
	if err := writeResponse(failingWriter{}, 200, nil, []byte("x")); err == nil {
		t.Error("expected an error writing the head")
	}
	if err := writeResponse(&headOnlyWriter{}, 200, nil, []byte("x")); err == nil {
		t.Error("expected an error writing the body")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// headOnlyWriter accepts the first write and fails the second, which is where
// the body goes.
type headOnlyWriter struct{ wrote bool }

func (h *headOnlyWriter) Write(b []byte) (int, error) {
	if h.wrote {
		return 0, errors.New("broken pipe")
	}
	h.wrote = true
	return len(b), nil
}

func TestIsClosed(t *testing.T) {
	if isClosed(nil) {
		t.Error("nil is not a closed connection")
	}
	for _, err := range []error{net.ErrClosed, io.EOF,
		errors.New("read: connection reset by peer"),
		errors.New("write: broken pipe"),
		errors.New("use of closed network connection")} {
		if !isClosed(err) {
			t.Errorf("%v should read as closed", err)
		}
	}
	if isClosed(errors.New("no route to host")) {
		t.Error("an unrelated error should not read as closed")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "a", "b"); got != "a" {
		t.Errorf("= %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("= %q", got)
	}
}

func TestCAIsReusedBetweenRuns(t *testing.T) {
	// A CA regenerated on every start would have to be re-trusted on every
	// start, and the natural response to that is to stop verifying anything.
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")

	first, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first.CertPEM()) != string(second.CertPEM()) {
		t.Error("the authority was regenerated instead of reloaded")
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// The key is the authority. Anyone who reads it can impersonate every site
	// to anyone who trusts this CA.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 600", mode)
	}
}

func TestCAErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(bad, bad); err == nil {
		t.Error("expected an error for files that are not PEM")
	}

	// A PEM block that is not a certificate.
	notCert := filepath.Join(dir, "wrong.pem")
	if err := os.WriteFile(notCert, []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(notCert, notCert); err == nil {
		t.Error("expected an error for a PEM block that is not a certificate")
	}

	// A good certificate with a key that is not one.
	good := newCAForTest(t)
	certFile := filepath.Join(dir, "good.pem")
	if err := os.WriteFile(certFile, good.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	badKey := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badKey, []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(certFile, badKey); err == nil {
		t.Error("expected an error for an unusable key")
	}

	// A path that cannot be written.
	unwritable := filepath.Join(dir, "file-not-a-dir")
	if err := os.WriteFile(unwritable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(filepath.Join(unwritable, "ca.pem"), filepath.Join(unwritable, "ca.key")); err == nil {
		t.Error("expected an error when the authority cannot be written")
	}
}

func TestLeafCertificates(t *testing.T) {
	ca := newCAForTest(t)

	first, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Error("a second certificate was minted for the same host")
	}

	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNS names = %v", leaf.DNSNames)
	}
	if len(first.Certificate) != 2 {
		t.Errorf("the chain has %d certificates, want the leaf and the authority",
			len(first.Certificate))
	}

	// An IP has to go in the SAN as an IP, or no client will accept it.
	byIP, err := ca.leafFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ipLeaf, err := x509.ParseCertificate(byIP.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(ipLeaf.IPAddresses) != 1 {
		t.Errorf("IP addresses = %v", ipLeaf.IPAddresses)
	}
}
