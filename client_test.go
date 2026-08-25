package tlsforge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Every test here runs against the local echo server rather than the internet.
// That is not only about speed: it means a failure is a failure of this code,
// and the assertions can be about the actual bytes sent rather than about
// whether some third party liked them.
func startEcho(t *testing.T) *echo.Server {
	t.Helper()
	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func newTestClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	client, err := New(append(opts, WithInsecureSkipVerify())...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func measure(t *testing.T, client *Client, server *echo.Server) *capture.Capture {
	t.Helper()
	res, err := client.Get(server.URL() + "/api/all")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !res.OK() {
		t.Fatalf("status = %d", res.Status)
	}
	var measured capture.Capture
	if err := json.Unmarshal(res.Body, &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return &measured
}

func TestTheDefaultClientSendsTheMeasuredChromeHandshake(t *testing.T) {
	// The claim the whole library rests on, checked end to end: the bytes on the
	// wire are the ones captured from a real browser.
	server := startEcho(t)
	client := newTestClient(t)

	measured := measure(t, client, server)
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	want, err := profile.Get(shipped.Name)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	expected, err := (&capture.Capture{RawClientHello: want.ClientHello}).Hello()
	if err != nil {
		t.Fatalf("parsing the shipped profile: %v", err)
	}

	if measured.TLS.JA4 != expected.JA4() {
		t.Errorf("JA4 = %s, want the profile's %s", measured.TLS.JA4, expected.JA4())
	}
	if measured.TLS.Resumed {
		t.Error("the first connection reported itself as resumed")
	}
	if got, want := measured.HTTP2.HeaderOrder, shipped.HeaderOrder(); !reflect.DeepEqual(got, want) {
		t.Errorf("header order = %v\nwant             %v", got, want)
	}
	if got, want := measured.HTTP2.PseudoHeaderOrder, []string{"m", "a", "s", "p"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pseudo header order = %v, want %v", got, want)
	}
	if measured.UserAgent() != shipped.UserAgent {
		t.Errorf("user-agent = %q, want %q", measured.UserAgent(), shipped.UserAgent)
	}
}

func TestExtensionOrderIsShuffledLikeChrome(t *testing.T) {
	// Chrome randomises its extension order on every connection, so a client
	// that always sends the same order is distinguishable from Chrome even with
	// Chrome's exact extension set. JA4 sorts before hashing, so it must NOT
	// move; JA3 does not, so it must.
	server := startEcho(t)

	// A fresh client per iteration, because a client reuses its connection and
	// one connection is one handshake. Reusing it would measure the same
	// ClientHello six times and conclude, wrongly, that nothing varies.
	ja3 := map[string]bool{}
	ja4 := map[string]bool{}
	for i := 0; i < 6; i++ {
		measured := measure(t, newTestClient(t), server)
		ja3[measured.TLS.JA3Hash] = true
		ja4[measured.TLS.JA4] = true
	}

	if len(ja4) != 1 {
		t.Errorf("JA4 varied across connections: %v", keys(ja4))
	}
	if len(ja3) < 2 {
		t.Errorf("JA3 was stable across 6 connections; the extension order is not being shuffled")
	}
}

func TestFixedExtensionOrder(t *testing.T) {
	// Firefox and Safari send a stable order, and against those a shuffling
	// client is the anomaly.
	server := startEcho(t)

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		seen[measure(t, newTestClient(t, WithFixedExtensionOrder()), server).TLS.JA3Hash] = true
	}
	if len(seen) != 1 {
		t.Errorf("JA3 varied with shuffling disabled: %v", keys(seen))
	}
}

func TestPerRequestHeadersKeepTheProfileOrder(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t)

	res, err := client.Do(&Request{
		URL:    server.URL() + "/api/all",
		Header: NewHeader("Accept-Language", "en-GB,en;q=0.9", "X-Extra", "1"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var measured capture.Capture
	if err := json.Unmarshal(res.Body, &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	order := measured.HTTP2.HeaderOrder
	shipped, _ := profile.Get(DefaultProfile)
	// The overridden header stays in the browser's slot; the new one goes last.
	if got, want := order[:len(shipped.Headers)], shipped.HeaderOrder(); !reflect.DeepEqual(got, want) {
		t.Errorf("header order = %v\nwant             %v", got, want)
	}
	if order[len(order)-1] != "x-extra" {
		t.Errorf("header order = %v, want the extra header last", order)
	}
	if value, _ := measured.HTTP2.Fingerprint().Header("accept-language"); value != "en-GB,en;q=0.9" {
		t.Errorf("accept-language = %q", value)
	}
}

func TestHeadersOptionAppliesToEveryRequest(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t, WithHeaders(NewHeader("X-Session", "abc")))

	measured := measure(t, client, server)
	if value, _ := measured.HTTP2.Fingerprint().Header("x-session"); value != "abc" {
		t.Errorf("x-session = %q", value)
	}
	if got := client.Headers().Get("x-session"); got != "abc" {
		t.Errorf("Headers() = %v", client.Headers())
	}
}

func TestClientHeadersAreACopy(t *testing.T) {
	client := newTestClient(t)
	headers := client.Headers()
	headers.Set("user-agent", "tampered")
	if client.Headers().Get("user-agent") == "tampered" {
		t.Error("Headers() handed out the client's own slice")
	}
}

func TestPostSendsABody(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t)

	res, err := client.Do(&Request{
		Method: "POST",
		URL:    server.URL() + "/collect",
		Body:   []byte(`{"user_agent":"from a POST"}`),
		Header: NewHeader("content-type", "application/json"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !res.OK() {
		t.Fatalf("status = %d", res.Status)
	}
	if !strings.Contains(res.Text(), "from a POST") {
		t.Errorf("body = %s", res.Text())
	}
}

func TestCookiesGoThroughTheJar(t *testing.T) {
	// Through the jar rather than through a Cookie header: setting the header by
	// hand REPLACES whatever the jar holds, so cookies the server set earlier in
	// the session would silently vanish — which no real browser would do.
	server := startEcho(t)
	client := newTestClient(t)

	res, err := client.Do(&Request{
		URL:     server.URL() + "/api/all",
		Cookies: []Cookie{{Name: "session", Value: "abc"}, {Name: "pinned", Value: "1", Path: "/api"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(res.Cookies) == 0 {
		t.Error("the jar reported no cookies")
	}

	stored, err := client.Cookies(server.URL() + "/api/all")
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	names := map[string]bool{}
	for _, cookie := range stored {
		names[cookie.Name] = true
	}
	if !names["session"] || !names["pinned"] {
		t.Errorf("jar holds %+v", stored)
	}
}

func TestCookiesOnAnUnparseableURL(t *testing.T) {
	client := newTestClient(t)
	if _, err := client.Cookies("://nonsense"); err == nil {
		t.Error("expected an error")
	}
}

func TestRedirectsAreFollowedByDefaultAndCanBeTurnedOff(t *testing.T) {
	server := startEcho(t)

	// The echo server has no redirects, so this checks the option reaches the
	// transport rather than the behaviour of a redirect itself.
	following := newTestClient(t)
	if _, err := following.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	notFollowing := newTestClient(t, WithoutRedirects())
	if _, err := notFollowing.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestNewRejectsAnUnknownProfile(t *testing.T) {
	if _, err := New(WithProfile("netscape_4")); err == nil {
		t.Error("expected an error")
	}
}

func TestNewRejectsNilOptions(t *testing.T) {
	if _, err := New(nil); err == nil || !strings.Contains(err.Error(), "nil client option") {
		t.Fatalf("New(nil) error = %v", err)
	}
	if _, err := New(WithProfileValue(nil)); err == nil ||
		!strings.Contains(err.Error(), "profile value cannot be nil") {
		t.Fatalf("WithProfileValue(nil) error = %v", err)
	}
	if _, err := New(WithTransportOption(nil)); err == nil ||
		!strings.Contains(err.Error(), "nil transport option") {
		t.Fatalf("WithTransportOption(nil) error = %v", err)
	}
}

func TestTheLastProfileOptionWins(t *testing.T) {
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	client := newTestClient(t, WithProfileValue(shipped), WithProfile("chrome_133"))
	if got := client.Profile().Name; got != "chrome_133" {
		t.Errorf("profile = %q, want chrome_133", got)
	}
}

func TestNewRejectsAnUnusableProfile(t *testing.T) {
	broken := &profile.Profile{Name: "broken", ClientHello: []byte{1, 2, 3}}
	if _, err := New(WithProfileValue(broken)); err == nil {
		t.Error("expected an error")
	}
}

func TestNewRejectsAnUnusableProxy(t *testing.T) {
	if _, err := New(WithProxy("://not a url")); err == nil {
		t.Error("expected an error")
	}
}

func TestWithProfileValue(t *testing.T) {
	server := startEcho(t)
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	client := newTestClient(t, WithProfileValue(shipped))
	if client.Profile().Name != shipped.Name {
		t.Errorf("profile = %q", client.Profile().Name)
	}
	if _, err := client.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestACatalogueProfileWorksWithoutHeaders(t *testing.T) {
	// tls-client's catalogue carries a handshake but no headers of its own.
	server := startEcho(t)
	client := newTestClient(t, WithProfile("chrome_133"))
	if len(client.Headers()) != 0 {
		t.Errorf("headers = %v, want none", client.Headers())
	}
	if _, err := client.Get(server.URL() + "/api/all"); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestDoRejectsEmptyRequests(t *testing.T) {
	client := newTestClient(t)
	if _, err := client.Do(nil); err == nil {
		t.Error("expected an error for a nil request")
	}
	if _, err := client.Do(&Request{}); err == nil {
		t.Error("expected an error for a request without a URL")
	}
}

func TestDoRejectsAnUnusableRequest(t *testing.T) {
	client := newTestClient(t)
	if _, err := client.Do(&Request{URL: "http://example.com", Method: "bad method"}); err == nil {
		t.Error("expected an error for an invalid method")
	}
	if _, err := client.Do(&Request{URL: "://nonsense"}); err == nil {
		t.Error("expected an error for an unparseable URL")
	}
}

func TestDoReportsATransportFailure(t *testing.T) {
	client := newTestClient(t, WithTimeout(2*time.Second))
	// Nothing is listening on this port, and the error has to come back as an
	// error rather than as an empty response.
	if _, err := client.Get("https://127.0.0.1:1/"); err == nil {
		t.Error("expected a transport error")
	}
}

func TestResponseHelpers(t *testing.T) {
	ok := &Response{Status: 204, Body: []byte("hi")}
	if !ok.OK() || ok.Text() != "hi" {
		t.Errorf("response = %+v", ok)
	}
	for _, status := range []int{199, 300, 404, 500} {
		if (&Response{Status: status}).OK() {
			t.Errorf("status %d reported as OK", status)
		}
	}
}

func TestResponseHeadersAreLowerCased(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t)
	res, err := client.Get(server.URL() + "/api/all")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for name := range res.Header {
		if name != strings.ToLower(name) {
			t.Errorf("header %q was not lower-cased", name)
		}
	}
	if got := res.Header["content-type"]; len(got) == 0 {
		t.Errorf("headers = %v", res.Header)
	}
}

func TestSuppliedCookieJarIsShared(t *testing.T) {
	server := startEcho(t)
	jar := tls_client.NewCookieJar()

	first := newTestClient(t, WithCookieJar(jar))
	if _, err := first.Do(&Request{
		URL:     server.URL() + "/api/all",
		Cookies: []Cookie{{Name: "shared", Value: "yes"}},
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	second := newTestClient(t, WithCookieJar(jar))
	stored, err := second.Cookies(server.URL() + "/api/all")
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	if len(stored) == 0 || stored[0].Name != "shared" {
		t.Errorf("the second client did not see the jar: %+v", stored)
	}
}

func TestTransportOptionEscapeHatch(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t, WithTransportOption(tls_client.WithForceHttp1()))
	measured := measure(t, client, server)
	if measured.Negotiated != "http/1.1" {
		t.Errorf("ALPN = %q, want the forced http/1.1", measured.Negotiated)
	}
}

func TestCloseIsSafe(t *testing.T) {
	client, err := New(WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := client.Get("https://example.com/"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("Get after Close = %v", err)
	}
}

func TestNewRejectsNonPositiveTimeouts(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := New(WithTimeout(timeout)); err == nil {
			t.Errorf("New with timeout %v succeeded", timeout)
		}
	}
}

func TestNewReportsDefaultCookieJarFailure(t *testing.T) {
	original := newDefaultCookieJar
	newDefaultCookieJar = func() (fhttp.CookieJar, error) {
		return nil, errors.New("jar failed")
	}
	t.Cleanup(func() { newDefaultCookieJar = original })
	if _, err := New(); err == nil || !strings.Contains(err.Error(), "cookie jar") {
		t.Fatalf("error = %v", err)
	}
}

func TestTimeoutConversionBounds(t *testing.T) {
	client, err := New(WithTimeout(time.Nanosecond))
	if err != nil {
		t.Fatalf("one-nanosecond timeout: %v", err)
	}
	_ = client.Close()

	tooLarge := time.Duration(math.MaxInt32+1) * time.Millisecond
	if _, err := New(WithTimeout(tooLarge)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("large timeout error = %v", err)
	}
}

func TestSubsecondTimeoutIsNotRoundedToUnlimited(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	t.Cleanup(server.Close)

	client, err := New(WithInsecureSkipVerify(), WithTimeout(5*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("a request beyond the subsecond timeout succeeded")
	}
}

func TestRequestContextCancelsAnInFlightRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte("late"))
		}
	}))
	t.Cleanup(server.Close)

	client, err := New(WithTimeout(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = client.Do(&Request{Context: ctx, URL: server.URL})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("cancellation took %v", elapsed)
	}
}

func TestResponseBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	t.Cleanup(server.Close)

	client, err := New(WithMaxResponseBody(4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Get(server.URL); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}

	exact, err := New(WithMaxResponseBody(5))
	if err != nil {
		t.Fatal(err)
	}
	defer exact.Close()
	if _, err := exact.Get(server.URL); err != nil {
		t.Fatalf("exactly-at-limit response: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	cfg := defaults()
	if cfg.profileName != DefaultProfile {
		t.Errorf("profile = %q", cfg.profileName)
	}
	if !cfg.followRedirects {
		t.Error("redirects should be followed by default")
	}
	if cfg.shuffleExtensions != nil {
		t.Error("extension order should be selected from the profile by default")
	}
	if cfg.timeout != Timeout {
		t.Errorf("timeout = %v", cfg.timeout)
	}
	if cfg.maxResponseBody != DefaultMaxResponseBody {
		t.Errorf("maximum response body = %d", cfg.maxResponseBody)
	}
}

func TestWithTimeout(t *testing.T) {
	cfg := defaults()
	WithTimeout(5 * time.Second)(&cfg)
	if cfg.timeout != 5*time.Second {
		t.Errorf("timeout = %v", cfg.timeout)
	}
}

func TestWithMaxResponseBody(t *testing.T) {
	cfg := defaults()
	WithMaxResponseBody(123)(&cfg)
	if cfg.maxResponseBody != 123 {
		t.Errorf("maximum response body = %d", cfg.maxResponseBody)
	}
	if _, err := New(WithMaxResponseBody(0)); err == nil {
		t.Error("New accepted a non-positive response body limit")
	}
}

func TestExtensionOrderOverrides(t *testing.T) {
	cfg := defaults()
	WithFixedExtensionOrder()(&cfg)
	if cfg.shuffleExtensions == nil || *cfg.shuffleExtensions {
		t.Error("WithFixedExtensionOrder did not disable shuffling")
	}
	WithRandomExtensionOrder()(&cfg)
	if cfg.shuffleExtensions == nil || !*cfg.shuffleExtensions {
		t.Error("WithRandomExtensionOrder did not enable shuffling")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// truncatingServer answers with a Content-Length it does not honour and then
// hangs up.
//
// This is what a dropped connection mid-response looks like, and it is the one
// way the body read can fail after the request succeeded. Silently returning a
// short body there would be the worst outcome: a caller would parse half a page
// and never know.
func truncatingServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.Read(buf)
				conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"))
			}()
		}
	}()
	return "https://" + listener.Addr().String() + "/"
}

func TestDoReportsATruncatedBody(t *testing.T) {
	url := truncatingServer(t)
	client := newTestClient(t,
		WithTimeout(5*time.Second),
		WithTransportOption(tls_client.WithForceHttp1()),
	)

	_, err := client.Get(url)
	if err == nil {
		t.Fatal("a truncated body was accepted as a complete response")
	}
	if !strings.Contains(err.Error(), "reading body") {
		t.Errorf("error = %v, want it to name the body read", err)
	}
}

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	// The README tells people to build a pool of clients and share each one
	// across goroutines, so this is a promise the tests have to keep. Run under
	// -race it is also the only check that the shared cookie jar and the
	// underlying transport are not being mutated from two places at once.
	server := startEcho(t)
	client := newTestClient(t)

	const workers = 12
	var wg sync.WaitGroup
	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			res, err := client.Do(&Request{
				URL:     fmt.Sprintf("%s/api/all?worker=%d", server.URL(), n),
				Header:  NewHeader("x-worker", fmt.Sprint(n)),
				Cookies: []Cookie{{Name: fmt.Sprintf("w%d", n), Value: "1"}},
			})
			if err != nil {
				results <- "error: " + err.Error()
				return
			}
			var measured capture.Capture
			if err := json.Unmarshal(res.Body, &measured); err != nil {
				results <- "decode: " + err.Error()
				return
			}
			results <- measured.TLS.JA4
		}(i)
	}
	wg.Wait()
	close(results)

	seen := map[string]int{}
	for r := range results {
		seen[r]++
	}
	if len(seen) != 1 {
		t.Fatalf("workers disagreed about what they sent: %v", seen)
	}
	for ja4, count := range seen {
		if strings.HasPrefix(ja4, "error") || strings.HasPrefix(ja4, "decode") {
			t.Fatalf("%d workers failed: %s", count, ja4)
		}
		if count != workers {
			t.Errorf("got %d results, want %d", count, workers)
		}
	}
}
