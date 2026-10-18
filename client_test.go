package tlsforge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"golang.org/x/net/proxy"

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
	// Through the jar rather than through a Cookie header: a cookie in the jar
	// goes on every request it belongs to and gives way to the value the server
	// sets next, while one in the header goes with one request alone, beside
	// the jar's.
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
	server, requests := hopServer(t)

	res, err := newTestClient(t).Get(server.URL + "/hop")
	if err != nil {
		t.Fatalf("following: %v", err)
	}
	if res.Status != 200 || res.Text() != "landed" || res.URL != server.URL+"/landed" {
		t.Errorf("following: %d %q at %s, want 200 \"landed\" at /landed", res.Status, res.Text(), res.URL)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("following: the server saw %d requests, want the redirect and where it led", got)
	}

	requests.Store(0)
	res, err = newTestClient(t, WithoutRedirects()).Get(server.URL + "/hop")
	if err != nil {
		t.Fatalf("not following: %v", err)
	}
	if res.Status != 302 || res.URL != server.URL+"/hop" {
		t.Errorf("not following: %d at %s, want the 302 itself", res.Status, res.URL)
	}
	if got := res.Header["location"]; len(got) != 1 || got[0] != "/landed" {
		t.Errorf("not following: location = %q, want /landed", got)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("not following: the server saw %d requests, want 1", got)
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

// quotingDialer fails every dial with an error that quotes the proxy, as a
// transport's error may.
type quotingDialer struct{ err error }

func (d quotingDialer) Dial(string, string) (net.Conn, error) { return nil, d.err }
func (d quotingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func TestATransportOptionIsGivenAfterTLSForgesOwn(t *testing.T) {
	// So that one which sets what tls-forge sets replaces it, as GO.md says:
	// here the cookie jar, which then keeps the cookie the site set, and the
	// client's own none of it.
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1"})
	}))
	t.Cleanup(site.Close)
	theirs := tls_client.NewCookieJar()
	client := newTestClient(t, WithTransportOption(tls_client.WithCookieJar(theirs)))
	if _, err := client.Get(site.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	at, _ := neturl.Parse(site.URL)
	if got := theirs.Cookies(at); len(got) != 1 || got[0].Name != "a" {
		t.Errorf("the option's jar holds %v", got)
	}
	if got, err := client.CookiesFor(site.URL); err != nil || len(got) != 0 {
		t.Errorf("the client's own jar holds %v, %v", got, err)
	}
}

func TestAClientProfileGivenAsATransportOptionOrdersThePseudoHeaders(t *testing.T) {
	// The transport orders them as its client profile does, so a client
	// profile given as an option replaces the profile's order with the rest
	// of what it sets; the headers each request carries stay the profile's.
	server := startEcho(t)
	client := newTestClient(t, WithProfile("chrome_155_macos"),
		WithTransportOption(tls_client.WithClientProfile(profiles.Firefox_148)))
	measured := measure(t, client, server)
	if got, want := measured.HTTP2.PseudoHeaderOrder, []string{"m", "p", "a", "s"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pseudo header order = %v, want Firefox's %v", got, want)
	}
	if !strings.Contains(measured.UserAgent(), "Chrome/") {
		t.Errorf("user-agent = %q, want the profile's", measured.UserAgent())
	}

	// fetch() goes out on the transport the option built, Firefox's order,
	// with the priority its browser context gives it, Chrome's for a script,
	// in place of the option's for the transport's other requests. On a
	// connection of its own, the first of which the server keeps.
	client.CloseIdleConnections()
	res, err := client.Do(&Request{URL: server.URL() + "/api/all",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: server.URL() + "/"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var fetched capture.Capture
	if err := json.Unmarshal(res.Body, &fetched); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if p := fetched.HTTP2.HeaderPriority; p == nil || p.Weight != 219 || !p.Exclusive ||
		!reflect.DeepEqual(fetched.HTTP2.PseudoHeaderOrder, []string{"m", "p", "a", "s"}) {
		t.Errorf("fetch() went out with priority %+v and pseudo-headers %v", p, fetched.HTTP2.PseudoHeaderOrder)
	}
}

func TestARequestsErrorSaysNothingOfItsProxysPassword(t *testing.T) {
	// The error is printed by whoever gets it. What it wraps is underneath.
	const through = "alice:s3cr3t@proxy.test:8080"
	refused := fmt.Errorf("dial through %s and http://bob:hunter2@other.test: refused", through)
	client, err := New(WithProxy("http://"+through), WithTransportOption(tls_client.WithProxyDialerFactory(
		func(string, time.Duration, *net.TCPAddr, fhttp.Header, tls_client.Logger) (proxy.ContextDialer, error) {
			return quotingDialer{err: refused}, nil
		})))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_, err = client.Get("https://example.test/")
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "hunter2") ||
		!strings.Contains(err.Error(), "alice@proxy.test:8080") {
		t.Errorf("Get() = %v", err)
	}
	if !errors.Is(err, refused) {
		t.Errorf("%v does not wrap what the dial said", err)
	}
}

func TestAProxyThatCannotBeUsedIsNotQuotedWithItsPassword(t *testing.T) {
	// url.Parse and the transport quote back the whole URL they could not
	// use, and the error is printed by whoever gets it: with a scheme, and
	// without one, which nothing but the URL as given can be told by.
	for proxy, said := range map[string]string{
		// One that will not parse keeps nothing before its last "@".
		"http://alice:s3cr3t@[bad":     `parse "[redacted]@[bad"`,
		"alice:s3cr3t@proxy.test:8080": "`alice@proxy.test:8080`",
	} {
		_, err := New(WithProxy(proxy))
		if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), said) {
			t.Errorf("New(WithProxy(%q)) = %v, want one that says %s", proxy, err, said)
		}
	}
	// What went wrong is underneath, for a program that asks.
	_, err := New(WithProxy("http://alice:s3cr3t@[bad"))
	var parse *neturl.Error
	if !errors.As(err, &parse) || parse.URL != "http://alice:s3cr3t@[bad" {
		t.Errorf("the parse error is not underneath %v", err)
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

func TestClientOwnsAnIndependentProfile(t *testing.T) {
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	wantedName := shipped.Name
	client := newTestClient(t, WithProfileValue(shipped))

	shipped.Name = "changed outside"
	returned := client.Profile()
	returned.Name = "changed through Profile"
	if got := client.Profile().Name; got != wantedName {
		t.Errorf("client profile = %q, want %q", got, wantedName)
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
	if _, err := client.Get("https://" + refused(t) + "/"); err == nil {
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

func TestLastCookieJarOptionWins(t *testing.T) {
	jar := tls_client.NewCookieJar()

	without := newTestClient(t, WithCookieJar(jar), WithoutCookieJar())
	if without.session.jar != nil {
		t.Fatal("WithoutCookieJar did not override the earlier custom jar")
	}

	with := newTestClient(t, WithoutCookieJar(), WithCookieJar(jar))
	if with.session.jar == nil || with.session.jar.inner != jar {
		t.Fatal("WithCookieJar did not override the earlier jarless option")
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

func recordingHTTP1Server(t *testing.T) (string, <-chan []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
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
	t.Cleanup(func() { _ = listener.Close() })
	lines := make(chan []string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		scanner := bufio.NewScanner(conn)
		var request []string
		for scanner.Scan() {
			line := strings.TrimSuffix(scanner.Text(), "\r")
			if line == "" {
				break
			}
			request = append(request, line)
		}
		lines <- request
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	return "https://" + listener.Addr().String() + "/", lines
}

func TestForcedHTTP1UsesBrowserLikeCasingAndHeaderOrder(t *testing.T) {
	url, recorded := recordingHTTP1Server(t)
	client := newTestClient(t, WithTransportOption(tls_client.WithForceHttp1()))
	res, err := client.Do(&Request{URL: url, Header: NewHeader(
		"x-repeat", "one", "x-repeat", "two",
	)})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Fatalf("body = %q", res.Body)
	}

	lines := <-recorded
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "Host: ") {
		t.Fatalf("Host was not the first header: %v", lines)
	}
	var userAgent bool
	var repeats []string
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "User-Agent: ") {
			userAgent = true
		}
		if strings.HasPrefix(line, "user-agent: ") {
			t.Errorf("User-Agent was sent in lower case: %q", line)
		}
		if strings.HasPrefix(line, "X-Repeat: ") {
			repeats = append(repeats, line)
		}
	}
	if !userAgent {
		t.Errorf("no canonically cased User-Agent in %v", lines)
	}
	if got, want := repeats, []string{"X-Repeat: one", "X-Repeat: two"}; !reflect.DeepEqual(got, want) {
		t.Errorf("repeated headers = %v, want %v", got, want)
	}
}

func profileWithMeasuredHTTP1(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	p.HTTP1 = &profile.HTTP1{
		HeaderOrder: []string{"Host", "sec-ch-ua", "User-Agent", "Connection"},
		Headers:     []profile.Field{{Name: "Connection", Value: "keep-alive"}},
	}
	return p
}

func TestMeasuredHTTP1UsesCapturedCasingAndProtocolOnlyHeaders(t *testing.T) {
	url, recorded := recordingHTTP1Server(t)
	client := newTestClient(t,
		WithProfileValue(profileWithMeasuredHTTP1(t)),
		WithTransportOption(tls_client.WithForceHttp1()),
	)
	if _, err := client.Get(url); err != nil {
		t.Fatalf("Get: %v", err)
	}

	lines := <-recorded
	if len(lines) < 5 {
		t.Fatalf("request is incomplete: %v", lines)
	}
	if !strings.HasPrefix(lines[1], "Host: ") ||
		!strings.HasPrefix(lines[2], "sec-ch-ua: ") ||
		!strings.HasPrefix(lines[3], "User-Agent: ") ||
		lines[4] != "Connection: keep-alive" {
		t.Errorf("measured HTTP/1.1 layout was not used: %v", lines)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "Sec-Ch-Ua: ") {
			t.Errorf("client hints were canonicalised instead of measured: %q", line)
		}
		if strings.HasPrefix(strings.ToLower(line), "priority: ") {
			t.Errorf("HTTP/2-only Priority leaked into HTTP/1.1: %q", line)
		}
	}
}

func TestMeasuredHTTP1DoesNotChangeHTTP2(t *testing.T) {
	server := startEcho(t)
	p := profileWithMeasuredHTTP1(t)
	client := newTestClient(t, WithProfileValue(p))
	measured := measure(t, client, server)
	if got, want := measured.HTTP2.HeaderOrder, p.HeaderOrder(); !reflect.DeepEqual(got, want) {
		t.Errorf("HTTP/2 order = %v, want %v", got, want)
	}
	if got, want := measured.HTTP2.Akamai,
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"; got != want {
		t.Errorf("HTTP/2 Akamai = %q, want %q", got, want)
	}
	for _, header := range measured.HTTP2.Headers {
		if header.Name == "connection" {
			t.Error("HTTP/1.1-only Connection leaked into HTTP/2")
		}
	}
}

func TestProtocolLayoutEdgeCases(t *testing.T) {
	layout := measuredHTTP1Layout(Header{
		{Name: "host", Value: "first.test"},
		{Name: "Host", Value: "last.test"},
		{Name: "x-extra", Value: "one"},
	}, &profile.HTTP1{HeaderOrder: []string{"Host", "Missing"}}, "derived.test")
	if got := layout.Get("Host"); got != "last.test" {
		t.Errorf("Host = %q, want the final caller override", got)
	}
	if _, ok := layout["Missing"]; ok {
		t.Error("a measured header with no request value was invented")
	}
	if got := layout.Get("X-Extra"); got != "one" {
		t.Errorf("caller-only header = %q", got)
	}

	redirected := redirectHTTP1Layout(
		fhttp.Header{
			"Host":               {"source.test"},
			"sec-ch-ua":          {"h1"},
			"Connection":         {"keep-alive"},
			"Authorization":      {"secret"},
			fhttp.HeaderOrderKey: {"host", "sec-ch-ua", "connection", "authorization"},
		},
		fhttp.Header{
			"Host":                {"source.test"},
			"Sec-Ch-Ua":           {"h2"},
			"Authorization":       {"secret"},
			"X-Changed":           {"old"},
			"Priority":            {"u=0"},
			fhttp.HeaderOrderKey:  {"host", "sec-ch-ua", "authorization", "x-changed", "priority"},
			fhttp.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
		},
		fhttp.Header{
			"Host":                {"source.test"},
			"Sec-Ch-Ua":           {"h2"},
			"X-Changed":           {"new"},
			"Priority":            {"u=0"},
			"Referer":             {"https://source.test/"},
			fhttp.HeaderOrderKey:  {"host", "sec-ch-ua", "x-changed", "priority"},
			fhttp.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
		},
		"target.test",
	)
	if got := redirected["Host"]; !reflect.DeepEqual(got, []string{"target.test"}) {
		t.Errorf("redirect Host = %v", got)
	}
	if _, ok := redirected["Authorization"]; ok {
		t.Error("redirect restored stripped Authorization")
	}
	if got := redirected["sec-ch-ua"]; !reflect.DeepEqual(got, []string{"h1"}) {
		t.Errorf("unchanged shared header lost its HTTP/1 value: %v", got)
	}
	if got := redirected["Connection"]; !reflect.DeepEqual(got, []string{"keep-alive"}) {
		t.Errorf("HTTP/1-only header was lost: %v", got)
	}
	if got := redirected["X-Changed"]; !reflect.DeepEqual(got, []string{"new"}) {
		t.Errorf("changed redirect header = %v", got)
	}
	if got := redirected["Referer"]; !reflect.DeepEqual(got, []string{"https://source.test/"}) {
		t.Errorf("redirect-only header = %v", got)
	}
	if _, ok := redirected["Priority"]; ok {
		t.Error("an unchanged HTTP/2-only header leaked into HTTP/1")
	}
	wantOrder := []string{"host", "sec-ch-ua", "connection", "x-changed", "referer"}
	if got := redirected[fhttp.HeaderOrderKey]; !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("redirect order = %v, want %v", got, wantOrder)
	}

	req, err := fhttp.NewRequest("GET", "https://example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if layoutsOn(req) != nil {
		t.Fatal("a request nothing was hung on carries layouts")
	}
	customHost := newLayouts(fhttp.Header{}, fhttp.Header{
		"Host":               {"old.test"},
		fhttp.HeaderOrderKey: {"host"},
	})
	req.Host = "virtual.test"
	if got := customHost.redirected(req).http1["Host"]; !reflect.DeepEqual(got, []string{"virtual.test"}) {
		t.Errorf("relative redirect custom Host = %v", got)
	}
}

func TestARequestIsWrittenOverHTTP1WithItsHTTP1Block(t *testing.T) {
	// The transport asks for the header to write once it knows the protocol:
	// over HTTP/2 the block worn, over HTTP/1.1 the other, laid over what the
	// client added, as the jar's Cookie.
	l := newLayouts(
		fhttp.Header{"Accept": {"*/*"}, "Priority": {"u=0, i"}, "User-Agent": {"ua"},
			fhttp.HeaderOrderKey: {"accept", "user-agent", "priority"}},
		fhttp.Header{"Host": {"example.test"}, "Connection": {"keep-alive"}, "Accept": {"*/*"}, "User-Agent": {"ua"},
			fhttp.HeaderOrderKey: {"host", "connection", "accept", "user-agent"}})
	req, err := fhttp.NewRequest("GET", "https://example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	worn := l.wear(req)
	worn.Header["Cookie"] = []string{"a=1"}
	if written := worn.WrittenHeader(fhttp.ProtocolHTTP2); written["Priority"] == nil || written["Cookie"] == nil ||
		written["Connection"] != nil {
		t.Errorf("over HTTP/2: %v", written)
	}
	want := fhttp.Header{"Host": {"example.test"}, "Connection": {"keep-alive"}, "Accept": {"*/*"}, "User-Agent": {"ua"},
		"Cookie": {"a=1"}, fhttp.HeaderOrderKey: {"host", "connection", "accept", "user-agent"}}
	if written := worn.WrittenHeader(fhttp.ProtocolHTTP1); !reflect.DeepEqual(written, want) {
		t.Errorf("over HTTP/1.1: %v, want %v", written, want)
	}
	// What it wears stays as it was, and so do the layouts it was made from.
	if worn.Header["Connection"] != nil || worn.Header["Priority"] == nil || l.http2["Cookie"] != nil ||
		layoutsOn(worn) != l {
		t.Errorf("wears %v, made from %v", worn.Header, l.http2)
	}

	// One the same over both is written with its one block over each.
	other, err := fhttp.NewRequest("GET", "https://example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if same := newLayouts(fhttp.Header{"Accept": {"*/*"}}, nil).wear(other); same.HeaderFor != nil ||
		layoutsOn(same) != nil || same.Header.Get("Accept") != "*/*" {
		t.Errorf("the same over both: %v", same.Header)
	}
}

func TestRedirectChoosesTheLayoutOfTheNextConnection(t *testing.T) {
	target, recorded := recordingHTTP1Server(t)
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	}))
	redirect.EnableHTTP2 = true
	redirect.StartTLS()
	t.Cleanup(redirect.Close)

	client := newTestClient(t, WithProfileValue(profileWithMeasuredHTTP1(t)))
	// A different hostname makes this a different origin even before the ports
	// are considered. fhttp strips explicit credentials on that boundary.
	source := strings.Replace(redirect.URL, "127.0.0.1", "localhost", 1)
	if _, err := client.Do(&Request{URL: source, Header: NewHeader(
		"Authorization", "Bearer review-secret",
		"Cookie", "manual=secret",
	)}); err != nil {
		t.Fatalf("redirect: %v", err)
	}
	lines := <-recorded
	if len(lines) < 3 || !strings.HasPrefix(lines[2], "sec-ch-ua: ") {
		t.Errorf("redirected HTTP/1.1 request used the wrong layout: %v", lines)
	}
	parsedTarget, err := neturl.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	if got, want := lines[1], "Host: "+parsedTarget.Host; got != want {
		t.Errorf("redirect Host = %q, want %q", got, want)
	}
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "cookie:") {
			t.Errorf("cross-origin redirect leaked a credential: %q", line)
		}
	}
}

func TestARedirectOfARequestTheSameOverBothSendsItWhole(t *testing.T) {
	// A profile that measured no HTTP/1.1 sends one block over both
	// protocols, and so does its redirect to an HTTP/1.1 server: there is no
	// other block to make the hop's from.
	target, recorded := recordingHTTP1Server(t)
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	}))
	redirect.EnableHTTP2 = true
	redirect.StartTLS()
	t.Cleanup(redirect.Close)

	p := profileWithMeasuredHTTP1(t)
	p.HTTP1 = nil
	client := newTestClient(t, WithProfileValue(p))
	if _, err := client.Get(redirect.URL); err != nil {
		t.Fatalf("redirect: %v", err)
	}
	lines := <-recorded
	sent := map[string]bool{}
	for _, line := range lines[1:] {
		if name, _, ok := strings.Cut(line, ":"); ok {
			sent[strings.ToLower(name)] = true
		}
	}
	for _, field := range p.Headers {
		if !sent[strings.ToLower(field.Name)] {
			t.Errorf("the redirect over HTTP/1.1 went without %s: %v", field.Name, lines)
		}
	}
}

// hopServer redirects /hop to /landed, and /loop to itself for ever.
func hopServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/hop":
			http.Redirect(w, r, "/landed", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = w.Write([]byte("landed"))
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &requests
}

// chainServer answers /chain/N with a redirect to /chain/N-1 and /chain/0
// with a page, and says how many requests it was asked and how many of them
// reached the page.
func chainServer(t *testing.T) (*httptest.Server, func() (requests, ends int32)) {
	t.Helper()
	var requests, ends atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/chain/"))
		if n == 0 {
			ends.Add(1)
			_, _ = w.Write([]byte("landed"))
			return
		}
		http.Redirect(w, r, "/chain/"+strconv.Itoa(n-1), http.StatusFound)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, func() (int32, int32) { return requests.Load(), ends.Load() }
}

func TestAChainOfRedirectsEndsAtItsTwentiethRequest(t *testing.T) {
	// As Chrome 155 was measured to: 19 redirects are followed to the answer,
	// 20 requests in all; the 20th redirect is not followed, and nothing past
	// it is asked. The default profile carries an HTTP/1.1 layout and the
	// catalogue one does not, which once decided whether a chain ever ended.
	for _, name := range []string{DefaultProfile, "chrome_133"} {
		for _, tc := range []struct {
			redirects      int
			requests, ends int32
		}{
			{0, 1, 1}, {1, 2, 1}, {19, 20, 1}, {20, 20, 0}, {21, 20, 0}, {100, 20, 0},
		} {
			t.Run(fmt.Sprintf("%s/%d", name, tc.redirects), func(t *testing.T) {
				server, count := chainServer(t)
				client := newTestClient(t, WithProfile(name), WithTimeout(10*time.Second))
				res, err := client.Get(fmt.Sprintf("%s/chain/%d", server.URL, tc.redirects))
				switch {
				case tc.ends == 0 && (err == nil || !strings.Contains(err.Error(), "the 20th redirect was not followed")):
					t.Errorf("error = %v, want the redirect limit", err)
				case tc.ends == 1 && (err != nil || string(res.Body) != "landed"):
					t.Errorf("Get = %v, %v", res, err)
				}
				if requests, ends := count(); requests != tc.requests || ends != tc.ends {
					t.Errorf("the server was asked %d times, the page %d; want %d and %d", requests, ends,
						tc.requests, tc.ends)
				}
			})
		}
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

// TestACallerSuppliedHostReplacesTheOneFromTheURL pins a boundary the header
// block's Host seeding opened.
//
// Host is written before the merged headers are walked, so a caller who sets
// one appended a second value rather than replacing it — and a request with two
// Host lines is one RFC 7230 requires a server to answer with 400, as well as a
// request smuggling primitive when a proxy and an origin choose different ones.
func TestACallerSuppliedHostReplacesTheOneFromTheURL(t *testing.T) {
	url, recorded := recordingHTTP1Server(t)
	client := newTestClient(t, WithTransportOption(tls_client.WithForceHttp1()))
	if _, err := client.Do(&Request{
		URL:    url,
		Header: NewHeader("host", "chosen.example"),
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	var hosts []string
	for _, line := range (<-recorded)[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			hosts = append(hosts, line)
		}
	}
	if got, want := hosts, []string{"Host: chosen.example"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Host lines = %v, want %v", got, want)
	}
}

// TestHostComesFromTheURLWhenTheCallerSetsNone is the other half: the seeded
// Host still leads the block.
func TestHostComesFromTheURLWhenTheCallerSetsNone(t *testing.T) {
	target, recorded := recordingHTTP1Server(t)
	client := newTestClient(t, WithTransportOption(tls_client.WithForceHttp1()))
	if _, err := client.Get(target); err != nil {
		t.Fatalf("Get: %v", err)
	}

	lines := <-recorded
	parsed, err := neturl.Parse(target)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := lines[1], "Host: "+parsed.Host; got != want {
		t.Errorf("first header = %q, want %q", got, want)
	}
	var hosts int
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			hosts++
		}
	}
	if hosts != 1 {
		t.Errorf("%d Host headers, want 1", hosts)
	}
}
