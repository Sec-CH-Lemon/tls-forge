package echo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/v6/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v6/fingerprint"
)

func startServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	server, err := Start(opts...)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// The certificate is generated per run and signs nothing, so verification is
// off — for this one loopback address, inside this process.
func insecure() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

// The standard transport, restricted to HTTP/2. h2 is the only protocol it
// offers in ALPN, so a test that asks for HTTP/2 fails if the server stops
// speaking it rather than passing over HTTP/1.1.
func http2Transport(config *tls.Config) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Transport{TLSClientConfig: config, Protocols: protocols}
}

func http2Client() *http.Client {
	return &http.Client{Transport: http2Transport(insecure())}
}

func http1Client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
	}}
}

func get(t *testing.T, client *http.Client, url string) (int, []byte) {
	t.Helper()
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return res.StatusCode, body
}

func TestServerReportsTheConnectionBackToIt(t *testing.T) {
	server := startServer(t)

	status, body := get(t, http2Client(), server.URL()+"/api/all")
	if status != 200 {
		t.Fatalf("status = %d", status)
	}

	var measured capture.Capture
	if err := json.Unmarshal(body, &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if measured.Negotiated != "h2" {
		t.Errorf("ALPN = %q, want h2", measured.Negotiated)
	}
	if len(measured.RawClientHello) == 0 {
		t.Fatal("no ClientHello was recorded")
	}
	// The raw bytes are the authority: everything rendered must be derivable
	// from them, so a bug in the rendering cannot make two handshakes look alike.
	hello, err := measured.Hello()
	if err != nil {
		t.Fatalf("re-parsing the recorded hello: %v", err)
	}
	if hello.JA4() != measured.TLS.JA4 {
		t.Errorf("rendered JA4 %s does not match the raw bytes' %s", measured.TLS.JA4, hello.JA4())
	}
	if measured.HTTP2 == nil {
		t.Fatal("no HTTP/2 preamble was recorded")
	}
	if len(measured.HTTP2.Settings) == 0 {
		t.Error("no SETTINGS were recorded")
	}
	if got := measured.HTTP2.PseudoHeaderOrder; len(got) != 4 {
		t.Errorf("pseudo header order = %v", got)
	}
}

func TestSessionResumptionIsOffByDefault(t *testing.T) {
	// Resumption changes the fingerprint being measured — a resumed hello
	// carries pre_shared_key, one more extension, so a different JA4. A capture
	// that silently alternated between the two would produce a profile that
	// matched the browser about half the time.
	server := startServer(t)
	transport := http2Transport(&tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	})
	client := &http.Client{Transport: transport}

	for i := 0; i < 3; i++ {
		transport.CloseIdleConnections()
		if status, _ := get(t, client, server.URL()+"/api/all"); status != 200 {
			t.Fatalf("status = %d", status)
		}
	}

	for _, session := range server.Sessions() {
		measured := session.Capture(capture.SourceTLSFetch)
		if measured.TLS.Resumed {
			t.Error("a connection resumed despite tickets being disabled")
		}
	}
}

func TestSessionTicketsCanBeEnabled(t *testing.T) {
	server := startServer(t, WithSessionTickets(true))
	if server.tlsConfig.SessionTicketsDisabled {
		t.Error("WithSessionTickets(true) did not enable tickets")
	}
}

func TestCapturePageAndCollect(t *testing.T) {
	server := startServer(t)
	client := http2Client()

	status, page := get(t, client, server.URL()+"/")
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	if !bytes.Contains(page, []byte("getHighEntropyValues")) {
		t.Error("the capture page does not collect the high-entropy client hints")
	}

	navigator := `{"user_agent":"Mozilla/5.0 Test","platform":"macOS","languages":["en-GB"]}`
	res, err := client.Post(server.URL()+"/collect", "application/json", strings.NewReader(navigator))
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	defer res.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if session.Navigator() == nil || session.Navigator().UserAgent != "Mozilla/5.0 Test" {
		t.Fatalf("navigator = %+v", session.Navigator())
	}

	// Await must return the DOCUMENT NAVIGATION, whose headers are a
	// navigation's — not the fetch that delivered the report, whose headers are
	// an XHR's.
	measured := session.Capture(capture.SourceBrowser)
	if measured.HTTP2 == nil {
		t.Fatal("no HTTP/2 data on the navigation session")
	}
	for _, name := range measured.HTTP2.HeaderOrder {
		if name == "content-type" || name == "content-length" {
			t.Errorf("the capture recorded the POST's headers, not the navigation's: %v",
				measured.HTTP2.HeaderOrder)
			break
		}
	}
	if session.Remote() == "" {
		t.Error("the session has no remote address")
	}
}

func TestHTTP2ReplenishesTheConnectionWindowAcrossRequestBodies(t *testing.T) {
	server := startServer(t)
	client := http2Client()
	client.Timeout = 2 * time.Second
	body := `{"padding":"` + strings.Repeat("x", 40<<10) + `"}`

	for i := range 2 {
		res, err := client.Post(server.URL()+"/collect", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST %d: %v", i+1, err)
		}
		_, readErr := io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if readErr != nil {
			t.Fatalf("reading POST %d: %v", i+1, readErr)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST %d status = %d", i+1, res.StatusCode)
		}
	}
}

func TestAwaitConsumesACompletedCaptureOnlyOnce(t *testing.T) {
	server := startServer(t)
	client := http2Client()
	get(t, client, server.URL()+"/")
	res, err := client.Post(server.URL()+"/collect", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	res.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := server.Await(ctx); err != nil {
		t.Fatalf("first Await: %v", err)
	}
	// A second measurement must wait for a second capture rather than silently
	// returning the previous browser forever.
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer secondCancel()
	if _, err := server.Await(secondCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Await = %v, want deadline", err)
	}
}

func TestCollectWithoutANavigationFallsBackToTheReporter(t *testing.T) {
	server := startServer(t)
	res, err := http2Client().Post(server.URL()+"/collect", "application/json",
		strings.NewReader(`{"user_agent":"direct"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if session.Navigator().UserAgent != "direct" {
		t.Errorf("navigator = %+v", session.Navigator())
	}
}

func TestCollectRejectsUnreadableJSON(t *testing.T) {
	server := startServer(t)
	res, err := http2Client().Post(server.URL()+"/collect", "application/json",
		strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
	body, _ := io.ReadAll(res.Body)
	if !bytes.Contains(body, []byte("error")) {
		t.Errorf("body = %s, want an error", body)
	}
}

func TestCollectRejectsAnUnknownNavigation(t *testing.T) {
	server := startServer(t)
	res, err := http2Client().Post(server.URL()+"/collect?navigation=missing", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
}

func TestNavigationRejectsAnUnknownHTTP1Capture(t *testing.T) {
	server := startServer(t)
	status, body := get(t, http2Client(), server.URL()+"/?navigation=missing")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
	}
	if !bytes.Contains(body, []byte("unknown HTTP/1.1 navigation")) {
		t.Errorf("body = %s, want the rejected token explained", body)
	}
	status, body = get(t, http1Client(), server.CaptureURL()+"/?navigation=missing")
	if status != http.StatusBadRequest {
		t.Fatalf("HTTP/1.1 status = %d, want %d", status, http.StatusBadRequest)
	}
	if !bytes.Contains(body, []byte("unknown HTTP/1.1 navigation")) {
		t.Errorf("HTTP/1.1 body = %s, want the rejected token explained", body)
	}
}

func TestCloneHTTP1AcceptsNil(t *testing.T) {
	if got := cloneHTTP1(nil); got != nil {
		t.Errorf("cloneHTTP1(nil) = %+v", got)
	}
}

func TestKnownNavigationTokenKeepsTheOriginalSession(t *testing.T) {
	server := startServer(t)
	original := &Session{}
	token, err := server.setNavigation(original, "")
	if err != nil {
		t.Fatalf("initial navigation: %v", err)
	}
	returning := &Session{}
	got, err := server.setNavigation(returning, token)
	if err != nil {
		t.Fatalf("return navigation: %v", err)
	}
	if got != token {
		t.Errorf("token = %q, want %q", got, token)
	}
	if returning.navigation {
		t.Error("the reporting connection replaced the original navigation")
	}
}

func TestUnknownPathIs404(t *testing.T) {
	server := startServer(t)
	status, _ := get(t, http2Client(), server.URL()+"/favicon.ico")
	if status != 404 {
		t.Errorf("status = %d, want 404", status)
	}
}

func TestQueryStringsAreIgnoredWhenRouting(t *testing.T) {
	server := startServer(t)
	status, body := get(t, http2Client(), server.URL()+"/api/all?cache-buster=1")
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	if !bytes.Contains(body, []byte("ja4")) {
		t.Errorf("body = %s", body)
	}
}

func TestHTTP1(t *testing.T) {
	// No browser reaches this path — they all negotiate h2 — but a client that
	// speaks HTTP/1.1 deserves an answer rather than a hang.
	server := startServer(t)
	status, body := get(t, http1Client(), server.URL()+"/api/all")
	if status != 200 {
		t.Fatalf("status = %d", status)
	}

	var measured capture.Capture
	if err := json.Unmarshal(body, &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if measured.Negotiated != "http/1.1" {
		t.Errorf("ALPN = %q", measured.Negotiated)
	}
	if measured.HTTP2 != nil {
		t.Error("an HTTP/1.1 connection reported HTTP/2 data")
	}
	if measured.HTTP1 == nil {
		t.Fatal("no HTTP/1.1 request was recorded")
	}
	if measured.HTTP1.Method != "GET" || measured.HTTP1.Path != "/api/all" {
		t.Errorf("request = %+v", measured.HTTP1)
	}
	// Lower-cased so the order compares directly against the HTTP/2 side.
	for _, name := range measured.HTTP1.HeaderOrder {
		if name != strings.ToLower(name) {
			t.Errorf("header name %q was not lower-cased", name)
		}
	}
	if len(measured.HTTP1.HeaderNames) != len(measured.HTTP1.HeaderOrder) {
		t.Fatalf("wire names = %v, normalised order = %v",
			measured.HTTP1.HeaderNames, measured.HTTP1.HeaderOrder)
	}
	if measured.HTTP1.HeaderNames[0] != "Host" {
		t.Errorf("first wire header = %q, want Host", measured.HTTP1.HeaderNames[0])
	}
}

func TestCaptureURLJoinsHTTP1WithoutChangingTheFirstHTTP2Request(t *testing.T) {
	server := startServer(t)
	transport := &http.Transport{
		TLSClientConfig:   insecure(),
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	res, err := client.Get(server.URL())
	if err != nil {
		t.Fatalf("capture navigation: %v", err)
	}
	page, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("reading page: %v", err)
	}
	if res.ProtoMajor != 2 {
		t.Errorf("main capture page used %s, want HTTP/2", res.Proto)
	}
	initialOrder := []string(nil)
	server.mu.Lock()
	var initial *Session
	if len(server.navigations) == 1 {
		initial = server.navigations[0]
	}
	server.mu.Unlock()
	if initial != nil {
		if captured := initial.Capture(capture.SourceBrowser); captured.HTTP2 != nil {
			initialOrder = append(initialOrder, captured.HTTP2.HeaderOrder...)
		}
	}

	const navigationMarker = "const http1Navigation = '"
	start := strings.Index(string(page), navigationMarker)
	if start < 0 {
		t.Fatalf("capture page has no HTTP/1.1 navigation: %s", page)
	}
	start += len(navigationMarker)
	end := strings.IndexByte(string(page[start:]), '\'')
	if end < 0 {
		t.Fatal("capture page has an unterminated HTTP/1.1 navigation")
	}
	finish, err := client.Get(string(page[start : start+end]))
	if err != nil {
		t.Fatalf("HTTP/1.1 navigation: %v", err)
	}
	page, err = io.ReadAll(finish.Body)
	_ = finish.Body.Close()
	if err != nil {
		t.Fatalf("reading finish page: %v", err)
	}

	const marker = "fetch('"
	start = strings.Index(string(page), marker)
	if start < 0 {
		t.Fatalf("capture page has no collection endpoint: %s", page)
	}
	start += len(marker)
	end = strings.IndexByte(string(page[start:]), '\'')
	if end < 0 {
		t.Fatal("capture page has an unterminated collection endpoint")
	}
	collect := string(page[start : start+end])
	response, err := client.Post(server.URL()+collect, "application/json",
		strings.NewReader(`{"user_agent":"two protocols"}`))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	_ = response.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	measured := session.Capture(capture.SourceBrowser)
	if measured.HTTP1 == nil || measured.HTTP2 == nil {
		t.Fatalf("capture did not join both protocols: %+v", measured)
	}
	if measured.HTTP1.HeaderNames[0] != "Host" {
		t.Errorf("HTTP/1.1 wire names = %v", measured.HTTP1.HeaderNames)
	}
	if got := measured.HTTP2.HeaderOrder; !reflect.DeepEqual(got, initialOrder) {
		t.Errorf("HTTP/2 first request changed after the H1 navigation: %v -> %v", initialOrder, got)
	}
}

func TestCaptureURLAPIReportsWireCasing(t *testing.T) {
	server := startServer(t)
	addr := strings.TrimPrefix(server.CaptureURL(), "https://")
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q, want HTTP/1.1", got)
	}
	if _, err := io.WriteString(conn,
		"GET /api/all HTTP/1.1\r\nHost: localhost\r\nsec-ch-ua: measured\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	var measured capture.Capture
	if err := json.Unmarshal(body, &measured); err != nil {
		t.Fatalf("capture: %v (%s)", err, body)
	}
	if got, want := measured.HTTP1.HeaderNames,
		[]string{"Host", "sec-ch-ua", "Connection"}; !reflect.DeepEqual(got, want) {
		t.Errorf("wire names = %v, want %v", got, want)
	}
}

func TestHTTP1PostAndKeepAlive(t *testing.T) {
	server := startServer(t)
	client := http1Client()

	res, err := client.Post(server.URL()+"/collect", "application/json",
		strings.NewReader(`{"user_agent":"http1"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	res.Body.Close()

	// A second request on the same kept-alive connection must still work, and
	// must not overwrite the first request's record.
	status, _ := get(t, client, server.URL()+"/api/all")
	if status != 200 {
		t.Errorf("status = %d", status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	measured := session.Capture(capture.SourceBrowser)
	if measured.HTTP1.Path != "/collect" {
		t.Errorf("recorded path = %q, want the first request's", measured.HTTP1.Path)
	}
}

// requestLineOf is a request line exactly n bytes long, its CRLF included.
func requestLineOf(n int) string {
	const head, tail = "GET /", " HTTP/1.1\r\n"
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}

// headerOf is header lines of size bytes in all, each well within a line's
// limit, their CRLFs counted.
func headerOf(size int) string {
	line := "X-Long: " + strings.Repeat("a", 6544) + "\r\n"
	lines := strings.Repeat(line, size/len(line))
	return lines + "X-End: " + strings.Repeat("b", size-len(lines)-len("X-End: \r\n")) + "\r\n"
}

// refused is how a request refused with status, for reason, is answered: with
// both, and the connection's end.
func refused(status, reason string) string {
	body := reason + "\n"
	return fmt.Sprintf("HTTP/1.1 %s %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n"+
		"Cache-Control: no-store\r\nConnection: close\r\n\r\n%s", status, statusText(status), len(body), body)
}

func TestHTTP1RefusesWhatItCannotParse(t *testing.T) {
	// Each guard of the parser, by the status and the reason it answers with,
	// as RFC 9112 has a server answer: a test that only saw the connection end
	// could not tell one guard from another. The connection ends after the
	// answer, since what follows a request that could not be read cannot be
	// told from the rest of it.
	server := startServer(t)
	headers := strings.Repeat("X-Test: value\r\n", maxHTTP1Headers+1)
	long := strings.Repeat("X-Long: "+strings.Repeat("a", 7000)+"\r\n", 10)
	for _, tc := range []struct{ name, request, status, reason string }{
		{"request line", "GARBAGE\r\n\r\n", "400", `malformed request line "GARBAGE"`},
		{"two spaces in the request line", "GET  / HTTP/1.1\r\n\r\n", "400", `malformed request line "GET  / HTTP/1.1"`},
		{"a method that is not a token", "G(T / HTTP/1.1\r\n\r\n", "400", `malformed request line "G(T / HTTP/1.1"`},
		{"a control character in the target", "GET /a\x01b HTTP/1.1\r\n\r\n", "400",
			`malformed request line "GET /a\x01b HTTP/1.1"`},
		{"a DEL in the target", "GET /a\x7fb HTTP/1.1\r\n\r\n", "400", `malformed request line "GET /a\x7fb HTTP/1.1"`},
		{"a version in lower case", "GET / http/1.1\r\n\r\n", "400", `malformed request line "GET / http/1.1"`},
		{"a version with more after it", "GET / HTTP/1.1x\r\n\r\n", "400", `malformed request line "GET / HTTP/1.1x"`},
		{"a version without its dot", "GET / HTTP/11\r\n\r\n", "400", `malformed request line "GET / HTTP/11"`},
		{"HTTP/2 over HTTP/1.1", "GET / HTTP/2.0\r\n\r\n", "505", "HTTP/2.0 is not a version of HTTP/1"},
		{"HTTP/0.9", "GET / HTTP/0.9\r\n\r\n", "505", "HTTP/0.9 is not a version of HTTP/1"},
		{"a carriage return in the request line", "GET /\r HTTP/1.1\r\n\r\n", "400",
			`a carriage return inside "GET /\r HTTP/1.1"`},
		{"header without a colon", "GET / HTTP/1.1\r\nno-colon\r\n\r\n", "400", `malformed header "no-colon"`},
		// RFC 9112, section 5.1: a server MUST refuse it. One server reads
		// "Content-Length " as the length and another does not.
		{"a space before the colon", "GET / HTTP/1.1\r\nHost : x\r\n\r\n", "400", `malformed header "Host : x"`},
		{"a tab before the colon", "GET / HTTP/1.1\r\nHost\t: x\r\n\r\n", "400", `malformed header "Host\t: x"`},
		{"a space in a name", "GET / HTTP/1.1\r\nX Y: z\r\n\r\n", "400", `malformed header "X Y: z"`},
		{"no name", "GET / HTTP/1.1\r\n: x\r\n\r\n", "400", `malformed header ": x"`},
		{"a header continued on the next line", "GET / HTTP/1.1\r\nX-A: 1\r\n  more\r\n\r\n", "400",
			`a header continued on another line, "  more"`},
		{"a tab beginning a line", "GET / HTTP/1.1\r\nX-A: 1\r\n\tmore\r\n\r\n", "400",
			`a header continued on another line, "\tmore"`},
		{"a NUL in a value", "GET / HTTP/1.1\r\nX-A: a\x00b\r\n\r\n", "400", "the value of X-A holds a control character"},
		{"a DEL in a value", "GET / HTTP/1.1\r\nX-A: a\x7fb\r\n\r\n", "400", "the value of X-A holds a control character"},
		{"a carriage return in a value", "GET / HTTP/1.1\r\nX-A: a\rb\r\n\r\n", "400", `a carriage return inside "X-A: a\rb"`},
		{"content length that is not a number",
			"POST /collect HTTP/1.1\r\ncontent-length: enormous\r\n\r\n", "400", `unusable content-length "enormous"`},
		{"negative content length", "POST /collect HTTP/1.1\r\ncontent-length: -1\r\n\r\n", "400",
			`unusable content-length "-1"`},
		{"content length with a sign", "POST /collect HTTP/1.1\r\ncontent-length: +5\r\n\r\n12345", "400",
			`unusable content-length "+5"`},
		{"empty content length", "POST /collect HTTP/1.1\r\ncontent-length:\r\n\r\n", "400", `unusable content-length ""`},
		{"two lengths in one", "POST /collect HTTP/1.1\r\ncontent-length: 1, 1\r\n\r\n1", "400",
			`unusable content-length "1, 1"`},
		{"content length one over the limit",
			fmt.Sprintf("POST /collect HTTP/1.1\r\ncontent-length: %d\r\n\r\n", maxRequestBody+1), "413",
			fmt.Sprintf("content-length %d exceeds %d bytes", maxRequestBody+1, maxRequestBody)},
		{"content length past any number",
			"POST /collect HTTP/1.1\r\ncontent-length: 99999999999999999999999\r\n\r\n", "413",
			fmt.Sprintf("content-length 99999999999999999999999 exceeds %d bytes", maxRequestBody)},
		{"duplicate content length",
			"POST /collect HTTP/1.1\r\ncontent-length: 0\r\ncontent-length: 0\r\n\r\n", "400", "duplicate content-length"},
		{"transfer encoding",
			"POST /collect HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "501", "transfer-encoding is not supported"},
		{"transfer encoding in its canonical spelling",
			"POST /collect HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "501", "transfer-encoding is not supported"},
		{"an expectation other than 100-continue",
			"POST /collect HTTP/1.1\r\nExpect: 100-continue, something\r\nContent-Length: 2\r\n\r\n{}", "417",
			`expectation "something" is not supported`},
		{"request line one byte over the limit",
			requestLineOf(maxHTTP1Line+1) + "\r\n", "414", fmt.Sprintf("line exceeds %d bytes", maxHTTP1Line)},
		{"header one byte over the limit",
			"GET / HTTP/1.1\r\nx: " + strings.Repeat("a", maxHTTP1Line-4) + "\r\n\r\n", "431",
			fmt.Sprintf("line exceeds %d bytes", maxHTTP1Line)},
		{"one header too many", "GET / HTTP/1.1\r\n" + headers + "\r\n", "431",
			fmt.Sprintf("request exceeds %d headers", maxHTTP1Headers)},
		{"headers past their bytes", "GET / HTTP/1.1\r\n" + long + "\r\n", "431",
			fmt.Sprintf("request header exceeds %d bytes", maxHTTP1HeaderBytes)},
		{"headers one byte past their bytes", "GET / HTTP/1.1\r\n" + headerOf(maxHTTP1HeaderBytes+1) + "\r\n", "431",
			fmt.Sprintf("request header exceeds %d bytes", maxHTTP1HeaderBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{reader: strings.NewReader(tc.request + "GET / HTTP/1.1\r\n\r\n"), writeBudget: 1 << 20}
			err := server.serveHTTP1(conn, &Session{})
			if err == nil || err.Error() != "echo: "+tc.reason {
				t.Fatalf("serveHTTP1 = %v, want %q", err, tc.reason)
			}
			if got := conn.written.String(); got != refused(tc.status, tc.reason) {
				t.Errorf("answered %q", got)
			}
		})
	}
}

func TestHTTP1DoesNotAnswerARequestItNeverReceived(t *testing.T) {
	// A body that stops short of what content-length promised: the request
	// is incomplete, not merely empty, and answering it would mean answering
	// something the client never finished saying, to a client that has gone.
	server := startServer(t)
	conn := &scriptedConn{reader: strings.NewReader("POST /collect HTTP/1.1\r\ncontent-length: 100\r\n\r\nshort"),
		writeBudget: 1 << 20}
	if err := server.serveHTTP1(conn, &Session{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("serveHTTP1 = %v", err)
	}
	if conn.written.Len() != 0 {
		t.Errorf("answered %q", conn.written.String())
	}
}

func TestHTTP1AcceptsWhatIsJustWithinItsLimits(t *testing.T) {
	// The other side of every limit above: one byte or one header fewer is a
	// request, answered. A limit that is off by one refuses a client that did
	// nothing wrong. And what RFC 9112 lets a server take: empty lines before
	// a request, a bare LF ending a line, bytes past ASCII and tabs in a value.
	server := startServer(t)
	for _, tc := range []struct{ name, request string }{
		{"request line at the limit", requestLineOf(maxHTTP1Line) + "\r\n"},
		{"header at the limit", "GET / HTTP/1.1\r\nx: " + strings.Repeat("a", maxHTTP1Line-5) + "\r\n\r\n"},
		{"as many headers as allowed",
			"GET / HTTP/1.1\r\n" + strings.Repeat("X-Test: value\r\n", maxHTTP1Headers) + "\r\n"},
		{"headers of as many bytes as allowed", "GET / HTTP/1.1\r\n" + headerOf(maxHTTP1HeaderBytes) + "\r\n"},
		{"content length at the limit", fmt.Sprintf("POST /collect HTTP/1.1\r\ncontent-length: %d\r\n\r\n%s",
			maxRequestBody, strings.Repeat("a", maxRequestBody))},
		{"content length with leading zeros", "POST /collect HTTP/1.1\r\ncontent-length: 002\r\n\r\n{}"},
		{"empty body", "POST /collect HTTP/1.1\r\ncontent-length: 0\r\n\r\n"},
		{"empty lines before the request", "\r\n\n\r\nGET / HTTP/1.1\r\n\r\n"},
		{"lines ended by LF alone", "GET / HTTP/1.1\nHost: x\n\n"},
		{"bytes past ASCII and tabs in a value", "GET / HTTP/1.1\r\nX-A: caf\xc3\xa9\tand\xff more\r\n\r\n"},
		{"a later version of HTTP/1", "GET / HTTP/1.2\r\n\r\n"},
		{"an expectation in HTTP/1.0, which knows none", "GET / HTTP/1.0\r\nExpect: something\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{reader: strings.NewReader(tc.request), writeBudget: 1 << 20}
			if err := server.serveHTTP1(conn, &Session{}); err != nil {
				t.Fatalf("serveHTTP1 = %v, want the request answered", err)
			}
			if !strings.HasPrefix(conn.written.String(), "HTTP/1.1 ") {
				t.Errorf("no answer was written: %q", conn.written.String())
			}
		})
	}
}

// hungUpOn reads what the server sends until it hangs up, failing the test if
// it does not within the deadline. Reading until any error at all could not
// tell a server that refused a request from one that stopped answering, since
// a deadline is an error too.
func hungUpOn(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	said, err := io.ReadAll(conn)
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("the server kept the connection open; it had sent %q", said)
	}
	return said
}

func TestHTTP1ClosesAConnectionItCannotParse(t *testing.T) {
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GARBAGE\r\n\r\nGET /api/all HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Answered with why, and nothing after it is read.
	if said := hungUpOn(t, conn); string(said) != refused("400", `malformed request line "GARBAGE"`) {
		t.Errorf("answered %q", said)
	}
}

func TestBadHTTP2Preface(t *testing.T) {
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("this is not the HTTP/2 preface at all\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Not even SETTINGS: the server speaks HTTP/2 only to a client that has.
	if said := hungUpOn(t, conn); len(said) != 0 {
		t.Errorf("answered a connection without a preface: %q", said)
	}

	// The handshake still happened, so the hello was still recorded. A client
	// that fails afterwards has already told us who it is.
	if len(server.Sessions()) == 0 {
		t.Fatal("no session was registered")
	}
}

func TestHTTP2EndsAConnectionWithAFrameLargerThanItReads(t *testing.T) {
	// A header block of 64 KiB in one HEADERS frame, past the 16 KiB a frame
	// may be when SETTINGS says nothing else: the connection ends with
	// FRAME_SIZE_ERROR, and nothing comes back on the stream. The rest of the
	// frame is read and dropped before it closes, or closing on it unread
	// would send a reset that could lose the GOAWAY.
	server := startServer(t)
	c := dialH2(t, server)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	c.buf.Reset()
	for _, field := range [][2]string{{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"},
		{":path", "/"}, {"x-oversized", strings.Repeat("a", maxHTTP2HeaderListSize)}} {
		if err := c.enc.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
			t.Fatalf("encoding: %v", err)
		}
	}
	if err := c.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: c.buf.Bytes(),
		EndHeaders: true, EndStream: true}); err != nil {
		t.Fatalf("HEADERS: %v", err)
	}
	goAway := c.readUntil(t, func(f http2.Frame) bool { _, ok := f.(*http2.GoAwayFrame); return ok }).(*http2.GoAwayFrame)
	if goAway.ErrCode != http2.ErrCodeFrameSize || goAway.LastStreamID != 0 {
		t.Errorf("GOAWAY %+v", goAway)
	}
	_ = c.conn.CloseWrite()
	c.refusedStream(t, 1)
}

func TestHandshakeFailureStillRecordsTheHello(t *testing.T) {
	// A client that rejects our certificate told us who it is on the way in, and
	// that is often the only thing worth knowing about it.
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{ServerName: "localhost"})
	if err == nil {
		conn.Close()
		t.Skip("this machine trusts the generated certificate")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, session := range server.Sessions() {
			if measured := session.Capture(capture.SourceBrowser); len(measured.RawClientHello) > 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a rejected handshake recorded no ClientHello")
}

func TestNonTLSTrafficIsSurvivable(t *testing.T) {
	server := startServer(t)
	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadAll(conn)

	// The server must still be serving.
	if status, _ := get(t, http2Client(), server.URL()+"/api/all"); status != 200 {
		t.Errorf("status = %d after a plaintext connection", status)
	}
}

func TestURLAndAddrAndCertificate(t *testing.T) {
	server := startServer(t, WithHost("localhost"))
	if !strings.HasPrefix(server.URL(), "https://localhost:") {
		t.Errorf("URL = %q", server.URL())
	}
	if !strings.HasPrefix(server.CaptureURL(), "https://localhost:") ||
		server.CaptureURL() == server.URL() {
		t.Errorf("CaptureURL = %q, URL = %q", server.CaptureURL(), server.URL())
	}
	if _, _, err := net.SplitHostPort(server.Addr()); err != nil {
		t.Errorf("Addr = %q: %v", server.Addr(), err)
	}
	if len(server.Certificate()) == 0 {
		t.Error("no certificate was generated")
	}
}

func TestURLBracketsAnIPv6Host(t *testing.T) {
	server := startServer(t, WithHost("::1"))
	if !strings.HasPrefix(server.URL(), "https://[::1]:") {
		t.Errorf("URL = %q", server.URL())
	}
	if !strings.HasPrefix(server.CaptureURL(), "https://[::1]:") {
		t.Errorf("CaptureURL = %q", server.CaptureURL())
	}
}

func TestStartRejectsInvalidOptions(t *testing.T) {
	if _, err := Start(nil); err == nil {
		t.Error("expected a nil option to be rejected")
	}
	if _, err := Start(WithHost("")); err == nil {
		t.Error("expected an empty host to be rejected")
	}
	invalidCertificateHost := func(o *options) { o.hosts = append(o.hosts, "") }
	if _, err := Start(invalidCertificateHost); err == nil {
		t.Error("expected an empty certificate host to be rejected")
	}
}

func TestStartRejectsAnUnusableAddress(t *testing.T) {
	if _, err := Start(WithAddr("256.256.256.256:0")); err == nil {
		t.Error("expected an error for an unusable address")
	}
}

func TestStartReportsASecondListenerFailure(t *testing.T) {
	original := listenCapture
	t.Cleanup(func() { listenCapture = original })
	listenCapture = func(net.Listener) (net.Listener, error) {
		return nil, errors.New("no second port")
	}
	if _, err := Start(); err == nil || !strings.Contains(err.Error(), "HTTP/1.1 capture") {
		t.Errorf("Start error = %v", err)
	}
}

type malformedListenerAddr struct{}

func (malformedListenerAddr) Network() string { return "tcp" }
func (malformedListenerAddr) String() string  { return "missing-port" }

type malformedAddrListener struct{ net.Listener }

func (malformedAddrListener) Addr() net.Addr { return malformedListenerAddr{} }

func TestListenCaptureReportsAMalformedMainAddress(t *testing.T) {
	if _, err := listenCapture(malformedAddrListener{}); err == nil {
		t.Error("a listener address without a port was accepted")
	}
}

func TestCloseIsIdempotentInEffect(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close reports that it was already closed rather than panicking on
	// a closed channel.
	if err := server.Close(); err == nil {
		t.Error("expected the second Close to report that it was already closed")
	}
}

func TestAwaitRespectsItsContext(t *testing.T) {
	server := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := server.Await(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want a deadline", err)
	}
}

func TestAwaitEndsWhenTheServerCloses(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := server.Await(context.Background())
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	server.Close()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "closed") {
			t.Errorf("error = %v, want a closed-server complaint", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Await did not return after the server closed")
	}
}

// writtenTo is a connection that reads nothing and keeps what is written to it.
func writtenTo() *scriptedConn {
	return &scriptedConn{reader: strings.NewReader(""), writeBudget: 1 << 20}
}

// answering is a stream whose request has arrived, with a window of window.
func answering(h *h2conn, id uint32, window int64) *stream {
	st := &stream{id: id, req: &request{stream: id, headers: map[string]string{}}, window: window}
	h.streams[id] = st
	return st
}

func TestAnAnswerLargerThanTheServerBuildsIsRefused(t *testing.T) {
	// None is that large. The guard makes one that ever grows past it fail
	// loudly rather than go out unbounded.
	h := newH2Conn(writtenTo())
	err := h.answer(answering(h, 1, 65535), "200", "text/plain", make([]byte, maxResponseBody+1), false)
	if err == nil || err.Error() != fmt.Sprintf("echo: an answer of %d bytes exceeds the %d this server sends",
		maxResponseBody+1, maxResponseBody) {
		t.Fatalf("error = %v", err)
	}
}

func TestAnAnswerGoesInFramesNoLargerThanTheirSize(t *testing.T) {
	conn := writtenTo()
	out := &conn.written
	h := newH2Conn(conn)
	h.window = 1 << 20
	if err := h.answer(answering(h, 1, 1<<20), "200", "text/plain", make([]byte, maxFrameSize+100), false); err != nil {
		t.Fatalf("answer: %v", err)
	}
	framer := http2.NewFramer(nil, out)
	var sizes []int
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		if data, ok := frame.(*http2.DataFrame); ok {
			sizes = append(sizes, len(data.Data()))
		}
	}
	if len(sizes) != 2 || sizes[0] != maxFrameSize || sizes[1] != 100 {
		t.Errorf("DATA frames of %v bytes", sizes)
	}
	if len(h.streams) != 0 || len(h.sending) != 0 || h.held != 0 {
		t.Errorf("a finished answer is still held: %d, %d, %d", len(h.streams), len(h.sending), h.held)
	}
}

func TestAnAnswerWithAnEmptyBodyEndsWithItsHeaders(t *testing.T) {
	conn := writtenTo()
	out := &conn.written
	h := newH2Conn(conn)
	var answered []*request
	h.answered = func(req *request) { answered = append(answered, req) }
	st := answering(h, 1, 0)
	if err := h.answer(st, "404", "text/plain", nil, false); err != nil {
		t.Fatalf("answer: %v", err)
	}
	frame, err := http2.NewFramer(nil, out).ReadFrame()
	if err != nil || !frame.(*http2.HeadersFrame).StreamEnded() || out.Len() != 0 {
		t.Errorf("wrote %v, %v, and %d bytes more", frame, err, out.Len())
	}
	if len(h.streams) != 0 || len(answered) != 1 || answered[0] != st.req {
		t.Errorf("streams %v, answered %v", h.streams, answered)
	}
}

func TestAnAnswerReportsAFailedWrite(t *testing.T) {
	for _, body := range [][]byte{nil, []byte("hello"), make([]byte, maxFrameSize+1)} {
		h := newH2Conn(&scriptedConn{reader: strings.NewReader("")})
		if err := h.answer(answering(h, 1, 1<<20), "200", "text/plain", body, false); err == nil {
			t.Errorf("an answer of %d bytes did not fail", len(body))
		}
	}
}

func TestReadPreface(t *testing.T) {
	if err := readPreface(strings.NewReader(http2.ClientPreface)); err != nil {
		t.Errorf("readPreface: %v", err)
	}
	if err := readPreface(strings.NewReader("too short")); err == nil {
		t.Error("expected an error for a truncated preface")
	}
	wrong := strings.Repeat("x", len(http2.ClientPreface))
	if err := readPreface(strings.NewReader(wrong)); err == nil {
		t.Error("expected an error for the wrong preface")
	}
}

func TestIsClosed(t *testing.T) {
	if isClosed(nil) {
		t.Error("nil is not a closed connection")
	}
	for _, err := range []error{net.ErrClosed, os.ErrDeadlineExceeded} {
		if !isClosed(err) {
			t.Errorf("%v should read as closed", err)
		}
	}
	for _, message := range []string{
		"read: connection reset by peer", "write: broken pipe", "use of closed network connection",
	} {
		if !isClosed(errors.New(message)) {
			t.Errorf("%q should read as closed", message)
		}
	}
	if isClosed(errors.New("no route to host")) {
		t.Error("an unrelated error should not read as closed")
	}
}

func TestJSONResponseReportsEncodingFailures(t *testing.T) {
	status, _, body := jsonResponse(make(chan int))
	if status != "500" {
		t.Errorf("status = %s, want 500", status)
	}
	if len(body) == 0 {
		t.Error("no error was reported")
	}
}

func TestRecordingConnGivesUpOnGarbage(t *testing.T) {
	// A peer that sends a very large non-hello must not make the recorder buffer
	// without limit.
	recorder := &recordingConn{Conn: nopConn{}}
	chunk := make([]byte, 4096)
	for i := 0; i < (maxRecordedHello/len(chunk))+2; i++ {
		copy(chunk, bytes.Repeat([]byte{0x16}, len(chunk)))
		recorder.Read(chunk)
	}
	if !recorder.done {
		t.Error("the recorder never gave up")
	}
	if recorder.buffered != nil {
		t.Errorf("the recorder held on to %d bytes", len(recorder.buffered))
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Read(p []byte) (int, error) { return len(p), nil }

func TestSessionCaptureBeforeAnythingHappened(t *testing.T) {
	measured := (&Session{}).Capture(capture.SourceBrowser)
	if measured.Source != capture.SourceBrowser {
		t.Errorf("source = %q", measured.Source)
	}
	if len(measured.RawClientHello) != 0 || measured.HTTP2 != nil {
		t.Errorf("an empty session produced data: %+v", measured)
	}
}

func TestSessionSnapshotsDoNotExposeInternalState(t *testing.T) {
	session := &Session{
		navigator: &capture.Navigator{
			UserAgent: "original", Languages: []string{"en"}, Brands: []capture.Brand{{Brand: "Chrome"}},
			FullVersionList: []capture.Brand{{Brand: "Chrome", Version: "151"}},
			FormFactors:     []string{"Desktop"}, Extra: json.RawMessage(`{"source":"browser"}`),
		},
		http1: &capture.HTTP1{
			Method: "GET", HeaderOrder: []string{"accept"}, HeaderNames: []string{"Accept"},
			Headers: []capture.HeaderField{{Name: "accept", Value: "*/*"}},
		},
	}

	measured := session.Capture(capture.SourceBrowser)
	measured.Navigator.UserAgent = "changed"
	measured.Navigator.Languages[0] = "fr"
	measured.Navigator.Brands[0].Brand = "Other"
	measured.Navigator.FullVersionList[0].Version = "0"
	measured.Navigator.FormFactors[0] = "Mobile"
	measured.Navigator.Extra[0] = '['
	measured.HTTP1.HeaderOrder[0] = "changed"
	measured.HTTP1.HeaderNames[0] = "changed"
	measured.HTTP1.Headers[0].Value = "changed"

	navigator := session.Navigator()
	if navigator.UserAgent != "original" || navigator.Languages[0] != "en" ||
		navigator.Brands[0].Brand != "Chrome" || navigator.FullVersionList[0].Version != "151" ||
		navigator.FormFactors[0] != "Desktop" || navigator.Extra[0] != '{' {
		t.Errorf("navigator was mutated through a snapshot: %+v", navigator)
	}
	again := session.Capture(capture.SourceBrowser)
	if again.HTTP1.HeaderOrder[0] != "accept" || again.HTTP1.HeaderNames[0] != "Accept" ||
		again.HTTP1.Headers[0].Value != "*/*" {
		t.Errorf("HTTP/1 data was mutated through a snapshot: %+v", again.HTTP1)
	}
}

func TestRecordersIgnoreEverythingAfterTheFirstRequest(t *testing.T) {
	// The preamble frames belong to the connection, the request to the
	// navigation. Once the request is recorded, later frames on the same
	// connection must not overwrite it.
	session := &Session{}
	session.recordWindowUpdate(100)
	session.http2Recorded = true
	session.recordWindowUpdate(999)
	session.recordSettings(&http2.SettingsFrame{})
	session.recordPriority(&http2.PriorityFrame{})

	if session.http2.WindowUpdate != 100 {
		t.Errorf("window update = %d, want the first one", session.http2.WindowUpdate)
	}
	if len(session.http2.Settings) != 0 || len(session.http2.Priorities) != 0 {
		t.Error("frames after the first request were recorded")
	}
}

func TestPriorityFramesAreRecorded(t *testing.T) {
	session := &Session{}
	session.recordPriority(&http2.PriorityFrame{
		FrameHeader:   http2.FrameHeader{StreamID: 3},
		PriorityParam: http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 200},
	})
	if len(session.http2.Priorities) != 1 {
		t.Fatalf("priorities = %v", session.http2.Priorities)
	}
	got := session.http2.Priorities[0]
	if got != (fingerprint.Priority{StreamID: 3, Exclusive: true, Weight: 200}) {
		t.Errorf("priority = %+v", got)
	}
}

func TestAConnectionPanicDoesNotTakeTheServerWithIt(t *testing.T) {
	// Everything a handler runs decodes bytes a peer chose, before any
	// handshake has completed. That code lives on its own goroutine, so without
	// the recover a single malformed record is a remote kill switch: this was
	// once true of a five-byte TLS record with an empty payload.
	original := handleConn
	t.Cleanup(func() { handleConn = original })
	handleConn = func(*Server, net.Conn) { panic("a parser fell over") }

	server, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Close() }()

	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if panics := server.Panics(); len(panics) == 1 {
			if !strings.Contains(panics[0], "a parser fell over") {
				t.Errorf("recovered %q", panics[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the panic was never recovered, or the server died with it")
}
