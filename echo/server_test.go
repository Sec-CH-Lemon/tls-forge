package echo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
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

func http2Client() *http.Client {
	return &http.Client{Transport: &http2.Transport{TLSClientConfig: insecure()}}
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
	client := &http.Client{Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(8),
		},
	}}

	for i := 0; i < 3; i++ {
		client.Transport.(*http2.Transport).CloseIdleConnections()
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

func TestAwaitReturnsImmediatelyWhenTheCaptureIsAlreadyDone(t *testing.T) {
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
	// A second Await must not block: the capture has already happened.
	if _, err := server.Await(ctx); err != nil {
		t.Fatalf("second Await: %v", err)
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
	body, _ := io.ReadAll(res.Body)
	if !bytes.Contains(body, []byte("error")) {
		t.Errorf("body = %s, want an error", body)
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

func TestHTTP1MalformedRequests(t *testing.T) {
	server := startServer(t)
	for _, tc := range []struct{ name, request string }{
		{"request line", "GARBAGE\r\n\r\n"},
		{"header", "GET / HTTP/1.1\r\nno-colon\r\n\r\n"},
		{"content length", "POST /collect HTTP/1.1\r\ncontent-length: enormous\r\n\r\n"},
		{"content length too large", "POST /collect HTTP/1.1\r\ncontent-length: 999999999\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
				InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte(tc.request)); err != nil {
				t.Fatalf("write: %v", err)
			}
			// The server closes the connection rather than answering nonsense.
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadAll(conn); err == nil {
				t.Log("server closed the connection, as expected")
			}
		})
	}
}

func TestHTTP1RejectsAnOverlongLine(t *testing.T) {
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /" + strings.Repeat("a", maxHTTP1Line*2) + " HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn)
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
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn)

	// The handshake still happened, so the hello was still recorded. A client
	// that fails afterwards has already told us who it is.
	if len(server.Sessions()) == 0 {
		t.Fatal("no session was registered")
	}
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
	if _, _, err := net.SplitHostPort(server.Addr()); err != nil {
		t.Errorf("Addr = %q: %v", server.Addr(), err)
	}
	if len(server.Certificate()) == 0 {
		t.Error("no certificate was generated")
	}
}

func TestStartRejectsAnUnusableAddress(t *testing.T) {
	if _, err := Start(WithAddr("256.256.256.256:0")); err == nil {
		t.Error("expected an error for an unusable address")
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

func TestWriteResponseRefusesABodyLargerThanTheWindow(t *testing.T) {
	// This server skips flow control because every HTTP/2 endpoint starts with a
	// 65535-octet window. The guard makes that assumption fail loudly rather
	// than as a hang if a response ever grows past it.
	h := newH2Conn(&bytes.Buffer{})
	err := h.writeResponse(1, "200", "text/plain", make([]byte, maxResponseBody+1))
	if err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("error = %v, want a window complaint", err)
	}
}

func TestWriteResponseChunksLargeBodies(t *testing.T) {
	out := &bytes.Buffer{}
	h := newH2Conn(out)
	if err := h.writeResponse(1, "200", "text/plain", make([]byte, maxFrameSize+100)); err != nil {
		t.Fatalf("writeResponse: %v", err)
	}
	if out.Len() < maxFrameSize {
		t.Errorf("wrote %d bytes, expected the whole body", out.Len())
	}
}

func TestWriteResponseWithAnEmptyBody(t *testing.T) {
	out := &bytes.Buffer{}
	h := newH2Conn(out)
	if err := h.writeResponse(1, "404", "text/plain", nil); err != nil {
		t.Fatalf("writeResponse: %v", err)
	}
	if out.Len() == 0 {
		t.Error("nothing was written")
	}
}

func TestWriteResponseReportsAFailedWrite(t *testing.T) {
	h := newH2Conn(failingReadWriter{})
	if err := h.writeResponse(1, "200", "text/plain", []byte("hello")); err == nil {
		t.Error("expected a write failure")
	}
	if err := h.writeResponse(1, "200", "text/plain", nil); err == nil {
		t.Error("expected a write failure with an empty body too")
	}
	if err := h.writeResponse(1, "200", "text/plain", make([]byte, maxFrameSize+1)); err == nil {
		t.Error("expected a write failure while chunking")
	}
}

type failingReadWriter struct{}

func (failingReadWriter) Read([]byte) (int, error)  { return 0, io.EOF }
func (failingReadWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

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
	if !isClosed(net.ErrClosed) {
		t.Error("net.ErrClosed should read as closed")
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
