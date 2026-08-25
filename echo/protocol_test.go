package echo

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// budgetedReader yields a fixed number of bytes and then fails, so a test can
// put the entropy source's failure at each of the points that reads from it.
type budgetedReader struct{ remaining int }

func (r *budgetedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("out of entropy")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = byte(i + 1)
	}
	r.remaining -= n
	return n, nil
}

func TestSelfSignedCertReportsEveryEntropyFailure(t *testing.T) {
	// Certificate generation reads entropy three times — the key, the serial
	// number and the signature — and a failure at any of them has to be reported
	// rather than producing a certificate that is subtly not random.
	//
	// The budget is swept rather than tuned to exact call counts, which would
	// break the moment the standard library changed how much it reads.
	original := randReader
	t.Cleanup(func() { randReader = original })

	seen := map[string]bool{}
	for budget := 0; budget <= 4096; budget += 8 {
		randReader = &budgetedReader{remaining: budget}
		_, err := selfSignedCert([]string{"localhost"})
		if err == nil {
			continue
		}
		for _, stage := range []string{"generate key", "serial", "create certificate"} {
			if strings.Contains(err.Error(), stage) {
				seen[stage] = true
			}
		}
	}

	for _, stage := range []string{"generate key", "serial", "create certificate"} {
		if !seen[stage] {
			t.Errorf("no budget produced a %q failure; that branch is untested", stage)
		}
	}
}

func TestStartReportsACertificateFailure(t *testing.T) {
	original := randReader
	t.Cleanup(func() { randReader = original })
	randReader = &budgetedReader{}

	if _, err := Start(); err == nil {
		t.Error("expected Start to fail when a certificate cannot be generated")
	}
}

func TestSelfSignedCertSubjectAndHosts(t *testing.T) {
	cert, err := selfSignedCert([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the generated certificate: %v", err)
	}
	if got, want := len(leaf.DNSNames), 1; got != want {
		t.Errorf("DNS names = %v, want %d", leaf.DNSNames, want)
	}
	if got, want := len(leaf.IPAddresses), 2; got != want {
		t.Errorf("IP addresses = %v, want %d", leaf.IPAddresses, want)
	}
	if !leaf.IsCA {
		t.Error("the certificate must be self-signed and therefore its own CA")
	}
}

// h2Conn is a raw HTTP/2 client: it writes the frames a test wants to see
// handled, which is the only way to exercise the frames a well-behaved client
// never sends.
type h2Conn struct {
	conn   *tls.Conn
	framer *http2.Framer
	enc    *hpack.Encoder
	buf    *bytes.Buffer
}

func dialH2(t *testing.T, server *Server) *h2Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("preface: %v", err)
	}
	buf := &bytes.Buffer{}
	return &h2Conn{conn: conn, framer: http2.NewFramer(conn, conn), enc: hpack.NewEncoder(buf), buf: buf}
}

func (c *h2Conn) headers(t *testing.T, streamID uint32, endStream bool, fields ...[2]string) {
	t.Helper()
	c.buf.Reset()
	for _, field := range fields {
		if err := c.enc.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
			t.Fatalf("encoding headers: %v", err)
		}
	}
	if err := c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: c.buf.Bytes(), EndHeaders: true, EndStream: endStream,
	}); err != nil {
		t.Fatalf("HEADERS: %v", err)
	}
}

// readUntil reads frames until one satisfies the predicate or the deadline
// passes.
func (c *h2Conn) readUntil(t *testing.T, want func(http2.Frame) bool) http2.Frame {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		frame, err := c.framer.ReadFrame()
		if err != nil {
			t.Fatalf("reading frames: %v", err)
		}
		if want(frame) {
			return frame
		}
	}
}

func TestHTTP2HandlesTheFramesAWellBehavedClientNeverSends(t *testing.T) {
	server := startServer(t)
	c := dialH2(t, server)

	if err := c.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if err := c.framer.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	// A standalone PRIORITY frame. Chrome stopped sending these, so their
	// presence is a signal in itself — and the recorder has to handle them.
	if err := c.framer.WritePriority(3, http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 200}); err != nil {
		t.Fatalf("PRIORITY: %v", err)
	}
	// A per-stream WINDOW_UPDATE, which is not part of the fingerprint and must
	// be ignored rather than recorded as the connection-level one.
	if err := c.framer.WriteWindowUpdate(1, 1000); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if err := c.framer.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("PING: %v", err)
	}
	// DATA for a stream that never sent HEADERS: dropped, not crashed on.
	if err := c.framer.WriteData(99, true, []byte("orphan")); err != nil {
		t.Fatalf("DATA: %v", err)
	}

	ping := c.readUntil(t, func(f http2.Frame) bool {
		p, ok := f.(*http2.PingFrame)
		return ok && p.IsAck()
	}).(*http2.PingFrame)
	if ping.Data[0] != 1 {
		t.Errorf("PING ack echoed %v", ping.Data)
	}

	// A POST arriving as HEADERS then DATA, which is how the capture page
	// reports what JavaScript sees.
	c.headers(t, 1, false,
		[2]string{":method", "POST"}, [2]string{":authority", "localhost"},
		[2]string{":scheme", "https"}, [2]string{":path", "/collect"},
		[2]string{"content-type", "application/json"})
	if err := c.framer.WriteData(1, true, []byte(`{"user_agent":"raw-frames"}`)); err != nil {
		t.Fatalf("DATA: %v", err)
	}

	c.readUntil(t, func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamEnded()
	})

	session := server.Sessions()[len(server.Sessions())-1]
	measured := session.Capture(capture.SourceBrowser)
	if measured.HTTP2 == nil {
		t.Fatal("nothing was recorded")
	}
	if measured.HTTP2.WindowUpdate != 15663105 {
		t.Errorf("window update = %d, want the connection-level one", measured.HTTP2.WindowUpdate)
	}
	if len(measured.HTTP2.Priorities) != 1 {
		t.Errorf("priorities = %v", measured.HTTP2.Priorities)
	}
	if session.Navigator() == nil || session.Navigator().UserAgent != "raw-frames" {
		t.Errorf("navigator = %+v", session.Navigator())
	}
}

func TestHTTP2GoAwayEndsTheConnection(t *testing.T) {
	server := startServer(t)
	c := dialH2(t, server)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if err := c.framer.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("GOAWAY: %v", err)
	}
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := c.framer.ReadFrame(); err != nil {
			return // the server hung up, which is the point
		}
	}
}

func TestHTTP2RecordsOnlyTheFirstRequest(t *testing.T) {
	// The page navigation is the request worth measuring. The capture page then
	// fetches over the SAME connection, and a fetch sends a different accept,
	// different sec-fetch-* and no upgrade-insecure-requests. Recording the last
	// request would hand back an XHR's headers labelled as a navigation's.
	server := startServer(t)
	c := dialH2(t, server)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}

	c.headers(t, 1, true,
		[2]string{":method", "GET"}, [2]string{":authority", "localhost"},
		[2]string{":scheme", "https"}, [2]string{":path", "/"},
		[2]string{"upgrade-insecure-requests", "1"})
	c.readUntil(t, func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamEnded()
	})

	c.headers(t, 3, true,
		[2]string{":method", "GET"}, [2]string{":authority", "localhost"},
		[2]string{":scheme", "https"}, [2]string{":path", "/api/all"},
		[2]string{"sec-fetch-mode", "cors"})
	c.readUntil(t, func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamID == 3 && d.StreamEnded()
	})

	measured := server.Sessions()[len(server.Sessions())-1].Capture(capture.SourceBrowser)
	names := strings.Join(measured.HTTP2.HeaderOrder, ",")
	if !strings.Contains(names, "upgrade-insecure-requests") {
		t.Errorf("header order = %q, want the navigation's", names)
	}
	if strings.Contains(names, "sec-fetch-mode") {
		t.Errorf("header order = %q, want the second request to have been ignored", names)
	}
}

func TestHTTP2RecordsAHeadersFrameWithoutPriority(t *testing.T) {
	// Go's own client sends no priority on HEADERS; Chrome does. Both must
	// record cleanly.
	server := startServer(t)
	c := dialH2(t, server)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	c.headers(t, 1, true,
		[2]string{":method", "GET"}, [2]string{":authority", "localhost"},
		[2]string{":scheme", "https"}, [2]string{":path", "/api/all"})
	c.readUntil(t, func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamEnded()
	})

	measured := server.Sessions()[len(server.Sessions())-1].Capture(capture.SourceBrowser)
	if measured.HTTP2.HeaderPriority != nil {
		t.Errorf("header priority = %+v, want none", measured.HTTP2.HeaderPriority)
	}
}

func TestHTTP2MalformedFrameEndsTheConnection(t *testing.T) {
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("preface: %v", err)
	}
	// A frame header claiming a length no client may send.
	if _, err := conn.Write([]byte{0xff, 0xff, 0xff, 0x00, 0x00, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn)
}

func TestHTTP1WriteFailureIsSurvivable(t *testing.T) {
	// The client asks and then vanishes before the answer is written. The
	// handler must end, not spin.
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("GET /api/all HTTP/1.1\r\nhost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	// The server must still be serving.
	time.Sleep(100 * time.Millisecond)
	if status, _ := get(t, http1Client(), server.URL()+"/api/all"); status != 200 {
		t.Errorf("status = %d", status)
	}
}

func TestHTTP1BodyShorterThanContentLength(t *testing.T) {
	server := startServer(t)
	conn, err := tls.Dial("tcp", server.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(
		"POST /collect HTTP/1.1\r\ncontent-length: 100\r\n\r\n{\"a\":1}")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The server waits for the rest of the body and then sees the connection
	// end; it must not answer as though the body were complete.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	body, _ := io.ReadAll(conn)
	if bytes.Contains(body, []byte("200 OK")) {
		t.Errorf("server answered a truncated body: %s", body)
	}
}

func TestRecordHTTP1KeepsTheFirstRequest(t *testing.T) {
	session := &Session{}
	session.recordHTTP1(&http1Request{HTTP1: capture.HTTP1{Method: "GET", Path: "/first"}})
	session.recordHTTP1(&http1Request{HTTP1: capture.HTTP1{Method: "POST", Path: "/second"}})
	if session.http1.Path != "/first" {
		t.Errorf("recorded %q, want the first request", session.http1.Path)
	}
}

func TestStatusText(t *testing.T) {
	for status, want := range map[string]string{
		"200": "OK", "400": "Bad Request", "404": "Not Found", "500": "Error",
	} {
		if got := statusText(status); got != want {
			t.Errorf("statusText(%s) = %q, want %q", status, got, want)
		}
	}
}

func TestCompleteWakesAWaiter(t *testing.T) {
	server := startServer(t)

	done := make(chan *Session, 1)
	go func() {
		session, err := server.Await(t.Context())
		if err != nil {
			done <- nil
			return
		}
		done <- session
	}()
	// Give Await time to register before the capture completes, which is the
	// ordering the waiter list exists for.
	time.Sleep(100 * time.Millisecond)

	client := http2Client()
	get(t, client, server.URL()+"/")
	res, err := client.Post(server.URL()+"/collect", "application/json",
		strings.NewReader(`{"user_agent":"waiter"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	res.Body.Close()

	select {
	case session := <-done:
		if session == nil || session.Navigator().UserAgent != "waiter" {
			t.Errorf("session = %+v", session)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter was never woken")
	}
}

func TestServerKeepsServingAfterAConnectionDies(t *testing.T) {
	server := startServer(t)
	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if status, _ := get(t, http2Client(), server.URL()+"/api/all"); status != 200 {
		t.Errorf("status = %d", status)
	}
}
