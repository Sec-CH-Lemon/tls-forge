package echo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/v3/capture"
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
	originalGenerateKey := generateKey
	originalRandomInt := randomInt
	originalCreateCertificate := createCertificate
	reset := func() {
		generateKey = originalGenerateKey
		randomInt = originalRandomInt
		createCertificate = originalCreateCertificate
	}
	t.Cleanup(reset)

	testErr := errors.New("crypto failure")
	tests := []struct {
		name string
		want string
		fail func()
	}{
		{"key", "generate key", func() {
			generateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) {
				return nil, testErr
			}
		}},
		{"serial", "serial", func() {
			randomInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, testErr }
		}},
		{"certificate", "create certificate", func() {
			createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
				return nil, testErr
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reset()
			test.fail()
			_, err := selfSignedCert([]string{"localhost"})
			if !errors.Is(err, testErr) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want wrapped %q failure", err, test.want)
			}
		})
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
	// A leaf: no authority, and nothing to sign others with.
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 || !leaf.BasicConstraintsValid {
		t.Errorf("the certificate is a CA %v, with key usage %b", leaf.IsCA, leaf.KeyUsage)
	}
	// Still trusted as itself by whoever trusts it, for each of its names.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("trusted as itself for %s: %v", name, err)
		}
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

// hungUp reads what the server sends until it hangs up, and is the header of
// every frame it sent first. A deadline fails the test: a server that merely
// stopped answering used to pass for one that refused, both being an error
// to a reader that read until any error.
//
// Headers rather than frames, because the framer reuses a frame once the next
// one is read.
func (c *h2Conn) hungUp(t *testing.T) []http2.FrameHeader {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var seen []http2.FrameHeader
	for {
		frame, err := c.framer.ReadFrame()
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatalf("the server kept the connection open after %d frames", len(seen))
			}
			return seen
		}
		seen = append(seen, frame.Header())
	}
}

// refusedStream is hungUp for a request the server must not answer: the
// connection ends, and nothing came back on the stream.
func (c *h2Conn) refusedStream(t *testing.T, stream uint32) {
	t.Helper()
	for _, frame := range c.hungUp(t) {
		if frame.StreamID == stream {
			t.Errorf("the server answered stream %d with %v", stream, frame)
		}
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
	// SETTINGS and the acknowledgement of ours, and then the end.
	for _, frame := range c.hungUp(t) {
		if frame.Type != http2.FrameSettings {
			t.Errorf("the server sent %v after GOAWAY", frame)
		}
	}
}

func TestHTTP2RejectsAnOversizedRequestBody(t *testing.T) {
	server := startServer(t)
	c := dialH2(t, server)
	c.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	c.headers(t, 1, false,
		[2]string{":method", "POST"}, [2]string{":authority", "localhost"},
		[2]string{":scheme", "https"}, [2]string{":path", "/collect"})

	// Four default-sized frames total 65536 bytes, one over the server's
	// request limit, and a fifth after it: answered 413 at the fourth, the
	// client asked to stop, and the fifth goes nowhere.
	chunk := make([]byte, maxFrameSize)
	for i := range maxRequestBody/maxFrameSize + 2 {
		if err := c.framer.WriteData(1, false, chunk); err != nil {
			t.Fatalf("DATA frame %d: %v", i, err)
		}
	}
	headers := c.readUntil(t, func(f http2.Frame) bool { _, ok := f.(*http2.MetaHeadersFrame); return ok })
	if status := headers.(*http2.MetaHeadersFrame).PseudoValue("status"); status != "413" {
		t.Errorf("answered %s", status)
	}
	reset := c.readUntil(t, func(f http2.Frame) bool { _, ok := f.(*http2.RSTStreamFrame); return ok }).(*http2.RSTStreamFrame)
	if reset.StreamID != 1 || reset.ErrCode != http2.ErrCodeNo {
		t.Errorf("RST_STREAM %+v", reset)
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
	// SETTINGS five bytes long, which no settings list can be: they come six
	// at a time. A frame header that only claimed an enormous length was used
	// here, and the server waited for the payload until the test gave up.
	if _, err := conn.Write([]byte{0, 0, 5, byte(http2.FrameSettings), 0, 0, 0, 0, 0, 1, 2, 3, 4, 5}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Told why, and then gone once the client is.
	framer := http2.NewFramer(nil, conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatalf("no GOAWAY: %v", err)
		}
		if away, ok := frame.(*http2.GoAwayFrame); ok {
			if away.ErrCode != http2.ErrCodeFrameSize {
				t.Errorf("GOAWAY %v", away.ErrCode)
			}
			break
		}
	}
	_ = conn.CloseWrite()
	hungUpOn(t, conn)
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
	// The client says it is done sending, seven bytes into the hundred it
	// promised. The server must hang up rather than answer as though the body
	// were complete, and must not wait for the rest until its idle deadline.
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if said := hungUpOn(t, conn); len(said) != 0 {
		t.Errorf("server answered a truncated body: %q", said)
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
		"200": "OK", "302": "Found", "400": "Bad Request", "404": "Not Found", "413": "Content Too Large",
		"414": "URI Too Long", "417": "Expectation Failed", "431": "Request Header Fields Too Large",
		"500": "Internal Server Error", "501": "Not Implemented", "505": "HTTP Version Not Supported",
		"418": "Error",
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
