package echo

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The client hangs up while the server is answering.
//
// This is not an exotic case — it is what a closed browser tab looks like from
// here, and it happens at whichever byte the kernel's buffer happened to end on.
// Driving the two protocol handlers over a connection whose writes fail after a
// chosen number of bytes puts the failure at each of the points that writes.

type scriptedConn struct {
	net.Conn
	reader      io.Reader
	writeBudget int
	written     bytes.Buffer
}

func (c *scriptedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.writeBudget < len(p) {
		return 0, errors.New("connection reset by peer")
	}
	c.writeBudget -= len(p)
	return c.written.Write(p)
}

func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) SetDeadline(t time.Time) error    { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// h2Script builds the bytes an HTTP/2 client would send.
func h2Script(t *testing.T, extra func(*http2.Framer, *hpack.Encoder, *bytes.Buffer)) io.Reader {
	t.Helper()
	stream := &bytes.Buffer{}
	stream.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(stream, nil)
	block := &bytes.Buffer{}
	encoder := hpack.NewEncoder(block)
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if extra != nil {
		extra(framer, encoder, block)
	}
	return bytes.NewReader(stream.Bytes())
}

func requestFrame(t *testing.T, framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer,
	path string, priority http2.PriorityParam) {
	t.Helper()
	block.Reset()
	for _, field := range [][2]string{
		{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", path},
	} {
		if err := encoder.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
			t.Fatalf("encoding: %v", err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true, Priority: priority,
	}); err != nil {
		t.Fatalf("HEADERS: %v", err)
	}
}

func TestHTTP2StopsWhenTheClientHangsUpMidWrite(t *testing.T) {
	server := startServer(t)

	// The budget is swept so the write fails at each of the points that write:
	// the server's SETTINGS, the SETTINGS ack, the PING ack, the response
	// headers and each DATA frame of the body.
	script := func(framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer) {
		if err := framer.WritePing(false, [8]byte{1}); err != nil {
			t.Fatalf("PING: %v", err)
		}
		requestFrame(t, framer, encoder, block, "/api/all", http2.PriorityParam{})
	}

	var failed int
	for budget := 0; budget < 40000; budget += 11 {
		conn := &scriptedConn{reader: h2Script(t, script), writeBudget: budget}
		if err := server.serveHTTP2(conn, &Session{}); err != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("no budget produced a write failure; the error paths are untested")
	}
}

func TestHTTP2StopsWhenTheClientHangsUpMidPost(t *testing.T) {
	// The POST path answers from a DATA frame rather than from HEADERS, and it
	// has its own write. This is the shape the capture page's report arrives in,
	// so it is the one that matters most.
	server := startServer(t)
	script := func(framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer) {
		block.Reset()
		for _, field := range [][2]string{
			{":method", "POST"}, {":authority", "localhost"},
			{":scheme", "https"}, {":path", "/collect"},
		} {
			if err := encoder.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
				t.Fatalf("encoding: %v", err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true,
		}); err != nil {
			t.Fatalf("HEADERS: %v", err)
		}
		if err := framer.WriteData(1, true, []byte(`{"user_agent":"post"}`)); err != nil {
			t.Fatalf("DATA: %v", err)
		}
	}

	var failed int
	for budget := 0; budget < 40000; budget += 11 {
		conn := &scriptedConn{reader: h2Script(t, script), writeBudget: budget}
		if err := server.serveHTTP2(conn, &Session{}); err != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("no budget produced a write failure on the POST path")
	}
}

func TestHTTP2ReportsAnUnreadableFrame(t *testing.T) {
	// Not an end of input and not a hang-up: bytes that are not HTTP/2 at all.
	// The connection is unusable, and saying so is better than looping on it.
	server := startServer(t)
	stream := &bytes.Buffer{}
	stream.WriteString(http2.ClientPreface)
	// A WINDOW_UPDATE frame whose payload is three bytes. The frame is complete
	// — it is simply not a legal WINDOW_UPDATE, which must carry exactly four —
	// so this is a protocol error rather than a truncated read.
	stream.Write([]byte{0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})
	stream.Write([]byte{0x00, 0x00, 0x01})

	conn := &scriptedConn{reader: bytes.NewReader(stream.Bytes()), writeBudget: 1 << 20}
	if err := server.serveHTTP2(conn, &Session{}); err == nil {
		t.Error("expected an error for an unreadable frame")
	}
}

func TestWriteResponseReportsAHeaderEncodingFailure(t *testing.T) {
	// hpack encodes into a bytes.Buffer, which cannot fail — so the error is
	// unreachable in production and would go untested with it. Pointing the
	// encoder at a writer that does fail exercises the branch that keeps a
	// half-written header block from being framed as a whole one.
	h := &h2conn{
		framer: http2.NewFramer(&bytes.Buffer{}, nil),
		enc:    hpack.NewEncoder(failingWriter{}),
		encBuf: &bytes.Buffer{},
	}
	if err := h.writeResponse(1, "200", "text/plain", []byte("body")); err == nil {
		t.Error("expected an error when the header block cannot be encoded")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no room") }

func TestHTTP1IgnoresAnIncompleteHeaderBlock(t *testing.T) {
	server := startServer(t)
	session := &Session{}
	conn := &scriptedConn{
		reader:      strings.NewReader("GET /api/all HTTP/1.1\r\nhost: localhost\r\n"),
		writeBudget: 1 << 20,
	}
	// A client that hung up part-way through its headers is an ordinary end of a
	// connection, not a failure to report — but it must not be answered, because
	// the request was never finished.
	if err := server.serveHTTP1(conn, session); err != nil {
		t.Errorf("serveHTTP1 = %v, want a clean end", err)
	}
	if conn.written.Len() != 0 {
		t.Errorf("answered an unfinished request: %q", conn.written.String())
	}
	if session.http1 != nil {
		t.Errorf("recorded an unfinished request: %+v", session.http1)
	}
}

func TestHTTP2RecordsAPriorityCarriedOnHeaders(t *testing.T) {
	// Chrome sends one — exclusive, depending on stream 0, weight 255 on the
	// wire. It is a different thing from a standalone PRIORITY frame and is set
	// by a different knob in every library that lets you set it at all.
	server := startServer(t)
	session := &Session{}
	script := func(framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer) {
		requestFrame(t, framer, encoder, block, "/api/all",
			http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255})
	}
	conn := &scriptedConn{reader: h2Script(t, script), writeBudget: 1 << 20}
	if err := server.serveHTTP2(conn, session); err != nil {
		t.Fatalf("serveHTTP2: %v", err)
	}

	got := session.http2.HeaderPriority
	if got == nil {
		t.Fatal("the HEADERS priority was not recorded")
		return
	}
	if !got.Exclusive || got.Weight != 255 || got.DependsOn != 0 {
		t.Errorf("header priority = %+v", got)
	}
}

func TestHTTP2EndsCleanlyWhenTheClientStopsTalking(t *testing.T) {
	// End of input is a browser closing a tab, not a failure worth reporting.
	server := startServer(t)
	conn := &scriptedConn{reader: h2Script(t, nil), writeBudget: 1 << 20}
	if err := server.serveHTTP2(conn, &Session{}); err != nil {
		t.Errorf("serveHTTP2 = %v, want a clean end", err)
	}
}

func TestHTTP1StopsWhenTheClientHangsUpMidWrite(t *testing.T) {
	server := startServer(t)
	request := "GET /api/all HTTP/1.1\r\nhost: localhost\r\n\r\n"

	var failed int
	for budget := 0; budget < 40000; budget += 11 {
		conn := &scriptedConn{reader: strings.NewReader(request), writeBudget: budget}
		if err := server.serveHTTP1(conn, &Session{}); err != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("no budget produced a write failure; the error paths are untested")
	}
}

func TestHTTP1ReportsAMalformedRequest(t *testing.T) {
	server := startServer(t)
	for _, request := range []string{
		"GARBAGE\r\n\r\n",
		"GET / HTTP/1.1\r\nheader-without-a-colon\r\n\r\n",
		"POST /collect HTTP/1.1\r\ncontent-length: not-a-number\r\n\r\n",
		// A body that stops short of what content-length promised: the request
		// is incomplete, not merely empty, and answering it would mean
		// answering something the client never finished saying.
		"POST /collect HTTP/1.1\r\ncontent-length: 100\r\n\r\nshort",
	} {
		conn := &scriptedConn{reader: strings.NewReader(request), writeBudget: 1 << 20}
		if err := server.serveHTTP1(conn, &Session{}); err == nil {
			t.Errorf("serveHTTP1 accepted %q", request)
		}
	}
}

func TestCaptureHTTP1ReportsAMalformedRequest(t *testing.T) {
	server := startServer(t)
	for _, request := range []string{
		"GET / HTTP/1.1\r\nheader-without-a-colon\r\n\r\n",
		"GET % HTTP/1.1\r\nHost: localhost\r\n\r\n",
	} {
		conn := &scriptedConn{reader: strings.NewReader(request), writeBudget: 1 << 20}
		if err := server.serveCaptureHTTP1(conn, &Session{}); err == nil {
			t.Errorf("serveCaptureHTTP1 accepted %q", request)
		}
	}
}

func TestCaptureHTTP1ReportsEveryWriteFailure(t *testing.T) {
	server := startServer(t)
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"GET /api/all HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"GET /api/all?cache=1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
	} {
		failed := 0
		succeeded := 0
		for budget := 0; budget < 2048; budget++ {
			conn := &scriptedConn{reader: strings.NewReader(request), writeBudget: budget}
			if err := server.serveCaptureHTTP1(conn, &Session{}); err != nil {
				failed++
			} else {
				succeeded++
			}
		}
		if failed == 0 || succeeded == 0 {
			t.Errorf("request %q exercised failed=%d succeeded=%d writes", request, failed, succeeded)
		}
	}

	for _, location := range []string{"", "https://localhost/?navigation=1"} {
		failed := 0
		succeeded := 0
		for budget := 0; budget < 1024; budget++ {
			conn := &scriptedConn{reader: strings.NewReader(""), writeBudget: budget}
			err := writeCaptureHTTP1Response(conn, "200", "text/plain", location, []byte("body"))
			if err != nil {
				failed++
			} else {
				succeeded++
			}
		}
		if failed == 0 || succeeded == 0 {
			t.Errorf("location %q exercised failed=%d succeeded=%d writes", location, failed, succeeded)
		}
	}
}

func TestHTTP1EndsCleanlyAtEndOfInput(t *testing.T) {
	server := startServer(t)
	conn := &scriptedConn{reader: strings.NewReader(""), writeBudget: 1 << 20}
	if err := server.serveHTTP1(conn, &Session{}); err != nil {
		t.Errorf("serveHTTP1 = %v, want a clean end", err)
	}
}

func TestWriteResponseFailsPartWayThroughABody(t *testing.T) {
	// The headers go out, then the connection dies between DATA frames.
	body := make([]byte, maxFrameSize+500)
	for budget := 0; budget < len(body)+2000; budget += 7 {
		conn := &scriptedConn{reader: strings.NewReader(""), writeBudget: budget}
		h := newH2Conn(conn)
		if err := h.writeResponse(1, "200", "text/plain", body); err == nil && budget < len(body) {
			t.Errorf("budget %d wrote a %d-byte body without failing", budget, len(body))
		}
	}
}
