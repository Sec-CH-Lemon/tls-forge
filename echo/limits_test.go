package echo

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// limited makes the limits servers start with what change says, for the rest
// of the test.
func limited(t *testing.T, change func(*limits)) {
	t.Helper()
	original := defaultLimits
	t.Cleanup(func() { defaultLimits = original })
	change(&defaultLimits)
}

// endsWithin reads what comes on conn until the server hangs up, which must
// be within the bound and not before least: a server that merely went quiet,
// or waited for its idle timeout, fails.
func endsWithin(t *testing.T, conn net.Conn, least, most time.Duration) []byte {
	t.Helper()
	started := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(most + 5*time.Second))
	said, err := io.ReadAll(conn)
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("the server kept the connection open; it had sent %q", said)
	}
	if elapsed := time.Since(started); elapsed < least || elapsed > most {
		t.Errorf("the connection ended after %s, want between %s and %s", elapsed, least, most)
	}
	return said
}

// trickling writes what it is given as it is given until it is told to
// trickle, and from then on a byte at a time, every pause.
type trickling struct {
	net.Conn
	pause   time.Duration
	trickle atomic.Bool
}

func (c *trickling) Write(p []byte) (int, error) {
	if !c.trickle.Load() {
		return c.Conn.Write(p)
	}
	for i := range p {
		time.Sleep(c.pause)
		if _, err := c.Conn.Write(p[i : i+1]); err != nil {
			return i, err
		}
	}
	return len(p), nil
}

func TestAHandshakeHasItsOwnEnd(t *testing.T) {
	// However quiet the peer is, and however it trickles its hello: each byte
	// inside the idle timeout is not a handshake made.
	limited(t, func(l *limits) { l.handshake, l.idle = 300*time.Millisecond, 5*time.Second })
	server := startServer(t)
	for _, tc := range []struct {
		name  string
		hello bool
	}{{"nothing sent", false}, {"a hello sent a byte at a time", true}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { _ = raw.Close() })
			if tc.hello {
				slow := &trickling{Conn: raw, pause: 20 * time.Millisecond}
				slow.trickle.Store(true)
				go func() { _ = tls.Client(slow, insecure()).Handshake() }()
			}
			endsWithin(t, raw, 250*time.Millisecond, 1500*time.Millisecond)
		})
	}
}

// dialHTTP1 is a TLS connection to the server, over HTTP/1.1, through conn's
// own writer, so that a test can make it trickle.
func dialHTTP1(t *testing.T, server *Server) (*tls.Conn, *trickling) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	slow := &trickling{Conn: raw, pause: 20 * time.Millisecond}
	conn := tls.Client(slow, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return conn, slow
}

func TestAnHTTP1RequestHasItsOwnEnd(t *testing.T) {
	// Its first byte is waited for as long as a connection may idle, and from
	// then it has as long as a request may take, however it trickles: in its
	// header, or in a TLS record that has not arrived whole.
	t.Run("a header a byte at a time", func(t *testing.T) {
		limited(t, func(l *limits) { l.request, l.idle = 300*time.Millisecond, 5*time.Second })
		server := startServer(t)
		conn, _ := dialHTTP1(t, server)
		if _, err := io.WriteString(conn, "GET /api/all HTTP/1.1\r\n"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		go func() {
			for {
				time.Sleep(20 * time.Millisecond)
				if _, err := io.WriteString(conn, "x"); err != nil {
					return
				}
			}
		}()
		if said := endsWithin(t, conn, 250*time.Millisecond, 1500*time.Millisecond); len(said) != 0 {
			t.Errorf("answered %q", said)
		}
	})
	t.Run("a record a byte at a time", func(t *testing.T) {
		limited(t, func(l *limits) { l.idle, l.request = 300*time.Millisecond, 5*time.Second })
		server := startServer(t)
		conn, slow := dialHTTP1(t, server)
		slow.trickle.Store(true)
		go func() {
			_, _ = io.WriteString(conn, "GET /api/all HTTP/1.1\r\nX-Pad: "+strings.Repeat("a", 100)+"\r\n\r\n")
		}()
		if said := endsWithin(t, conn, 250*time.Millisecond, 1500*time.Millisecond); len(said) != 0 {
			t.Errorf("answered %q", said)
		}
	})
	t.Run("on the capture listener", func(t *testing.T) {
		limited(t, func(l *limits) { l.request, l.idle = 300*time.Millisecond, 5*time.Second })
		server := startServer(t)
		conn, err := tls.Dial("tcp", strings.TrimPrefix(server.CaptureURL(), "https://localhost"),
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if _, err := io.WriteString(conn, "GET /api/all HTTP/1.1\r\nHost"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		if said := endsWithin(t, conn, 250*time.Millisecond, 1500*time.Millisecond); len(said) != 0 {
			t.Errorf("answered %q", said)
		}
	})
}

func TestAnHTTP1RequestOnTimeIsAnsweredAfterTheIdleTime(t *testing.T) {
	// The bounds are the request's: one that begins after its connection has
	// waited longer than a request may take is answered, and so is the one
	// after it.
	limited(t, func(l *limits) { l.request, l.idle = 200*time.Millisecond, 5*time.Second })
	server := startServer(t)
	conn, _ := dialHTTP1(t, server)
	for range 2 {
		time.Sleep(300 * time.Millisecond)
		if _, err := io.WriteString(conn, "GET /api/all HTTP/1.1\r\n\r\n"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		buf := make([]byte, len("HTTP/1.1 200 OK"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "HTTP/1.1 200 OK" {
			t.Fatalf("answered %q, %v", buf, err)
		}
		// The rest of the answer, before the next.
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = io.Copy(io.Discard, conn)
	}
}

func TestAnHTTP2FrameHasItsOwnEnd(t *testing.T) {
	// A frame header that promises a payload sent a byte at a time.
	limited(t, func(l *limits) { l.request, l.idle = 300*time.Millisecond, 5*time.Second })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	started := time.Now()
	if _, err := p.conn.Write([]byte{0, 0, 100, byte(http2.FramePing), 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("writing: %v", err)
	}
	go func() {
		for {
			time.Sleep(20 * time.Millisecond)
			if _, err := p.conn.Write([]byte{0}); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-p.ended:
		p.ended <- err
		if elapsed := time.Since(started); err != nil || elapsed < 250*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("ended with %v after %s", err, elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a frame sent a byte at a time kept the connection")
	}
}

func TestAnHTTP2RequestThatDoesNotEndIsReset(t *testing.T) {
	// However busy the client keeps the connection: a request still arriving
	// as long after its stream opened as a request may take is reset, and
	// let go.
	limited(t, func(l *limits) { l.request, l.idle = 300*time.Millisecond, 5*time.Second })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	p.request(1, "POST", "/collect", false)
	p.request(3, "GET", "/api/all", true)
	p.answer(3)
	started := time.Now()
	for time.Since(started) < 200*time.Millisecond {
		p.sync()
		time.Sleep(20 * time.Millisecond)
	}
	if streams, _, _ := p.held(); streams != 1 {
		t.Fatalf("%d streams are open before their time", streams)
	}
	for {
		p.sync()
		if streams, _, held := p.held(); streams == 0 {
			if held != 0 {
				t.Errorf("%d bytes are held", held)
			}
			break
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("the request was never reset")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := p.reset(1); code != http2.ErrCodeCancel {
		t.Errorf("reset with %v", code)
	}
}

func TestAnHTTP2ConnectionWithNothingOpenIsDoneWith(t *testing.T) {
	// PINGs keep a connection's reads busy, not its streams: one with none
	// open for as long as a connection may idle is told it is done with. One
	// with a stream open is not, until the stream ends and then as long again.
	limited(t, func(l *limits) { l.idle, l.request = 400*time.Millisecond, 600*time.Millisecond })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	started := time.Now()
	p.request(1, "POST", "/collect", false)
	busy := func() {
		var data [8]byte
		for {
			time.Sleep(20 * time.Millisecond)
			if err := p.framer.WritePing(false, data); err != nil {
				return
			}
		}
	}
	go busy()
	away := p.next(func(f sent) bool { return f.Type == http2.FrameGoAway })
	if elapsed := time.Since(started); away.code != http2.ErrCodeNo || elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("GOAWAY %v after %s", away.code, elapsed)
	}
	select {
	case err := <-p.ended:
		p.ended <- err
		if err != nil {
			t.Errorf("ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection went on after its GOAWAY")
	}
}

func TestAGoAwayIsFollowedByReadingForAMomentOnly(t *testing.T) {
	// What the client sends after a connection error is read and dropped, so
	// that closing does not reset the GOAWAY away; for as long as linger, and
	// no longer, however the client goes on. The server's linger, not one the
	// package has come to since it started.
	limited(t, func(l *limits) { l.linger = 300 * time.Millisecond })
	server := startServer(t)
	limited(t, func(l *limits) { l.linger = time.Hour })
	p := servedH2(t, server, &Session{}, 4096)
	if err := p.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2,
		BlockFragment: []byte{0x82}, EndHeaders: true}); err != nil {
		t.Fatalf("PUSH_PROMISE: %v", err)
	}
	p.next(func(f sent) bool { return f.Type == http2.FrameGoAway })
	started := time.Now()
	if _, err := p.conn.Write(make([]byte, 1024)); err != nil {
		t.Fatalf("what followed the GOAWAY was not read: %v", err)
	}
	for {
		if _, err := p.conn.Write([]byte{0}); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if elapsed := time.Since(started); elapsed < 250*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("read on for %s", elapsed)
	}
}

func TestConnectionsPastTheLimitWaitForOneToEnd(t *testing.T) {
	// On both listeners together: the next is accepted once one of those
	// served ends, not refused, and the server still closes while it waits.
	limited(t, func(l *limits) { l.connections = 1 })
	server := startServer(t)
	first, err := tls.Dial("tcp", strings.TrimPrefix(server.CaptureURL(), "https://localhost"), insecure())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	second := make(chan error, 1)
	go func() {
		status, err := func() (int, error) {
			res, err := http2Client().Get(server.URL() + "/api/all")
			if err != nil {
				return 0, err
			}
			defer res.Body.Close()
			return res.StatusCode, nil
		}()
		if err == nil && status != 200 {
			err = fmt.Errorf("status %d", status)
		}
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("a second connection was served while the first held the only slot: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("once the first ended, the second: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second connection was never served")
	}

	// Every slot taken again, by a connection that stays: Close returns all
	// the same, since ending that connection frees its slot.
	held, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	closed := make(chan struct{})
	go func() {
		_ = server.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a slot")
	}
}

// exhausted is a listener that runs out of descriptors now and then, as a
// process at its limit does until a connection ends: plan says how many
// accepts fail before each that succeeds, in turn.
type exhausted struct {
	net.Listener
	mu   sync.Mutex
	plan []int
}

func (l *exhausted) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.plan) > 0 && l.plan[0] > 0 {
		l.plan[0]--
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	if len(l.plan) > 0 {
		l.plan = l.plan[1:]
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestRunningOutOfDescriptorsIsWaitedOut(t *testing.T) {
	// Accepting goes on once it passes, rather than ending for good, with every
	// slot it had: one, here. The wait grows while it lasts, 315ms over six
	// failures, and starts afresh the next time.
	limited(t, func(l *limits) { l.connections = 1 })
	server := startServer(t)
	listen := func() net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		return listener
	}
	flaky := &exhausted{Listener: listen(), plan: []int{6, 1}}
	restarted := &Server{listener: flaky, captureListener: listen(), tlsConfig: server.tlsConfig,
		captureTLSConfig: server.captureTLSConfig, host: server.host, limits: server.limits,
		slots: make(chan struct{}, 1), closed: make(chan struct{}), ready: make(chan struct{}),
		conns: map[net.Conn]struct{}{}, navigationByID: map[string]*Session{}, trusted: map[string]bool{}}
	restarted.wg.Add(1)
	go restarted.accept(flaky, false)
	t.Cleanup(func() { _ = restarted.Close() })

	for i := range 2 {
		started := time.Now()
		conn, err := tls.Dial("tcp", flaky.Addr().String(), &tls.Config{InsecureSkipVerify: true,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if _, err := io.WriteString(conn, "GET /api/all HTTP/1.1\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		if said, _ := io.ReadAll(conn); !strings.HasPrefix(string(said), "HTTP/1.1 200 OK") {
			t.Fatalf("connection %d was answered %q", i, said)
		}
		if elapsed := time.Since(started); i == 1 && elapsed > 200*time.Millisecond {
			t.Errorf("the second connection waited %s", elapsed)
		}
		_ = conn.Close()
	}
}

func TestTheServerKeepsTheLatest(t *testing.T) {
	// Of everything it keeps a list of, so that one left running holds what
	// is recent and no more: connections, pages served and their tokens,
	// captures nobody has awaited, visitors trusted, panics.
	limited(t, func(l *limits) { l.kept = 2 })
	server := startServer(t)
	sessions := []*Session{{remote: "192.0.2.1:1"}, {remote: "192.0.2.2:1"}, {remote: "192.0.2.3:1"}}

	for _, sess := range sessions {
		server.register(sess)
	}
	if got := server.Sessions(); len(got) != 2 || got[0] != sessions[1] || got[1] != sessions[2] {
		t.Errorf("sessions kept: %v", got)
	}

	var tokens []string
	for _, sess := range sessions {
		token, err := server.setNavigation(sess, "")
		if err != nil {
			t.Fatalf("setNavigation: %v", err)
		}
		tokens = append(tokens, token)
	}
	if _, err := server.captureSession(tokens[0], &Session{}); err == nil {
		t.Error("the oldest page's token is still known")
	}
	if got, err := server.captureSession(tokens[2], &Session{}); err != nil || got != sessions[2] {
		t.Errorf("the latest page's token gave %v, %v", got, err)
	}
	if len(server.navigations) != 2 || len(server.navigationByID) != 2 {
		t.Errorf("%d pages kept, %d tokens", len(server.navigations), len(server.navigationByID))
	}
	// One filed by a report that came without a page counts the same.
	if _, err := server.captureSession("", &Session{}); err != nil || len(server.navigationByID) != 2 {
		t.Errorf("a report without a page: %v, %d tokens", err, len(server.navigationByID))
	}

	for _, sess := range sessions {
		server.complete(sess)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, want := range sessions[1:] {
		if got, err := server.Await(ctx); err != nil || got != want {
			t.Errorf("Await = %v, %v; want %v", got, err, want)
		}
	}

	manual := startServer(t, WithManual(true))
	visit := func(agent string) bool {
		page := manual.manualVisit(&Session{remote: "192.0.2.9:1"}, &request{headers: map[string]string{
			"user-agent": agent, "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
		}})
		return page != nil && strings.Contains(string(page), "has accepted the certificate")
	}
	for _, agent := range []string{"one", "two", "three"} {
		if !visit(agent) {
			t.Errorf("%s's first visit was not shown what to do", agent)
		}
	}
	if visit("three") || !visit("one") {
		t.Error("the latest visitor was forgotten, or the oldest kept")
	}

	for i := range 3 {
		server.panicked(fmt.Sprint("panic ", i))
	}
	if got := server.Panics(); len(got) != 2 || got[0] != "panic 1" || got[1] != "panic 2" {
		t.Errorf("panics kept: %v", got)
	}
}

func TestHTTP2StopsWhenTheClientHangsUpMidExpiry(t *testing.T) {
	// A request time below zero has every stream expire as soon as it opens:
	// the write of its reset fails at each point it can.
	limited(t, func(l *limits) { l.request = -1 })
	server := startServer(t)
	script := func(framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer) {
		block.Reset()
		for _, field := range [][2]string{
			{":method", "POST"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/collect"},
		} {
			if err := encoder.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
				t.Fatalf("encoding: %v", err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(),
			EndHeaders: true}); err != nil {
			t.Fatalf("HEADERS: %v", err)
		}
	}
	reset := false
	for budget := 0; budget < 200; budget++ {
		conn := &scriptedConn{reader: h2Script(t, script), writeBudget: budget}
		err := server.serveHTTP2(conn, &Session{})
		if err == nil && strings.Contains(conn.written.String(), "\x00\x00\x04\x03") {
			reset = true
		}
	}
	if !reset {
		t.Error("no stream was reset when it expired")
	}
}

func TestTheHandshakesDeadlineEndsWithIt(t *testing.T) {
	// A connection used for longer than its handshake may take is served:
	// what bounded the handshake does not bound what follows it.
	limited(t, func(l *limits) { l.handshake = 300 * time.Millisecond })
	server := startServer(t)
	conn, _ := dialHTTP1(t, server)
	time.Sleep(500 * time.Millisecond)
	if _, err := io.WriteString(conn, "GET /api/all HTTP/1.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if said, _ := io.ReadAll(conn); !strings.HasPrefix(string(said), "HTTP/1.1 200 OK") {
		t.Errorf("answered %q", said)
	}
}

func TestAnHTTP2RequestOnTimeIsAnsweredAfterTheRequestTime(t *testing.T) {
	// The time a frame has is the frame's: one that begins after its
	// connection has waited longer than that is read, and answered.
	limited(t, func(l *limits) { l.request, l.idle = 200*time.Millisecond, 5*time.Second })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	for stream := uint32(1); stream <= 3; stream += 2 {
		time.Sleep(300 * time.Millisecond)
		p.request(stream, "GET", "/api/all", true)
		if headers, _ := p.answer(stream); headers.status() != "200" {
			t.Fatalf("answered %v", headers.fields)
		}
	}
}

func TestAnAnswerWaitingForTheWindowDoesNotExpire(t *testing.T) {
	// The request has arrived: what is late is the client's window, which is
	// the client's to give.
	limited(t, func(l *limits) { l.request, l.idle = 200*time.Millisecond, 5*time.Second })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	p.request(1, "GET", "/api/all", true)
	for started := time.Now(); time.Since(started) < 500*time.Millisecond; {
		p.sync()
		time.Sleep(20 * time.Millisecond)
	}
	if streams, sending, _ := p.held(); streams != 1 || sending != 1 {
		t.Fatalf("%d streams, %d answers after the request time", streams, sending)
	}
	if err := p.framer.WriteWindowUpdate(1, 1<<20); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	if headers, _ := p.answer(1); headers.status() != "200" {
		t.Errorf("answered %v", headers.fields)
	}
}

func TestAnHTTP2ConnectionIsDoneWithAsLongAfterItsLastStream(t *testing.T) {
	// As long as a connection may idle from when its last stream ended, not
	// from when it began.
	limited(t, func(l *limits) { l.idle, l.request = 400*time.Millisecond, 5*time.Second })
	p := servedH2(t, startServer(t), &Session{}, 4096)
	started := time.Now()
	go func() {
		// A whole PING in one write, which the pipe keeps whole: the framer
		// is the test's, and not to be shared.
		ping := []byte{0, 0, 8, byte(http2.FramePing), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		for {
			time.Sleep(20 * time.Millisecond)
			if _, err := p.conn.Write(ping); err != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	p.request(1, "GET", "/api/all", true)
	away := p.next(func(f sent) bool { return f.Type == http2.FrameGoAway })
	if elapsed := time.Since(started); away.code != http2.ErrCodeNo || elapsed < 650*time.Millisecond {
		t.Errorf("GOAWAY %v after %s", away.code, elapsed)
	}
}

func TestAClientThatStopsReadingIsLetGo(t *testing.T) {
	// Answers asked for without end and never read fill what the network
	// holds, and the write that does not fit waits as long as a connection
	// may idle: the server's, not a constant.
	limited(t, func(l *limits) { l.idle = 300 * time.Millisecond })
	server := startServer(t)
	conn, _ := dialHTTP1(t, server)
	go func() {
		for {
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\n\r\n"); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		time.Sleep(50 * time.Millisecond)
		server.mu.Lock()
		open := len(server.conns)
		server.mu.Unlock()
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a client that stopped reading kept its connection")
		}
	}
}
