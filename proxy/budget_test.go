package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v3"
)

// budgeted makes the budget servers start with what change says for the rest
// of the test.
func budgeted(t *testing.T, change func(*budget)) {
	t.Helper()
	original := defaultBudget
	t.Cleanup(func() { defaultBudget = original })
	change(&defaultBudget)
}

// counting is a client that answers every request with a page, and counts
// them.
type counting struct{ asked atomic.Int32 }

func (c *counting) Do(*tlsforge.Request) (*tlsforge.Response, error) {
	c.asked.Add(1)
	return &tlsforge.Response{Status: 200, Header: map[string][]string{}, Body: []byte("page")}, nil
}

func (c *counting) Headers() tlsforge.Header { return tlsforge.NewHeader("user-agent", "Chrome") }

// requestOf is a request through the proxy whose header, from its request line
// to the empty line that ends it, is exactly size bytes long, followed by body.
func requestOf(t *testing.T, size int, body string) string {
	t.Helper()
	head := fmt.Sprintf("POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\nX-Pad: ", len(body))
	pad := size - len(head) - len("\r\n\r\n")
	if pad < 0 {
		t.Fatalf("a header of %d bytes cannot hold the request line", size)
	}
	return head + strings.Repeat("a", pad) + "\r\n\r\n" + body
}

// endsWithin reads what comes on conn until the proxy hangs up, which must be
// within the bound and not before least: a server that merely went quiet, or
// waited for its idle timeout, fails.
func endsWithin(t *testing.T, conn net.Conn, least, most time.Duration) []byte {
	t.Helper()
	started := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(most + 5*time.Second))
	said, err := io.ReadAll(conn)
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("the proxy kept the connection open; it had sent %q", said)
	}
	if elapsed := time.Since(started); elapsed < least || elapsed > most {
		t.Errorf("the connection ended after %s, want between %s and %s", elapsed, least, most)
	}
	return said
}

func TestAHeaderPastItsBudgetIsAnswered431(t *testing.T) {
	// Plainly and in a tunnel. Refused at the budget and at most one buffer
	// past it, never later: the bytes the reader holds already are not
	// counted, which is the most that can be read before the header has
	// visibly run long.
	budgeted(t, func(b *budget) { b.headerBytes = 8192 })
	over := requestOf(t, 8192+4096+1, "")
	check := func(t *testing.T, client *counting, problems *errorLog, conn net.Conn) {
		t.Helper()
		said := string(endsWithin(t, conn, 0, 5*time.Second))
		if !strings.HasPrefix(said, "HTTP/1.1 431 Request Header Fields Too Large\r\n") ||
			!strings.HasSuffix(said, "\r\n\r\nrequest header exceeds 8192 bytes\n") {
			t.Errorf("answered %q", said)
		}
		if client.asked.Load() != 0 {
			t.Error("the request went on")
		}
		if got := problems.list(); len(got) != 0 {
			t.Errorf("reported %v", got)
		}
	}

	t.Run("plainly", func(t *testing.T) {
		client := &counting{}
		server, problems := startProxy(t, client, newCAForTest(t))
		_, conn := through(t, server, over)
		check(t, client, problems, conn)
	})
	t.Run("in a tunnel", func(t *testing.T) {
		client := &counting{}
		ca := newCAForTest(t)
		server, problems := startProxy(t, client, ca)
		tunnel := openedTunnel(t, server, ca, "example.test:443", 0)
		if _, err := io.WriteString(tunnel, strings.Replace(over, "http://example.test/", "/", 1)); err != nil {
			t.Fatalf("writing: %v", err)
		}
		check(t, client, problems, tunnel)
	})
}

func TestAHeaderWithinItsBudgetIsServedAndItsBodyIsNotCounted(t *testing.T) {
	// A header of the budget exactly, its body four times as long, and a
	// second header of the budget after it on the same connection: the budget
	// is the header's, each header's own.
	budgeted(t, func(b *budget) { b.headerBytes = 8192 })
	client := &counting{}
	server, problems := startProxy(t, client, newCAForTest(t))
	request := requestOf(t, 8192, strings.Repeat("b", 4*8192))
	r, _ := through(t, server, request+request)
	for i := range 2 {
		res, err := http.ReadResponse(r, nil)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("answer %d: %v, %v", i, res, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
	}
	if client.asked.Load() != 2 {
		t.Errorf("%d requests went on, want 2", client.asked.Load())
	}
	if got := problems.list(); len(got) != 0 {
		t.Errorf("reported %v", got)
	}
}

func TestAHeaderSentAByteAtATimeIsCutOffAtItsTime(t *testing.T) {
	// Each byte inside the idle timeout, the whole never inside the header's.
	budgeted(t, func(b *budget) { b.header, b.idle = 300*time.Millisecond, 5*time.Second })
	client := &counting{}
	server, problems := startProxy(t, client, newCAForTest(t))
	_, conn := through(t, server, "GET http://example.test/ HTTP/1.1\r\n")
	go func() {
		for {
			time.Sleep(20 * time.Millisecond)
			if _, err := io.WriteString(conn, "x"); err != nil {
				return
			}
		}
	}()
	if said := endsWithin(t, conn, 250*time.Millisecond, 2*time.Second); len(said) != 0 {
		t.Errorf("answered %q", said)
	}
	if client.asked.Load() != 0 || len(problems.list()) != 0 {
		t.Errorf("asked %d, reported %v", client.asked.Load(), problems.list())
	}
}

// laterTrickling writes what it is given as it is given until it is told to
// trickle, and from then on a byte at a time, every pause.
type laterTrickling struct {
	net.Conn
	pause   time.Duration
	trickle atomic.Bool
}

func (c *laterTrickling) Write(p []byte) (int, error) {
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

// connected is a connection to the proxy that has been answered 200 to a
// CONNECT to authority, and the reader that read the answer.
func connected(t *testing.T, server *Server, authority string) (net.Conn, *bufio.Reader) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatalf("writing the CONNECT: %v", err)
	}
	reader := bufio.NewReader(raw)
	if res, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect}); err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT answered %v, %v", res, err)
	}
	return raw, reader
}

func TestWaitingForARequestInATunnelHasItsOwnEnd(t *testing.T) {
	// The first byte of a request in a tunnel comes at the end of a whole TLS
	// record, and one sent a byte at a time renews the idle timeout at every
	// byte. The wait for the request does not renew: it ends the connection
	// well before the record, and the request in it, could arrive.
	budgeted(t, func(b *budget) { b.idle = 300 * time.Millisecond })
	client := &counting{}
	ca := newCAForTest(t)
	server, _ := startProxy(t, client, ca)
	raw, reader := connected(t, server, "example.test:443")
	slow := &laterTrickling{Conn: raw, pause: 20 * time.Millisecond}
	tunnel := tls.Client(&bufferedConn{Conn: slow, reader: reader},
		&tls.Config{RootCAs: trusting(t, ca), ServerName: "example.test"})
	if err := tunnel.Handshake(); err != nil {
		t.Fatalf("the handshake in the tunnel: %v", err)
	}
	slow.trickle.Store(true)
	go func() {
		_, _ = io.WriteString(tunnel, "GET /x HTTP/1.1\r\nHost: example.test\r\nX-Pad: "+
			strings.Repeat("a", 100)+"\r\n\r\n")
	}()
	endsWithin(t, raw, 250*time.Millisecond, 1500*time.Millisecond)
	if client.asked.Load() != 0 {
		t.Error("the request went on")
	}
}

func TestAHandshakeInATunnelHasItsOwnEnd(t *testing.T) {
	// However quiet the caller is after the CONNECT, and however it
	// trickles: the handshake has as long as it has, in all, and is said to
	// have taken too long rather than to have been refused.
	budgeted(t, func(b *budget) { b.handshake, b.idle = 300*time.Millisecond, 5*time.Second })
	for _, tc := range []struct {
		name  string
		hello bool
	}{{"nothing sent", false}, {"a hello sent a byte at a time", true}} {
		t.Run(tc.name, func(t *testing.T) {
			client := &counting{}
			ca := newCAForTest(t)
			server, problems := startProxy(t, client, ca)
			raw, reader := connected(t, server, "example.test:443")
			if tc.hello {
				slow := &laterTrickling{Conn: raw, pause: 20 * time.Millisecond}
				slow.trickle.Store(true)
				tunnel := tls.Client(&bufferedConn{Conn: slow, reader: reader},
					&tls.Config{RootCAs: trusting(t, ca), ServerName: "example.test"})
				go func() { _ = tunnel.Handshake() }()
			}
			endsWithin(t, raw, 250*time.Millisecond, 1500*time.Millisecond)
			waitFor(t, problems, "the TLS handshake for example.test took longer than 300ms")
			for _, problem := range problems.list() {
				if strings.Contains(problem.Error(), "did not accept") {
					t.Errorf("reported %v", problem)
				}
			}
		})
	}
}

func TestConnectionsPastTheBudgetWaitForOneToEnd(t *testing.T) {
	// Not refused and not starved: the next connection is accepted once one
	// of those served ends, and the server still closes while it waits.
	budgeted(t, func(b *budget) { b.connections = 1 })
	client := &counting{}
	server, _ := startProxy(t, client, newCAForTest(t))
	first, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	r, _ := through(t, server, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
	time.Sleep(300 * time.Millisecond)
	if client.asked.Load() != 0 {
		t.Fatal("a second connection was served while the first held the only slot")
	}
	_ = first.Close()
	if res, err := http.ReadResponse(r, nil); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("once the first ended, the second was answered %v, %v", res, err)
	}

	// Every slot taken again, by a connection that stays: Close returns all
	// the same, since ending that connection frees its slot.
	if _, err := net.DialTimeout("tcp", server.Addr(), 5*time.Second); err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
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

func TestHeaderLimit(t *testing.T) {
	limit := headerLimit{r: strings.NewReader("abcdef"), left: -1}
	if got, err := io.ReadAll(io.LimitReader(&limit, 2)); string(got) != "ab" || err != nil {
		t.Errorf("between headers read %q, %v", got, err)
	}
	limit.left = 3
	p := make([]byte, 10)
	if n, err := limit.Read(p); n != 3 || err != nil || string(p[:n]) != "cde" {
		t.Errorf("a header read %q, %v", p[:n], err)
	}
	if n, err := limit.Read(p); n != 0 || !errors.Is(err, errHeaderTooLarge) {
		t.Errorf("a header past its budget read %d, %v", n, err)
	}
}

func TestTheBoundsOfAHeaderAndAHandshakeEndWithThem(t *testing.T) {
	// A body that takes longer than a header may, a byte at a time, and a
	// tunnel that is used after longer than its handshake may take: neither
	// is held to the bound of what came before it.
	budgeted(t, func(b *budget) {
		b.header, b.handshake, b.idle = 300*time.Millisecond, 300*time.Millisecond, 5*time.Second
	})

	t.Run("a body after its header", func(t *testing.T) {
		client := &counting{}
		server, problems := startProxy(t, client, newCAForTest(t))
		r, conn := through(t, server, "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10\r\n\r\n")
		for range 10 {
			time.Sleep(60 * time.Millisecond)
			if _, err := io.WriteString(conn, "b"); err != nil {
				t.Fatalf("writing the body: %v", err)
			}
		}
		if res, err := http.ReadResponse(r, nil); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("answered %v, %v; reported %v", res, err, problems.list())
		}
	})

	t.Run("a tunnel after its handshake", func(t *testing.T) {
		client := &counting{}
		ca := newCAForTest(t)
		server, problems := startProxy(t, client, ca)
		tunnel := openedTunnel(t, server, ca, "example.test:443", 0)
		time.Sleep(600 * time.Millisecond)
		if _, err := io.WriteString(tunnel, "GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		if res, err := http.ReadResponse(bufio.NewReader(tunnel), nil); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("answered %v, %v; reported %v", res, err, problems.list())
		}
	})
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
	// Accepting goes on once it passes, rather than ending for good, with
	// every slot it had: one, here. The wait grows while it lasts, 315ms over
	// six failures, and starts afresh the next time: the second connection is
	// not kept for the 320ms the seventh would have waited.
	budgeted(t, func(b *budget) { b.connections = 1 })
	client := &counting{}
	server, _ := startProxy(t, client, newCAForTest(t))
	_ = server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	flaky := &exhausted{Listener: listener, plan: []int{6, 1}}
	restarted := &Server{listener: flaky, opts: server.opts, budget: defaultBudget, conns: map[net.Conn]struct{}{},
		slots: make(chan struct{}, 1)}
	restarted.wg.Add(1)
	go restarted.accept()
	t.Cleanup(func() { _ = restarted.Close() })

	for i := range 2 {
		started := time.Now()
		r, conn := through(t, restarted, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
		if res, err := http.ReadResponse(r, nil); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("connection %d was answered %v, %v", i, res, err)
		}
		if elapsed := time.Since(started); i == 1 && elapsed > 200*time.Millisecond {
			t.Errorf("the second connection waited %s", elapsed)
		}
		// Which gives the one slot back.
		_ = conn.Close()
	}
	if client.asked.Load() != 2 {
		t.Errorf("asked %d", client.asked.Load())
	}
}
