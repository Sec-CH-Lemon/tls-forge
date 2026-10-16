package tlsforge

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorded is what a trace reported, kept in the order it was reported in.
//
// Behind a lock, because the hooks are called from whichever goroutine is doing
// the work and the test reads from its own.
type recorded struct {
	mu        sync.Mutex
	steps     []string
	conns     []ConnInfo
	sent      []Header
	redirects []string
	failed    []string
}

func (r *recorded) step(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, fmt.Sprintf(format, args...))
}

// trace is a Trace with every hook set, each writing down what it was told.
func (r *recorded) trace() *Trace {
	return &Trace{
		DNSStart: func(host string) { r.step("dns %s", host) },
		DNSDone: func(addrs []string, err error) {
			r.step("resolved %d %v", len(addrs), err)
		},
		ConnectStart: func(network, addr string) { r.step("dial %s %s", network, addr) },
		ConnectDone: func(_, addr string, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if err != nil {
				r.failed = append(r.failed, addr)
				return
			}
			r.steps = append(r.steps, "dialled "+addr)
		},
		GotConn: func(conn ConnInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.conns = append(r.conns, conn)
			r.steps = append(r.steps, "conn")
		},
		WroteRequest: func(sent Header, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.sent = append(r.sent, sent)
			r.steps = append(r.steps, fmt.Sprintf("wrote %v", err))
		},
		FirstByte: func() { r.step("first byte") },
		Redirect: func(status int, location string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.redirects = append(r.redirects, fmt.Sprintf("%d %s", status, location))
		},
	}
}

// index is where a step was reported, or -1 when it never was.
func (r *recorded) index(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, step := range r.steps {
		if strings.HasPrefix(step, prefix) {
			return i
		}
	}
	return -1
}

func TestTraceFollowsARequestOntoTheWire(t *testing.T) {
	// The echo server is reached as localhost, which is a name, so the lookup is
	// part of what gets reported.
	server := startEcho(t)
	client := newTestClient(t)

	var first recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: first.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	// In the order a request happens in: the name, the socket, the connection,
	// the request, the answer.
	order := []string{"dns localhost", "resolved", "dial tcp", "dialled", "conn", "wrote <nil>", "first byte"}
	last := -1
	for _, step := range order {
		at := first.index(step)
		if at < 0 {
			t.Fatalf("no %q among the steps: %v", step, first.steps)
		}
		if at < last {
			t.Errorf("%q came before the step it follows: %v", step, first.steps)
		}
		last = at
	}
	if first.index("resolved 0") >= 0 {
		t.Errorf("the lookup reported no addresses: %v", first.steps)
	}

	if len(first.conns) != 1 {
		t.Fatalf("connections reported = %d, want 1", len(first.conns))
	}
	conn := first.conns[0]
	if conn.Reused || conn.RemoteAddr == "" {
		t.Errorf("a first connection was reported as %+v", conn)
	}
	if conn.TLSVersion != "TLS 1.3" || conn.ALPN != "h2" || !strings.HasPrefix(conn.CipherSuite, "TLS_") {
		t.Errorf("the handshake was reported as %+v", conn)
	}

	// What was written, in the order it was written: the pseudo-headers lead
	// and the profile's headers follow them.
	if len(first.sent) != 1 || len(first.sent[0]) < 5 {
		t.Fatalf("request reported as %v", first.sent)
	}
	sent := first.sent[0]
	if sent[0].Name != ":method" || sent[0].Value != "GET" {
		t.Errorf("the first field written was %+v, want :method", sent[0])
	}
	if sent.Get(":path") != "/api/all" || sent.Get("user-agent") == "" {
		t.Errorf("the request line or the user-agent is missing from %v", sent)
	}

	// A second request finds the connection open: nothing to look up or dial.
	var second recorded
	if _, err := client.Do(&Request{URL: server.URL() + "/api/all", Trace: second.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(second.conns) != 1 || !second.conns[0].Reused {
		t.Errorf("the second request's connection was reported as %+v", second.conns)
	}
	if second.index("dns") >= 0 || second.index("dial") >= 0 {
		t.Errorf("a reused connection reported a lookup or a dial: %v", second.steps)
	}
}

func TestTraceReportsEachHopOfARedirect(t *testing.T) {
	server, _ := hopServer(t)
	client := newTestClient(t)

	var seen recorded
	res, err := client.Do(&Request{URL: server.URL + "/hop", Trace: seen.trace()})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.URL != server.URL+"/landed" {
		t.Fatalf("landed on %s", res.URL)
	}

	if want := []string{"302 " + server.URL + "/landed"}; len(seen.redirects) != 1 || seen.redirects[0] != want[0] {
		t.Errorf("redirects reported = %v, want %v", seen.redirects, want)
	}
	// Each hop reports the request it wrote and nothing of the hop before it.
	if len(seen.sent) != 2 {
		t.Fatalf("requests written = %d, want one per hop", len(seen.sent))
	}
	for i, path := range []string{"/hop", "/landed"} {
		if got := seen.sent[i].Values(":path"); len(got) != 1 || got[0] != path {
			t.Errorf("hop %d wrote :path %v, want only %s", i+1, got, path)
		}
	}
}

func TestTraceDoesNotReportARedirectThatWasRefused(t *testing.T) {
	server, _ := hopServer(t)
	client := newTestClient(t, WithTimeout(10*time.Second))

	var seen recorded
	if _, err := client.Do(&Request{URL: server.URL + "/loop", Trace: seen.trace()}); err == nil {
		t.Fatal("a redirect that never ends was followed to an answer")
	}
	// Twenty requests were made, so nineteen redirects were followed. The
	// twentieth was the one the chain stopped at, and is not reported as one
	// that was taken.
	if len(seen.redirects) != maxRedirects-1 {
		t.Errorf("redirects reported = %d, want %d", len(seen.redirects), maxRedirects-1)
	}
}

func TestTraceWithNoHooksChangesNothing(t *testing.T) {
	// Every hook is optional, and that includes all of them at once.
	server, _ := hopServer(t)
	client := newTestClient(t)
	res, err := client.Do(&Request{URL: strings.Replace(server.URL, "127.0.0.1", "localhost", 1) + "/hop",
		Trace: &Trace{}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(res.Body) != "landed" {
		t.Errorf("body = %q", res.Body)
	}
}

func TestTraceReportsADialThatFails(t *testing.T) {
	client := newTestClient(t, WithTimeout(2*time.Second))
	var seen recorded
	// Nothing listens here, so the dial is the last thing that happens.
	nowhere := refused(t)
	if _, err := client.Do(&Request{URL: "https://" + nowhere + "/", Trace: seen.trace()}); err == nil {
		t.Fatal("expected a transport error")
	}
	if len(seen.failed) != 1 || seen.failed[0] != nowhere {
		t.Errorf("failed dials reported = %v", seen.failed)
	}
	if len(seen.conns) != 0 || seen.index("first byte") >= 0 {
		t.Errorf("a request that never connected reported more than its dial: %v", seen.steps)
	}
}

func TestTraceOverPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t)

	var seen recorded
	if _, err := client.Do(&Request{URL: server.URL, Trace: seen.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(seen.conns) != 1 {
		t.Fatalf("connections reported = %d", len(seen.conns))
	}
	// No handshake, so nothing to say about one.
	conn := seen.conns[0]
	if conn.TLSVersion != "" || conn.CipherSuite != "" || conn.ALPN != "" || conn.Resumed {
		t.Errorf("a plain connection reported a handshake: %+v", conn)
	}
	if conn.RemoteAddr != strings.TrimPrefix(server.URL, "http://") {
		t.Errorf("remote address = %q, want the server's", conn.RemoteAddr)
	}
	// HTTP/1.1 has no pseudo-headers, and its names keep their wire spelling.
	if len(seen.sent) != 1 || len(seen.sent[0]) == 0 || seen.sent[0][0].Name != "Host" {
		t.Errorf("request reported as %v, want Host first", seen.sent)
	}
}

// addresslessConn is a connection that cannot say where it leads.
type addresslessConn struct{ net.Conn }

func (addresslessConn) RemoteAddr() net.Addr { return nil }

func TestConnOfAConnectionWithNoAddress(t *testing.T) {
	if got, want := connOf(addresslessConn{}, true), (ConnInfo{Reused: true}); !reflect.DeepEqual(got, want) {
		t.Errorf("connOf = %+v, want %+v", got, want)
	}
}
