package tlsforge

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/conntap"
)

// lifecycleServer is a TLS server of h2 or HTTP/1.1 alone that says when each
// connection it took was closed.
type lifecycleServer struct {
	*httptest.Server
	mu     sync.Mutex
	closed map[string]time.Time // by the client's address
	done   chan string
}

func newLifecycleServer(t *testing.T, h2 bool, handler http.HandlerFunc) *lifecycleServer {
	t.Helper()
	s := &lifecycleServer{closed: map[string]time.Time{}, done: make(chan string, 16)}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }
	}
	s.Server = httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = h2
	s.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state != http.StateClosed && state != http.StateHijacked {
			return
		}
		s.mu.Lock()
		s.closed[c.RemoteAddr().String()] = time.Now()
		s.mu.Unlock()
		s.done <- c.RemoteAddr().String()
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// closedWithin says whether the server saw a connection closed within d.
func (s *lifecycleServer) closedWithin(d time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(d):
		return false
	}
}

func get(t *testing.T, c *Client, url string, tap conntap.Tap) *Response {
	t.Helper()
	ctx := context.Background()
	if tap != nil {
		ctx = conntap.With(ctx, tap)
	}
	res, err := c.Do(&Request{URL: url, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestAChromeProfileClosesItsConnectionsWithoutCloseNotify holds
// "tls.close_notify" to what goes over the connection when the client closes
// it: nothing before the TCP close for Chrome's profiles, whose browser calls
// no SSL_shutdown, and the alert's record when a profile says true; over
// HTTP/2 and HTTP/1.1.
func TestAChromeProfileClosesItsConnectionsWithoutCloseNotify(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h2     bool
		policy map[string]any
		alert  bool
	}{
		{"h2/chrome", true, nil, false},
		{"h1/chrome", false, nil, false},
		{"h2/close_notify", true, map[string]any{"tls.close_notify": true}, true},
		{"h1/close_notify", false, map[string]any{"tls.close_notify": true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newLifecycleServer(t, tc.h2, nil)
			c := newTestClient(t, WithProfileValue(policyFile(t, tc.policy)))
			tap := &seeingTap{}
			get(t, c, site.URL, tap)
			time.Sleep(100 * time.Millisecond) // whatever follows the answer has been sent
			dialed, _ := tap.seen()
			if len(dialed) != 1 {
				t.Fatalf("%d connections dialed", len(dialed))
			}
			before, _ := dialed[0].what()
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if !site.closedWithin(2 * time.Second) {
				t.Fatal("the connection was not closed")
			}
			after, _ := dialed[0].what()
			sent := len(after) - len(before)
			if tc.alert && sent == 0 {
				t.Fatal("no close_notify was sent")
			}
			if !tc.alert && sent != 0 {
				t.Fatalf("%d bytes sent as the connection was closed", sent)
			}
		})
	}
}

// TestAChromeProfileClosesASessionGoingAwayAtOnce: a server that says GOAWAY
// (Go's says it for "Connection: close", and closes a second later) sees
// Chrome's profiles close the connection as soon as its stream is done;
// without "h2.close_on_goaway" the client waits for the server to close it.
func TestAChromeProfileClosesASessionGoingAwayAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy map[string]any
		at     time.Duration // the connection closed before this
		after  time.Duration // and after this
	}{
		{"chrome", nil, 400 * time.Millisecond, 0},
		{"stays", map[string]any{"h2.close_on_goaway": false}, 3 * time.Second, 700 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newLifecycleServer(t, true, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				_, _ = io.WriteString(w, "going away")
			})
			c := newTestClient(t, WithProfileValue(policyFile(t, tc.policy)))
			res := get(t, c, site.URL, nil)
			if res.Text() != "going away" {
				t.Fatalf("answer %q", res.Text())
			}
			answered := time.Now()
			if !site.closedWithin(tc.at) {
				t.Fatalf("the connection was still open %v after the GOAWAY", tc.at)
			}
			if took := time.Since(answered); took < tc.after {
				t.Fatalf("the client closed %v after the GOAWAY", took)
			}
		})
	}
}

// TestAChromeProfileKeepsAnIdleHTTP2ConnectionOpen: Chrome's SpdySession has
// no idle timer ("h2.idle_connection_timeout_ms": 0); a profile that gives one
// closes the connection when it runs out.
func TestAChromeProfileKeepsAnIdleHTTP2ConnectionOpen(t *testing.T) {
	site := newLifecycleServer(t, true, nil)
	c := newTestClient(t, WithProfileValue(policyFile(t, nil)))
	get(t, c, site.URL, nil)
	if site.closedWithin(400 * time.Millisecond) {
		t.Fatal("an idle HTTP/2 connection was closed by the client")
	}

	timed := newLifecycleServer(t, true, nil)
	c = newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h2.idle_connection_timeout_ms": 100})))
	get(t, c, timed.URL, nil)
	if !timed.closedWithin(2 * time.Second) {
		t.Fatal("an HTTP/2 idle timeout of 100 ms did not close the connection")
	}
}

// TestAChromeProfileReapsIdleHTTP1ConnectionsWhenItAsksForOne holds
// "h1.idle_reap": "on-request" to Chromium's socket pool, which closes its
// idle sockets that are too old when a socket is asked of it, for any host,
// and never by itself; "timer" closes one by itself.
func TestAChromeProfileReapsIdleHTTP1ConnectionsWhenItAsksForOne(t *testing.T) {
	a := newLifecycleServer(t, false, nil)
	b := newLifecycleServer(t, false, nil)
	c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h1.idle_connection_timeout_ms": 100})))
	get(t, c, a.URL, nil)
	if a.closedWithin(400 * time.Millisecond) {
		t.Fatal("an idle HTTP/1.1 connection was closed with nothing asking for a connection")
	}
	get(t, c, b.URL, nil)
	if !a.closedWithin(2 * time.Second) {
		t.Fatal("asking for a connection left one idle too long open")
	}

	timer := newLifecycleServer(t, false, nil)
	c = newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h1.idle_connection_timeout_ms": 100, "h1.idle_reap": "timer"})))
	get(t, c, timer.URL, nil)
	if !timer.closedWithin(2 * time.Second) {
		t.Fatal("the idle timer did not close the connection")
	}

	// Chrome's 300 s: an idle connection is reused within it.
	reused := newLifecycleServer(t, false, nil)
	c = newTestClient(t, WithProfileValue(policyFile(t, nil)))
	tap := &seeingTap{}
	get(t, c, reused.URL, tap)
	get(t, c, reused.URL, tap)
	if dialed, _ := tap.seen(); len(dialed) != 1 {
		t.Fatalf("%d connections for two requests", len(dialed))
	}
}
