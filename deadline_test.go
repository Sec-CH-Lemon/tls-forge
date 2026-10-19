package tlsforge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tarpit lets the first let connections it takes through to the server, and
// holds every later one: taken, never answered, so that a handshake with it
// hangs. caught has each one held.
type tarpit struct {
	net.Listener
	let    atomic.Int32
	taken  atomic.Int32
	mu     sync.Mutex
	held   []net.Conn
	caught chan net.Conn
}

func (l *tarpit) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.taken.Add(1) <= l.let.Load() {
			return c, nil
		}
		l.mu.Lock()
		l.held = append(l.held, c)
		l.mu.Unlock()
		l.caught <- c
	}
}

func (l *tarpit) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.held {
		_ = c.Close()
	}
}

// heldOne is the next connection l holds, which it must within five seconds.
func (l *tarpit) heldOne(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-l.caught:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection held")
		return nil
	}
}

// h2Server serves HTTP/2 and HTTP/1.1 over TLS at 127.0.0.1 with handler, the
// first let connections, and holds every later one.
func h2Server(t *testing.T, let int32, handler http.HandlerFunc) (*httptest.Server, *tarpit) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	pit := &tarpit{Listener: server.Listener, caught: make(chan net.Conn, 16)}
	pit.let.Store(let)
	server.Listener = pit
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(pit.release)
	return server, pit
}

func nothing(http.ResponseWriter, *http.Request) {}

// doing sends req with client, and says on the channel it returns how it
// ended.
func doing(client *Client, req *Request) <-chan error {
	ended := make(chan error, 1)
	go func() {
		_, err := client.Do(req)
		ended <- err
	}()
	return ended
}

// endedWithin is how ended ended, which it must within limit.
func endedWithin(t *testing.T, ended <-chan error, limit time.Duration) error {
	t.Helper()
	select {
	case err := <-ended:
		return err
	case <-time.After(limit):
		t.Fatalf("still going after %v", limit)
		return nil
	}
}

// hungUp says the client closed its end of c within two seconds.
func hungUp(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := io.Copy(io.Discard, c)
	return !errors.Is(err, os.ErrDeadlineExceeded)
}

// goroutinesBackTo fails the test unless the goroutines are as many as
// before within three seconds.
func goroutinesBackTo(t *testing.T, before int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, %d before:\n%s", runtime.NumGoroutine(), before, stacks[:runtime.Stack(stacks, true)])
		}
	}
}

func TestAHandshakeThatHangsEndsWithItsRequestsDeadline(t *testing.T) {
	const deadline = 300 * time.Millisecond
	for _, connection := range []struct {
		name string
		let  int32
	}{
		{"the first, which finds out what the server speaks", 0},
		{"one HTTP/2 dials after the first", 1},
	} {
		for _, by := range []struct {
			name    string
			timeout time.Duration
			ctx     func() (context.Context, context.CancelFunc)
		}{
			{"the client's timeout", deadline, func() (context.Context, context.CancelFunc) {
				return context.Background(), func() {}
			}},
			{"the caller's context", 30 * time.Second, func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), deadline)
			}},
		} {
			t.Run(connection.name+", "+by.name, func(t *testing.T) {
				server, pit := h2Server(t, connection.let, nothing)
				client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(by.timeout))
				if connection.let > 0 {
					if _, err := client.Do(&Request{URL: server.URL + "/first"}); err != nil {
						t.Fatalf("Do: %v", err)
					}
					client.CloseIdleConnections()
				}
				before := runtime.NumGoroutine()
				ctx, cancel := by.ctx()
				defer cancel()
				start := time.Now()
				err := endedWithin(t, doing(client, &Request{URL: server.URL + "/", Context: ctx}), 5*time.Second)
				took := time.Since(start)
				if !errors.Is(err, context.DeadlineExceeded) || !isTimeout(err) {
					t.Fatalf("Do: %v, want its deadline", err)
				}
				if want := `tlsforge: Get "` + server.URL + `/": context deadline exceeded`; err.Error() != want {
					t.Errorf("said %q, want %q", err, want)
				}
				if took < deadline || took > deadline+500*time.Millisecond {
					t.Errorf("ended after %v, its deadline %v", took, deadline)
				}
				// The connection is let go of, and so is every goroutine that
				// waited for it.
				if !hungUp(pit.heldOne(t)) {
					t.Error("the connection was not let go of")
				}
				goroutinesBackTo(t, before)
			})
		}
	}
}

func TestAHandshakeThatHangsHoldsUpNoOtherOriginOfItsSite(t *testing.T) {
	for _, tc := range []struct {
		name string
		let  int32
	}{
		{"the first", 0},
		{"one HTTP/2 dials after the first", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Origins of one site, 127.0.0.1: their connections are one
			// client's.
			hanging, pit := h2Server(t, tc.let, nothing)
			open, _ := h2Server(t, 100, nothing)
			fresh, _ := h2Server(t, 100, nothing)
			client := newTestClient(t, WithProfile("chrome_155_macos"))
			for _, url := range []string{open.URL, hanging.URL}[:1+tc.let] {
				if _, err := client.Do(&Request{URL: url + "/"}); err != nil {
					t.Fatalf("Do: %v", err)
				}
			}
			if tc.let > 0 {
				client.CloseIdleConnections()
				if _, err := client.Do(&Request{URL: open.URL + "/"}); err != nil {
					t.Fatalf("Do: %v", err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			hung := doing(client, &Request{URL: hanging.URL + "/", Context: ctx})
			pit.heldOne(t)
			// One the client has a connection to, and one it has none to yet.
			for _, url := range []string{open.URL, fresh.URL} {
				start := time.Now()
				if err := endedWithin(t, doing(client, &Request{URL: url + "/"}), 5*time.Second); err != nil {
					t.Errorf("Do %s: %v", url, err)
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("Do %s waited %v", url, took)
				}
			}
			// Its idle connections closed meanwhile.
			closed := make(chan struct{})
			go func() {
				client.CloseIdleConnections()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Error("closing its idle connections waited for the handshake")
			}
			cancel()
			if err := endedWithin(t, hung, 3*time.Second); !errors.Is(err, context.Canceled) {
				t.Errorf("the one that hung: %v", err)
			}
		})
	}
}

func TestAClientClosesWhileAHandshakeHangs(t *testing.T) {
	server, pit := h2Server(t, 0, nothing)
	client, err := New(WithInsecureSkipVerify(), WithProfile("chrome_155_macos"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hung := doing(client, &Request{URL: server.URL + "/", Context: ctx})
	pit.heldOne(t)
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	if err := endedWithin(t, closed, time.Second); err != nil {
		t.Errorf("Close: %v", err)
	}
	cancel()
	if err := endedWithin(t, hung, 3*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("the one that hung: %v", err)
	}
}

// slowly answers each request after delay, as answer says, the nth it was
// asked.
func slowly(delay time.Duration, answer func(w http.ResponseWriter, r *http.Request, n int)) http.HandlerFunc {
	var n atomic.Int32
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		answer(w, r, int(n.Add(1)))
	}
}

func TestTheTimeoutIsOneDeadlineForAllOfARequest(t *testing.T) {
	// Each step well within the timeout, the steps together past it.
	const timeout, step = time.Second, 600 * time.Millisecond
	for _, tc := range []struct {
		name    string
		answer  func(w http.ResponseWriter, r *http.Request, n int)
		request func(url string) *Request
	}{
		{"a 401 answered", func(w http.ResponseWriter, r *http.Request, _ int) {
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
				w.WriteHeader(http.StatusUnauthorized)
			}
		}, func(url string) *Request { return &Request{URL: strings.Replace(url, "://", "://u:p@", 1) + "/"} }},
		{"a 421 sent again", func(w http.ResponseWriter, _ *http.Request, n int) {
			if n == 1 {
				w.WriteHeader(http.StatusMisdirectedRequest)
			}
		}, func(url string) *Request { return &Request{URL: url + "/"} }},
		{"a preflight", func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
			w.Header().Set("Access-Control-Allow-Headers", "x-foo")
		}, func(url string) *Request {
			return &Request{URL: url + "/", Header: NewHeader("X-Foo", "1"),
				Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/"}}
		}},
		{"a start again for client hints", func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Accept-CH", "Sec-CH-UA-Arch")
			w.Header().Set("Critical-CH", "Sec-CH-UA-Arch")
		}, func(url string) *Request {
			return &Request{URL: url + "/", Browser: &BrowserContext{Kind: KindNavigation}}
		}},
		{"redirects", func(w http.ResponseWriter, r *http.Request, n int) {
			if n == 1 {
				http.Redirect(w, r, "/next", http.StatusFound)
			}
		}, func(url string) *Request { return &Request{URL: url + "/"} }},
		{"the body", func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Content-Length", "2")
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			time.Sleep(step)
			_, _ = io.WriteString(w, "b")
		}, func(url string) *Request { return &Request{URL: url + "/"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := h2Server(t, 100, slowly(step, tc.answer))
			client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(timeout))
			start := time.Now()
			res, err := client.Do(tc.request(server.URL))
			took := time.Since(start)
			if err == nil {
				t.Fatalf("answered %d after %v, past its timeout", res.Status, took)
			}
			if !errors.Is(err, context.DeadlineExceeded) || !isTimeout(err) {
				t.Errorf("Do: %v, want its deadline", err)
			}
			if took < timeout || took > timeout+500*time.Millisecond {
				t.Errorf("ended after %v, its timeout %v", took, timeout)
			}
		})
	}
}

func TestACallersEarlierDeadlineEndsARequestFirst(t *testing.T) {
	server, _ := h2Server(t, 100, slowly(time.Second, func(http.ResponseWriter, *http.Request, int) {}))
	client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(30*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := client.Do(&Request{URL: server.URL + "/", Context: ctx}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Do: %v, want the caller's deadline", err)
	}
	if took := time.Since(start); took > 700*time.Millisecond {
		t.Errorf("ended after %v", took)
	}
}

func TestARequestThroughAProxyThatNeverAnswersEndsAtItsDeadline(t *testing.T) {
	// A proxy that takes the connection and never says a word: the request
	// ends at its deadline, and lets go of the connection to the proxy.
	for _, scheme := range []string{"socks5", "socks5h", "socks4", "socks4a", "http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			taken := make(chan net.Conn, 4)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					taken <- c
				}
			}()
			client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(300*time.Millisecond),
				WithProxy(scheme+"://"+ln.Addr().String()))
			start := time.Now()
			// An address, which SOCKS4 looks up nowhere, never dialed: the
			// proxy says nothing.
			_, err = client.Do(&Request{URL: "https://127.0.0.1:8443/"})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Do: %v, want its deadline", err)
			}
			if took := time.Since(start); took > time.Second {
				t.Errorf("ended after %v", took)
			}
			select {
			case c := <-taken:
				defer c.Close()
				if !hungUp(c) {
					t.Error("the connection to the proxy was kept")
				}
			case <-time.After(time.Second):
				t.Fatal("the proxy was never dialed")
			}
		})
	}
}
