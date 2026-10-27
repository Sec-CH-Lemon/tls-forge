package tlsforge

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closingPool struct {
	*idler
	calls            atomic.Int32
	entered, release chan struct{}
}

func (p *closingPool) CloseIdleConnections() {
	if p.calls.Add(1) == 1 {
		close(p.entered)
	}
	<-p.release
}

func TestConcurrentIdleClosesWaitForTheSameIO(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	s, err := tr.siteOf("old")
	if err != nil {
		t.Fatal(err)
	}
	pool := &closingPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
	s.inner.HttpClient = pool
	tr.releaseSite(s)
	first, second := make(chan struct{}), make(chan struct{})
	go func() { tr.closeIdle(); close(first) }()
	<-pool.entered
	go func() { tr.closeIdle(); close(second) }()
	select {
	case <-second:
		t.Error("second idle close returned before pending I/O finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(pool.release)
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("idle close did not finish")
		}
	}
	if calls := pool.calls.Load(); calls != 1 {
		t.Fatalf("%d overlapping close calls, want one shared operation", calls)
	}
}

func TestAnIdleCloseOfALeasedSiteWaitsForItsLastRelease(t *testing.T) {
	// A site with a request in flight is not closed under its reader (an
	// HTTP/3 transport counts a request only to its headers), nor forgotten:
	// its last release closes what is idle by then, once.
	tr, _ := idlers(t, "", refuseNone)
	s, err := tr.siteOf("busy")
	if err != nil {
		t.Fatal(err)
	}
	inner, bare := &idler{}, &idler{}
	s.inner.HttpClient, s.bare.HttpClient = inner, bare
	tr.mu.Lock()
	s.refs++ // a second reader of the site
	tr.mu.Unlock()
	tr.closeIdle()
	if inner.closed.Load() != 0 || bare.closed.Load() != 0 {
		t.Fatal("a leased site's connections were closed under its readers")
	}
	tr.releaseSite(s)
	if inner.closed.Load() != 0 {
		t.Fatal("closed while another reader still held the site")
	}
	tr.releaseSite(s)
	if inner.closed.Load() != 1 || bare.closed.Load() != 1 {
		t.Fatalf("closed %d and %d times on the last release, want once each", inner.closed.Load(), bare.closed.Load())
	}
	if s.idleAsked || s.closing != nil {
		t.Fatal("the request outlived its close")
	}
	if again, err := tr.siteOf("busy"); err != nil || again != s {
		t.Fatalf("the resident site went with its idle connections: %v", err)
	}
	tr.releaseSite(s)
	if inner.closed.Load() != 1 {
		t.Fatal("a release after the close closed the site again")
	}
}

func TestAnIdleConnectionOfABusySiteClosesOnceItsRequestEnds(t *testing.T) {
	// Over a real transport: the slow request's connection is left to it,
	// the idle one beside it is closed when the slow request is done, and
	// none of the site's stays open after CloseIdleConnections and that.
	hold := make(chan struct{})
	var mu sync.Mutex
	states := map[string]http.ConnState{}
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			w.Header().Set("Content-Length", "10")
			_, _ = w.Write([]byte("12345"))
			w.(http.Flusher).Flush()
			<-hold
			_, _ = w.Write([]byte("67890"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	site.Config.ConnState = func(c net.Conn, s http.ConnState) {
		mu.Lock()
		states[c.RemoteAddr().String()] = s
		mu.Unlock()
	}
	site.StartTLS() // HTTP/1.1: a connection a request at a time
	t.Cleanup(site.Close)
	client, err := New(WithProfile("chrome_155_macos"), WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	snapshot := func() map[http.ConnState]int {
		mu.Lock()
		defer mu.Unlock()
		count := map[http.ConnState]int{}
		for _, s := range states {
			count[s]++
		}
		return count
	}
	slow := make(chan error, 1)
	go func() {
		res, err := client.Do(&Request{URL: site.URL + "/slow"})
		if err == nil && string(res.Body) != "1234567890" {
			err = fmt.Errorf("the slow body came as %q", res.Body)
		}
		slow <- err
	}()
	waitFor(t, func() bool { return snapshot()[http.StateActive] == 1 })
	if _, err := client.Do(&Request{URL: site.URL + "/fast"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return snapshot()[http.StateIdle] == 1 })
	client.CloseIdleConnections()
	if got := snapshot(); got[http.StateActive] != 1 {
		t.Fatalf("the slow request's connection was not left to it: %v", got)
	}
	close(hold)
	if err := <-slow; err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		got := snapshot()
		return got[http.StateClosed] == 2 && len(got) == 1
	})
}

// waitFor waits up to 5 s for done to say so, failing the test otherwise.
func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
