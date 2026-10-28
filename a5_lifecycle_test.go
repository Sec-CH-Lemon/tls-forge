package tlsforge

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEvictedSiteConnectionsAreClosed(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, credentials := range []string{"include", "omit"} {
			for _, earlyClose := range []bool{false, true} {
				t.Run(fmt.Sprintf("h2=%v/%s/close-before-body=%v", h2, credentials, earlyClose), func(t *testing.T) {
					entered, release := make(chan struct{}), make(chan struct{})
					var mu sync.Mutex
					states := map[net.Conn]http.ConnState{}
					changed := make(chan struct{}, 1)
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Cache-Control", "no-store")
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
						w.Header().Set("Access-Control-Allow-Credentials", "true")
						w.Header().Set("Content-Length", "2")
						if r.URL.Path == "/hold" {
							w.WriteHeader(200)
							w.(http.Flusher).Flush()
							close(entered)
							<-release
						}
						_, _ = io.WriteString(w, "ok")
					}))
					server.EnableHTTP2 = h2
					server.Config.ConnState = func(c net.Conn, s http.ConnState) {
						mu.Lock()
						states[c] = s
						mu.Unlock()
						select {
						case changed <- struct{}{}:
						default:
						}
					}
					server.StartTLS()
					t.Cleanup(server.Close)
					var once sync.Once
					finish := func() { once.Do(func() { close(release) }) }
					defer finish()
					c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"http.max_site_pools": 1})))
					request := func(page, path string) error {
						_, err := c.Do(&Request{URL: server.URL + path, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://" + page + "/", Credentials: credentials}})
						return err
					}
					done := make(chan error, 1)
					go func() { done <- request("a.example", "/hold") }()
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("held response never began")
					}
					if err := request("b.example", "/"); err != nil {
						t.Fatal(err)
					}
					// One site at most: a.example's was evicted for b.example's,
					// and is held, retired, by the request still reading it.
					c.transports.mu.Lock()
					var held *site
					for s := range c.transports.retired {
						held = s
					}
					names := []string{}
					for _, s := range c.transports.sites {
						names = append(names, s.name)
					}
					evicted := len(c.transports.retired) == 1 && held.refs > 0 && held.retired &&
						len(names) == 1 && names[0] != held.name && strings.Contains(held.name, "a.example")
					c.transports.mu.Unlock()
					if !evicted {
						t.Fatalf("no eviction: sites %v, retired %d", names, len(c.transports.retired))
					}
					if earlyClose {
						_ = c.Close()
					}
					finish()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					if !earlyClose {
						// Its last lease ended with the request: it is closed,
						// and forgotten, before Close.
						c.transports.mu.Lock()
						left := len(c.transports.retired)
						c.transports.mu.Unlock()
						if left != 0 {
							t.Errorf("%d retired sites kept after their last request", left)
						}
						_ = c.Close()
					}
					deadline := time.NewTimer(time.Second)
					defer deadline.Stop()
					for {
						mu.Lock()
						opened := 0
						total := len(states)
						for _, s := range states {
							if s != http.StateClosed {
								opened++
							}
						}
						mu.Unlock()
						if opened == 0 && total >= 2 {
							t.Logf("RESULT: %d of %d connections open after completion/Close", opened, total)
							break
						}
						select {
						case <-changed:
						case <-deadline.C:
							t.Fatalf("RESULT: %d of %d connections open after completion/Close", opened, total)
						}
					}
				})
			}
		}
	}
}

type stalledPool struct {
	*idler
	entered, release chan struct{}
	once             sync.Once
}

func (p *stalledPool) stall()                        { p.once.Do(func() { close(p.entered) }); <-p.release }
func (p *stalledPool) CloseIdleConnections()         { p.stall() }
func (p *stalledPool) ReapIdleConnectionsBut(string) { p.stall() }

func TestTransportIOLeavesRegistryUnlocked(t *testing.T) {
	for _, operation := range []string{"evict", "close-idle", "reap"} {
		t.Run(operation, func(t *testing.T) {
			tr, _ := idlers(t, "", refuseNone)
			tr.behavior = tr.behavior.Clone()
			tr.behavior["http.max_site_pools"] = []byte(`1`)
			old, err := tr.siteOf("old")
			if err != nil {
				t.Fatal(err)
			}
			blocked := &stalledPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
			old.inner.HttpClient = blocked
			tr.releaseSite(old)
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch operation {
				case "evict":
					_, _ = tr.siteOf("new")
				case "close-idle":
					tr.closeIdle()
				case "reap":
					tr.reapIdle("")
				}
			}()
			select {
			case <-blocked.entered:
			case <-time.After(time.Second):
				t.Fatal("I/O did not begin")
			}
			unlocked := tr.mu.TryLock()
			if unlocked {
				tr.mu.Unlock()
			}
			close(blocked.release)
			<-done
			if !unlocked {
				t.Error("transport registry mutex held across I/O")
			}
		})
	}
}

func TestRetiredSitesHaveBoundedLeaseLifetime(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	tr.behavior = tr.behavior.Clone()
	tr.behavior["http.max_site_pools"] = []byte(`1`)
	first, err := tr.siteOf("first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tr.siteOf("second")
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.retired) != 1 || !tr.retired[first] {
		t.Fatal("busy evicted site lost")
	}
	tr.closeIdle()
	tr.releaseSite(first)
	if len(tr.retired) != 0 {
		t.Fatal("completed evicted site retained")
	}
	tr.close()
	if len(tr.retired) != 1 || !tr.retired[second] {
		t.Fatal("active site lost during Close")
	}
	tr.releaseSite(second)
	if len(tr.retired) != 0 || len(tr.sites) != 0 {
		t.Fatal("Close retained completed sites")
	}
	if _, err := tr.siteOf("late"); err == nil {
		t.Fatal("closed transports admitted a site")
	}
}

func TestCloseIdleWaitsForDrainStillStarting(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	s, err := tr.siteOf("first")
	if err != nil {
		t.Fatal(err)
	}
	entered, returned := make(chan struct{}), make(chan struct{})
	go func() {
		tr.letGo(func(ctx context.Context) <-chan struct{} {
			close(entered)
			<-ctx.Done()
			done := make(chan struct{})
			close(done)
			return done
		}, s)
		close(returned)
	}()
	<-entered
	stopped := make(chan struct{})
	go func() { tr.closeIdle(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("close/drain deadlocked")
	}
	<-returned
	tr.releaseSite(s)
	if len(tr.draining) != 0 {
		t.Fatal("drain retained")
	}
}

func TestEvictedRedirectDrainRemainsOwned(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			server := newLifecycleServer(t, h2, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					w.Header().Set("Location", "https://b.example/end")
					w.Header().Set("Content-Length", "64")
					w.WriteHeader(302)
					w.(http.Flusher).Flush()
					close(entered)
					<-release
					_, _ = io.WriteString(w, strings.Repeat("x", 64))
					return
				}
				_, _ = io.WriteString(w, "ok")
			})
			defer close(release)
			c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"http.max_site_pools": 1, "h1.dropped_body": "drain", "h2.dropped_body": "drain", "http.drain_bytes": 16384, "http.drain_ms": 3000, "h1.unread_grace_us": 0, "h2.unread_grace_us": 0})), dialingTo(server.Listener.Addr().String()))
			if _, err := c.Get("https://a.example/start"); err != nil {
				t.Fatal(err)
			}
			<-entered
			c.transports.mu.Lock()
			n := len(c.transports.retired)
			c.transports.mu.Unlock()
			if n != 1 {
				t.Fatalf("detached evicted response lost: %d retired sites", n)
			}
			_ = c.Close()
			c.transports.mu.Lock()
			n = len(c.transports.retired)
			pending := len(c.transports.draining)
			c.transports.mu.Unlock()
			if n != 0 || pending != 0 {
				t.Fatalf("Close retained %d sites/%d drains", n, pending)
			}
		})
	}
}

func TestIdleCloseExcludesNewReadersWithoutRegistryLock(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	old, err := tr.siteOf("old")
	if err != nil {
		t.Fatal(err)
	}
	blocked := &stalledPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
	old.inner.HttpClient = blocked
	tr.releaseSite(old)
	closed := make(chan struct{})
	go func() { tr.closeIdle(); close(closed) }()
	<-blocked.entered
	acquired := make(chan *site, 1)
	go func() {
		s, err := tr.siteOf("old")
		if err != nil {
			t.Error(err)
		}
		acquired <- s
	}()
	unrelated, err := tr.siteOf("unrelated")
	if err != nil {
		t.Fatal(err)
	}
	tr.releaseSite(unrelated)
	select {
	case <-acquired:
		t.Error("new reader entered a pool whose idle close is in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(blocked.release)
	<-closed
	select {
	case s := <-acquired:
		if s != old {
			t.Fatal("idle close replaced the site's session pool")
		}
		tr.releaseSite(s)
	case <-time.After(time.Second):
		t.Fatal("reader not released after idle close")
	}
}

// Close waits for the close of a site evicted before it that is still going,
// a site no request leased as much as one whose last lease it ended: once
// Close returns, no connection of the client is left to close.
func TestCloseWaitsForTheCloseOfAnEvictedSite(t *testing.T) {
	for _, leased := range []bool{false, true} {
		t.Run(fmt.Sprintf("leased=%v", leased), func(t *testing.T) {
			tr, _ := idlers(t, "", refuseNone)
			tr.behavior = tr.behavior.Clone()
			tr.behavior["http.max_site_pools"] = []byte(`1`)
			old, err := tr.siteOf("old")
			if err != nil {
				t.Fatal(err)
			}
			blocked := &stalledPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
			old.inner.HttpClient = blocked
			if !leased {
				tr.releaseSite(old)
			}
			evicting := make(chan struct{})
			go func() {
				defer close(evicting)
				if s, err := tr.siteOf("new"); err == nil {
					tr.releaseSite(s)
				}
			}()
			if leased {
				// Evicted under its lease; its last release closes it.
				deadline := time.Now().Add(time.Second)
				for {
					tr.mu.Lock()
					retired := old.retired
					tr.mu.Unlock()
					if retired || time.Now().After(deadline) {
						break
					}
					time.Sleep(time.Millisecond)
				}
				go func() {
					tr.releaseSite(old)
				}()
			}
			select {
			case <-blocked.entered:
			case <-time.After(time.Second):
				t.Fatal("the evicted site's close did not begin")
			}
			closed := make(chan struct{})
			go func() {
				tr.close()
				close(closed)
			}()
			select {
			case <-closed:
				t.Error("Close returned while an evicted site's close was still going")
			case <-time.After(100 * time.Millisecond):
			}
			close(blocked.release)
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Close did not return once the evicted site's close was done")
			}
			<-evicting
			tr.mu.Lock()
			defer tr.mu.Unlock()
			if len(tr.retired) != 0 || len(tr.sites) != 0 {
				t.Errorf("after Close, %d retired and %d sites kept", len(tr.retired), len(tr.sites))
			}
		})
	}
}

// A Close made while another is closing a site waits for it too.
func TestACloseWaitsForTheSitesAnotherCloseIsClosing(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	s, err := tr.siteOf("one")
	if err != nil {
		t.Fatal(err)
	}
	blocked := &stalledPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
	s.inner.HttpClient = blocked
	tr.releaseSite(s)
	first := make(chan struct{})
	go func() {
		tr.close()
		close(first)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("the first Close did not begin closing the site")
	}
	second := make(chan struct{})
	go func() {
		tr.close()
		close(second)
	}()
	select {
	case <-second:
		t.Error("a second Close returned while the first was still closing a site")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocked.release)
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("a Close did not return once the site was closed")
		}
	}
}
