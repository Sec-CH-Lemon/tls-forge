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
					if earlyClose {
						_ = c.Close()
					}
					finish()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					if !earlyClose {
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
