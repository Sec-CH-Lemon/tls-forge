package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The server counts actual accepted connections and requests, independently
// of the client's reused bit. No cache hit can stand in for a request here.
func TestA9CLIConnectionOwnership(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, workers := range []string{"1", "4"} {
			for _, mode := range []string{"shared", "fresh", "entry"} {
				t.Run(protocol+"/"+workers+"/"+mode, func(t *testing.T) {
					var mu sync.Mutex
					accepted, closed, requests := 0, 0, 0
					peers := map[string]int{}
					site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests++
						peers[r.RemoteAddr]++
						mu.Unlock()
						w.Header().Set("Cache-Control", "no-store")
						_, _ = w.Write([]byte(r.URL.Path))
					}))
					site.EnableHTTP2 = protocol == "h2"
					site.Config.ConnState = func(_ net.Conn, state http.ConnState) {
						mu.Lock()
						defer mu.Unlock()
						if state == http.StateNew {
							accepted++
						}
						if state == http.StateClosed {
							closed++
						}
					}
					site.StartTLS()
					t.Cleanup(site.Close)
					list := writeList(t, "urls.txt", site.URL+"/a\n"+site.URL+"/b\n"+site.URL+"/c\n"+site.URL+"/d\n")
					args := []string{"fetch", "--no-exit-lookup", "--insecure", "--input", list, "--repeat", "2", "-c", workers}
					switch mode {
					case "fresh":
						args = append(args, "--fresh-connection")
					case "entry":
						args = append(args, "--reuse-connection")
					}
					if code, _, stderr := exec(t, args...); code != 0 {
						t.Fatalf("exit %d: %s", code, stderr)
					}
					deadline := time.Now().Add(3 * time.Second)
					for {
						mu.Lock()
						done := accepted == closed
						mu.Unlock()
						if done || time.Now().After(deadline) {
							break
						}
						time.Sleep(time.Millisecond)
					}
					mu.Lock()
					defer mu.Unlock()
					if requests != 8 || accepted != closed {
						t.Errorf("requests=%d accepted=%d closed=%d peers=%v", requests, accepted, closed, peers)
					}
					switch mode {
					case "shared":
						if protocol == "h2" || workers == "1" {
							if accepted != 1 {
								t.Errorf("shared: accepted=%d, want 1; peers=%v", accepted, peers)
							}
						} else if accepted < 1 || accepted > 4 {
							t.Errorf("H1 pool accepted=%d, want 1..4", accepted)
						}
					case "fresh":
						if accepted != 8 {
							t.Errorf("fresh: accepted=%d, want 8", accepted)
						}
					case "entry":
						if len(peers) != 4 || accepted < 4 || accepted > 8 {
							t.Errorf("entry: accepted=%d serving_peers=%d, want four private row pools (including any unused cold dials)", accepted, len(peers))
						}
					}
					t.Logf("requests=%d accepted=%d closed=%d peer_request_counts=%v", requests, accepted, closed, peers)
				})
			}
		}
	}
}

func TestA9CLISharedProxyIdentities(t *testing.T) {
	first, second := rotatingProxy(t), rotatingProxy(t)
	var mu sync.Mutex
	seen := map[string][]string{}
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = append(seen[r.URL.Path], r.RemoteAddr)
		mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("page"))
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	t.Cleanup(site.Close)
	list := writeList(t, "urls.json", fmt.Sprintf(`[{"url":%q,"proxy":%q},{"url":%q,"proxy":%q},{"url":%q,"proxy":%q}]`,
		site.URL+"/a", "http://"+first.addr, site.URL+"/b", "http://"+second.addr, site.URL+"/c", "http://"+first.addr))
	report := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "--insecure", "--input", list, "--repeat", "2", "-c", "4", "--report="+report, "--report-format", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, proxy := range []*recordingProxy{first, second} {
		if tunnels := proxy.seen(); len(tunnels) != 1 {
			t.Errorf("tunnels=%v, want one per identity", tunnels)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen["/a"]) != 2 || len(seen["/b"]) != 2 || len(seen["/c"]) != 2 {
		t.Fatalf("requests=%v", seen)
	}
	a, b := seen["/a"][0], seen["/b"][0]
	if a == b || !slices.Equal(seen["/a"], []string{a, a}) || !slices.Equal(seen["/b"], []string{b, b}) || !slices.Equal(seen["/c"], []string{a, a}) {
		t.Errorf("identity connections=%v", seen)
	}
	for _, r := range decoded(t, []byte(reportOf(t, report))).Requests {
		if r.Exit == nil || !strings.HasPrefix(r.Exit.IP, "203.0.113.") {
			t.Errorf("passive exit lost: %+v", r)
		}
	}
	t.Logf("one tunnel per proxy; request peers=%v", seen)
}

func TestA9CLIRetriesBorrowTheSharedConnection(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run(fmt.Sprint(reload), func(t *testing.T) {
			var mu sync.Mutex
			var peers []string
			site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				peers = append(peers, r.RemoteAddr)
				first := len(peers) == 1
				mu.Unlock()
				w.Header().Set("Cache-Control", "no-store")
				if first {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				_, _ = w.Write([]byte("page"))
			}))
			t.Cleanup(site.Close)
			args := []string{"fetch", "--no-exit-lookup", "--insecure", "--retry", "1", site.URL}
			if reload {
				args = append(args, "--retry-as-browser")
			}
			if code, _, stderr := exec(t, args...); code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(peers) != 2 || peers[0] != peers[1] {
				t.Errorf("retry peers=%v", peers)
			}
		})
	}
}
