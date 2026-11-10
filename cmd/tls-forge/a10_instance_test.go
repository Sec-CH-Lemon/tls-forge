package main

import (
	"fmt"
	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestA10CLIDefaultIsolatesEveryRequest(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, workers := range []string{"1", "4"} {
			t.Run(fmt.Sprintf("h2=%v/workers=%s", h2, workers), func(t *testing.T) {
				var mu sync.Mutex
				peers := map[string]bool{}
				count := 0
				site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					count++
					peers[r.RemoteAddr] = true
					if r.Header.Get("Cookie") != "" || r.Header.Get("If-None-Match") != "" {
						t.Error("inherited state", r.Header)
					}
					w.Header().Set("Set-Cookie", "received=secret; Path=/; Secure")
					w.Header().Set("Cache-Control", "max-age=600")
					w.Header().Set("ETag", `"v1"`)
					fmt.Fprint(w, "page")
				}))
				site.EnableHTTP2 = h2
				site.StartTLS()
				defer site.Close()
				code, _, stderr := exec(t, "fetch", "-k", "--repeat", "4", "-c", workers, site.URL)
				if code != 0 {
					t.Fatal(code, stderr)
				}
				mu.Lock()
				defer mu.Unlock()
				if count != 4 || len(peers) != 4 {
					t.Fatal("requests/connections", count, len(peers))
				}
			})
		}
	}
}

func TestA10CLIRejectsPersistentFlagsBeforeIO(t *testing.T) {
	count := 0
	site := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { count++ }))
	defer site.Close()
	for _, flags := range [][]string{{"--reuse-connection"}, {"--retry", "1", "--retry-as-browser"}} {
		args := append([]string{"fetch"}, flags...)
		args = append(args, site.URL)
		code, _, stderr := exec(t, args...)
		if code != 2 || !strings.Contains(stderr, "http.instance_scope=client") {
			t.Fatal(code, stderr)
		}
	}
	if count != 0 {
		t.Fatal("network side effects", count)
	}
}

func TestA10NetscapeOutputDoesNotMergeInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	flags := startedFlags(t, "--save-cookies", path)
	records := []result{{sessions: [][]tlsforge.Cookie{{{Name: "a", Value: "one"}}, {{Name: "a", Value: "two"}}}}}
	if _, err := (&pool{}).saveSessions(flags, records); err == nil || !strings.Contains(err.Error(), "multiple instances") {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "original" {
		t.Fatal(string(raw), err)
	}
}
