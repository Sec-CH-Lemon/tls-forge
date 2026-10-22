package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/cookie"
)

// seen is a server's record of the requests it was sent, method and headers.
type seen struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (s *seen) keep(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
}

func (s *seen) all() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.requests...)
}

// keepingServer is a TLS server that keeps every request and answers it with
// answer, or a page.
func keepingServer(t *testing.T, answer http.HandlerFunc) (*httptest.Server, *seen) {
	t.Helper()
	got := &seen{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.keep(r.Clone(r.Context()))
		if answer != nil {
			answer(w, r)
			return
		}
		_, _ = w.Write([]byte("<!doctype html><title>page</title>"))
	}))
	t.Cleanup(server.Close)
	return server, got
}

func TestRequestKindSendsWhatChromeSendsForIt(t *testing.T) {
	server, got := keepingServer(t, nil)
	page := server.URL + "/page"
	for _, tc := range []struct {
		name   string
		args   []string
		want   map[string]string
		absent []string
		as     string
	}{
		{"a typed navigation", []string{"--request-kind", "navigation"},
			map[string]string{"Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Sec-Fetch-Mode": "navigate",
				"Upgrade-Insecure-Requests": "1"},
			[]string{"Referer", "Origin"}, "a navigation typed into the address bar"},
		{"a navigation from the page", []string{"--request-kind", "navigation", "--initiator-url", page},
			map[string]string{"Sec-Fetch-Site": "same-origin", "Referer": page, "Sec-Fetch-Dest": "document"},
			[]string{"Sec-Fetch-User", "Origin"}, "a navigation from " + page},
		{"a form posted", []string{"--request-kind", "form", "--initiator-url", page, "-X", "POST", "-d", "a=1"},
			map[string]string{"Cache-Control": "max-age=0", "Origin": server.URL, "Sec-Fetch-Mode": "navigate",
				"Content-Type": "application/x-www-form-urlencoded"},
			nil, "a form from " + page},
		{"fetch()", []string{"--request-kind", "fetch", "--initiator-url", page},
			map[string]string{"Accept": "*/*", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": page},
			// HTTP/1.1, which says no priority.
			[]string{"Upgrade-Insecure-Requests", "Origin", "Priority"}, "fetch() from " + page},
		{"an XHR", []string{"--request-kind", "xhr", "--initiator-url", page, "-X", "post", "-d", "x",
			"-H", "Content-Type: text/plain;charset=UTF-8"},
			map[string]string{"Origin": server.URL, "Content-Type": "text/plain;charset=UTF-8"},
			nil, "an XHR from " + page},
	} {
		before := len(got.all())
		log := filepath.Join(t.TempDir(), "run.jsonl")
		args := append([]string{"fetch", "--insecure", "--profile", "chrome_155_macos", "--log", log}, tc.args...)
		code, _, stderr := exec(t, append(args, server.URL+"/target")...)
		if code != 0 {
			t.Fatalf("%s: exit code = %d\n%s", tc.name, code, stderr)
		}
		requests := got.all()[before:]
		if len(requests) != 1 {
			t.Fatalf("%s: %d requests", tc.name, len(requests))
		}
		r := requests[0]
		for name, want := range tc.want {
			if value := r.Header.Get(name); value != want {
				t.Errorf("%s: %s is %q, want %q", tc.name, name, value, want)
			}
		}
		for _, name := range tc.absent {
			if r.Header.Get(name) != "" {
				t.Errorf("%s: has %s: %q", tc.name, name, r.Header.Get(name))
			}
		}
		if r.Method != strings.ToUpper(r.Method) {
			t.Errorf("%s: sent %s", tc.name, r.Method)
		}
		if !strings.Contains(stderr, "  sent as     "+tc.as+"\n") {
			t.Errorf("%s: the header does not say %q:\n%s", tc.name, tc.as, stderr)
		}
		run := recordsOf(logRecords(t, log), "run")
		if len(run) != 1 || run[0].get("request_kind") != tc.args[1] {
			t.Errorf("%s: the run was logged as %v", tc.name, run)
		}
	}
	// Without the flag nothing is said of it, and the run goes as before.
	if code, _, stderr := exec(t, "fetch", "--insecure", server.URL); code != 0 || strings.Contains(stderr, "sent as") {
		t.Errorf("without --request-kind: exit code = %d\n%s", code, stderr)
	}
}

func TestRequestKindKeepsNoCookieOfAnAnswerToARequestWithoutCredentials(t *testing.T) {
	// fetch() of another site, credentials same-origin, carries none and keeps
	// none of the cookies its answer sets, as Chrome's; from the page's own
	// origin it carries them and keeps them.
	server, _ := keepingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Set-Cookie", strings.TrimPrefix(r.URL.Path, "/")+"=1; Path=/; Secure")
	})
	for _, tc := range []struct {
		initiator, name string
		kept            bool
	}{
		{"https://other.test/page", "across", false},
		{server.URL + "/page", "same", true},
	} {
		saved := filepath.Join(t.TempDir(), "session.json")
		code, _, stderr := exec(t, "fetch", "--insecure", "--profile", "chrome_155_macos", "--request-kind", "fetch",
			"--initiator-url", tc.initiator, "--save-cookies", saved, server.URL+"/"+tc.name)
		if code != 0 {
			t.Fatalf("%s: exit code = %d\n%s", tc.name, code, stderr)
		}
		// A jar that holds nothing is written nowhere.
		var names []string
		if data, err := os.ReadFile(saved); err == nil {
			file, err := cookie.Load(data)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for _, set := range file.Sets {
				for _, c := range set.Cookies {
					names = append(names, c.Name)
				}
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if kept := slices.Contains(names, tc.name); kept != tc.kept || len(names) > 1 {
			t.Errorf("%s: saved %v", tc.name, names)
		}
	}
}

func TestRequestKindAsksCORSFirstAndStopsWhereItSaysNo(t *testing.T) {
	pageServer, _ := keepingServer(t, nil)
	page := pageServer.URL + "/page"
	allow := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", pageServer.URL)
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "content-type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	api, got := keepingServer(t, allow)
	args := []string{"fetch", "--insecure", "--profile", "chrome_155_macos", "--request-kind", "fetch",
		"--initiator-url", page, "-X", "POST", "-H", "Content-Type: application/json", "-d", "{}", "--retry", "2"}
	code, stdout, stderr := exec(t, append(args, api.URL+"/api")...)
	if code != 0 || stdout != `{"ok":true}` {
		t.Fatalf("exit code = %d, %q\n%s", code, stdout, stderr)
	}
	if methods := methodsOf(got.all()); methods != "OPTIONS,POST" {
		t.Errorf("sent %s", methods)
	}
	options := got.all()[0]
	if options.Header.Get("Access-Control-Request-Method") != "POST" ||
		options.Header.Get("Access-Control-Request-Headers") != "content-type" ||
		options.Header.Get("Origin") != pageServer.URL || options.Header.Get("Sec-Ch-Ua") != "" {
		t.Errorf("the preflight said %v", options.Header)
	}

	// Refused: the preflight alone, once, however many tries were asked for.
	refusing, refused := keepingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	code, _, stderr = exec(t, append(args, refusing.URL+"/api")...)
	if code != 1 || !strings.Contains(stderr, "CORS: the preflight of POST "+refusing.URL+"/api from "+pageServer.URL+
		" refused it: it was answered 403") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if methods := methodsOf(refused.all()); methods != "OPTIONS" {
		t.Errorf("sent %s", methods)
	}
}

func TestRequestKindAsksNothingOfPlainHTTPFromAPageOverHTTPS(t *testing.T) {
	// The flags say all there is to know of the first request: a usage
	// error, before any directory is made.
	dir := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--profile", "chrome_155_macos", "--request-kind", "fetch",
		"--initiator-url", "https://www.example.com/page", "-o", dir, "http://plain.test/x")
	if code != 2 || !strings.Contains(stderr, "tlsforge: bad usage: --request-kind fetch: http://plain.test/x: mixed content: "+
		"fetch() from a page over https is not sent to http://plain.test/x, which is not potentially trustworthy") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the output directory: %v", err)
	}

	// A redirect there: the first request goes, once, however many tries were
	// asked for, and the hop does not.
	server, got := keepingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://plain.test/hop", http.StatusFound)
	})
	code, _, stderr = exec(t, "fetch", "--insecure", "--profile", "chrome_155_macos", "--request-kind", "fetch",
		"--initiator-url", server.URL+"/page", "--retry", "2", server.URL+"/r")
	if code != 1 || !strings.Contains(stderr, "mixed content: fetch() from a page over https follows no redirect to "+
		"http://plain.test/hop, which is not potentially trustworthy") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if methods := methodsOf(got.all()); methods != "GET" {
		t.Errorf("sent %s", methods)
	}
}

func methodsOf(requests []*http.Request) string {
	var methods []string
	for _, r := range requests {
		methods = append(methods, r.Method)
	}
	return strings.Join(methods, ",")
}

func TestACheckerThatCannotBeMadeIsSaid(t *testing.T) {
	original := newClient
	t.Cleanup(func() { newClient = original })
	newClient = func(string, ...tlsforge.Option) (*tlsforge.Client, error) { return nil, errors.New("no client") }
	code, _, stderr := exec(t, "fetch", "--request-kind", "navigation", "https://a.example/")
	if code != 1 || !strings.Contains(stderr, "no client") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}
