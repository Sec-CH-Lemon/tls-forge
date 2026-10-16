package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// profileWith is a profile file, at path, of a shipped Chrome whose user agent
// is agent.
func profileWith(t *testing.T, path, agent string) {
	t.Helper()
	p := resolved(t, "chrome_151_linux")
	p.Name = "mine"
	p.UserAgent = agent
	for i, field := range p.Headers {
		if field.Name == "user-agent" {
			p.Headers[i].Value = agent
		}
	}
	data, err := p.Save()
	if err != nil {
		t.Fatalf("saving the profile: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing the profile: %v", err)
	}
}

func TestAClientMadeLateWearsWhatTheRunBeganWith(t *testing.T) {
	// A list that goes two ways makes a client for each as it reaches it. The
	// profile is read off the disk when it is named, so the second client,
	// made after the file changed under the run, wore the new one while the
	// run said it wore the old: it is resolved once now, before the run.
	keepProfilesIn(t)
	path := filepath.Join(t.TempDir(), "mine.json")
	profileWith(t, path, "agent-before")

	var mu sync.Mutex
	agents := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents[r.URL.Path] = r.UserAgent()
		mu.Unlock()
		if r.URL.Path == "/first" {
			profileWith(t, path, "agent-after")
		}
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)

	// The second through a proxy: an identity of its own, and a client of its
	// own, made once the first has been fetched.
	proxy := startProxy(t)
	list := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(list, []byte(server.URL+"/first\n"+server.URL+"/second http://"+proxy.addr+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := exec(t, "fetch", "-k", "--profile", path, "--input", list, "--concurrency", "1",
		"--progress", "never")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if agents["/first"] != "agent-before" || agents["/second"] != "agent-before" {
		t.Errorf("the requests wore %v, want what the run began with for both", agents)
	}
}

func TestEveryPartOfARunNamesTheProfileItWears(t *testing.T) {
	// Asked for by a name that resolves to another, chrome: what the run
	// says on standard error, its log, its trace and each request it keeps
	// name the one it wears.
	keepProfilesIn(t)
	worn := resolved(t, "chrome").Name
	if worn == "chrome" {
		t.Fatal("chrome resolves to itself, which tells nothing")
	}
	server := startEcho(t)
	dir := t.TempDir()
	out, trace, log := filepath.Join(dir, "out"), filepath.Join(dir, "trace.json"), filepath.Join(dir, "run.jsonl")
	code, _, stderr := exec(t, "fetch", "--profile", "chrome", "--insecure", "-o", out, "--trace", trace,
		"--log", log, server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "  profile     "+worn+" · ") {
		t.Errorf("standard error does not name %s:\n%s", worn, stderr)
	}
	if runs := recordsOf(logRecords(t, log), "run"); len(runs) != 1 || runs[0].get("profile") != worn {
		t.Errorf("the log's run record is %v", runs)
	}
	if said := named(traceFile(t, trace), phaseInstant, "profile"); len(said) != 1 || said[0].Args["name"] != worn {
		t.Errorf("the trace says %v", said)
	}
	kept, err := filepath.Glob(filepath.Join(out, "localhost-*.log"))
	if err != nil || len(kept) != 1 {
		t.Fatalf("kept %v, %v", kept, err)
	}
	if data, err := os.ReadFile(kept[0]); err != nil || !strings.Contains(string(data), "profile") ||
		!strings.Contains(string(data), worn) {
		t.Errorf("the request kept says:\n%s", data)
	}
}

func TestTheDaemonStopsAtAProfileThereIsNoneOf(t *testing.T) {
	// Before it says what it is wearing, and with 1, as the client it cannot
	// make: the packages that start it read 2 as arguments it does not know.
	keepProfilesIn(t)
	code, _, stderr := exec(t, "daemon", "--profile", "no-such-profile")
	if code != 1 || !strings.Contains(stderr, `unknown profile "no-such-profile"`) ||
		strings.Contains(stderr, identityRule) {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}

func TestTheDaemonStopsAtACookieFileItCannotRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if code, _, stderr := exec(t, "daemon", "--cookies", missing); code != 1 || !strings.Contains(stderr, "missing.json") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}
