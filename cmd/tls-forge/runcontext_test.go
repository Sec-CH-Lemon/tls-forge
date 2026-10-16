package main

import (
	"maps"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/cookie"
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

// cookieKeeper is a server that keeps the Cookie header each path came with,
// and does what then says when one is asked for.
func cookieKeeper(t *testing.T, then func(path string)) (*httptest.Server, func() map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		then(r.URL.Path)
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	return server, func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(seen)
	}
}

func TestTheCookieFileIsReadOnceBeforeTheRun(t *testing.T) {
	// The second identity's client is made once the first has been fetched,
	// and the file has changed under the run by then, or become one that does
	// not read: it starts from the file as it was when the run began.
	for _, tc := range []struct{ name, then string }{
		{"written again", `{"sets":[{"id":"later","cookies":[{"name":"k","value":"after","domain":"127.0.0.1","path":"/"}]}]}`},
		{"no longer a cookie file", "{not a session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCookieFile(t,
				`{"sets":[{"id":"first","cookies":[{"name":"k","value":"before","domain":"127.0.0.1","path":"/"}]}]}`)
			server, seen := cookieKeeper(t, func(asked string) {
				if asked == "/first" {
					if err := os.WriteFile(path, []byte(tc.then), 0o600); err != nil {
						t.Errorf("rewriting the file: %v", err)
					}
				}
			})
			proxy := startProxy(t)
			list := writeList(t, "list.txt", server.URL+"/first\n"+server.URL+"/second http://"+proxy.addr+"\n")
			code, _, stderr := exec(t, "fetch", "-k", "--cookies", path, "--input", list, "--concurrency", "1",
				"--progress", "never")
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, stderr)
			}
			if got := seen(); got["/first"] != "k=before" || got["/second"] != "k=before" {
				t.Errorf("the requests carried %v", got)
			}
		})
	}
}

func TestEachIdentityDrawsItsSetOnceAndSaysWhich(t *testing.T) {
	// A file of sets and a list that goes two ways, two URLs each way: a set
	// drawn for each identity, in the order the list first goes each, and
	// used for every request that way. The log says which, set by set, which
	// is how such a run is read back.
	original := pickCookieSet
	t.Cleanup(func() { pickCookieSet = original })
	const seed = 11
	pickCookieSet = rand.New(rand.NewSource(seed))
	sets := []string{"a", "b", "c"}
	draw := rand.New(rand.NewSource(seed))
	direct, through := sets[draw.Intn(len(sets))], sets[draw.Intn(len(sets))]

	var lines []string
	for _, id := range sets {
		lines = append(lines, `{"id":"`+id+`","cookies":[{"name":"s","value":"`+id+`","domain":"127.0.0.1","path":"/"}]}`)
	}
	path := writeCookieFile(t, `{"sets":[`+strings.Join(lines, ",")+`]}`)
	server, seen := cookieKeeper(t, func(string) {})
	proxy := startProxy(t)
	list := writeList(t, "list.txt", server.URL+"/direct/1\n"+server.URL+"/through/1 http://"+proxy.addr+"\n"+
		server.URL+"/direct/2\n"+server.URL+"/through/2 http://"+proxy.addr+"\n")
	log := filepath.Join(t.TempDir(), "run.jsonl")
	code, _, stderr := exec(t, "fetch", "-k", "--cookies", path, "--input", list, "--concurrency", "1",
		"--progress", "never", "--log", log)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	got := seen()
	for _, n := range []string{"1", "2"} {
		if got["/direct/"+n] != "s="+direct || got["/through/"+n] != "s="+through {
			t.Fatalf("the requests carried %v, want s=%s direct and s=%s through the proxy", got, direct, through)
		}
	}
	loaded := recordsOf(logRecords(t, log), "cookies loaded")
	if len(loaded) != 2 || loaded[0].get("proxy") != "" || !strings.Contains(loaded[0].get("from"), "set "+direct+",") ||
		loaded[1].get("proxy") != "http://"+proxy.addr || !strings.Contains(loaded[1].get("from"), "set "+through+",") {
		t.Errorf("the log says %v", loaded)
	}
}

func TestTheDaemonStopsAtAClientItCannotMake(t *testing.T) {
	failingClients(t, func(string) bool { return true })
	if code, _, stderr := exec(t, "daemon"); code != 1 || !strings.Contains(stderr, "the transport would not have it") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}

func TestEveryOutputOfARunNamesTheOneRun(t *testing.T) {
	// One id, and one moment it began: the log and the reports are named after
	// it and say it, and so do the trace, each request kept and the session
	// saved, so that what one run left can be told from another's and put
	// together again.
	// A clock a millisecond later each time it is read: the moment the run
	// began is one reading, and anything that read its own would say another.
	var ticks atomic.Int64
	original := now
	t.Cleanup(func() { now = original })
	now = func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(ticks.Add(1)) * time.Millisecond)
	}
	server := cookieEcho(t)
	dir := t.TempDir()
	out, trace, session := filepath.Join(dir, "out"), filepath.Join(dir, "trace.json"), filepath.Join(dir, "session.json")
	code, _, stderr := exec(t, "fetch", "-k", "-o", out, "--trace", trace, "--save-cookies", session,
		"--report", "--report-format", "html,json", server.URL+"/set")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	worn := resolved(t, defaultProfileName()).Name
	logs, err := filepath.Glob(filepath.Join(out, "run-*.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs %v, %v", logs, err)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(logs[0]), "run-"), ".log")

	logged, err := os.ReadFile(filepath.Join(out, "run-"+id+".log"))
	if err != nil || !strings.Contains(string(logged), "run_id="+id) {
		t.Errorf("the log does not say the run: %v\n%s", err, logged)
	}
	doc := decoded(t, []byte(reportOf(t, filepath.Join(out, "report-"+id+".json"))))
	if doc.Run != id || stamp(doc.Started) != id || doc.Profile != worn {
		t.Errorf("the JSON report says run %q, started %s, wearing %q", doc.Run, doc.Started, doc.Profile)
	}
	if page := reportOf(t, filepath.Join(out, "report-"+id+".html")); !strings.Contains(page, "run "+id+" · "+worn+" · ") {
		t.Errorf("the page does not say the run and what it wore")
	}
	begun := named(traceFile(t, trace), phaseBegin, "fetch")
	if len(begun) != 1 || begun[0].Args["run_id"] != id ||
		begun[0].Args["started"] != doc.Started.Format(time.RFC3339Nano) {
		t.Errorf("the trace begins %v", begun)
	}
	kept, err := filepath.Glob(filepath.Join(out, "127.0.0.1-*.log"))
	if err != nil || len(kept) != 1 {
		t.Fatalf("kept %v, %v", kept, err)
	}
	if data, err := os.ReadFile(kept[0]); err != nil ||
		!regexp.MustCompile(`(?m)^  run +`+regexp.QuoteMeta(id)+`$`).Match(data) {
		t.Errorf("the request kept says, %v:\n%s", err, data)
	}
	data, err := os.ReadFile(session)
	if err != nil {
		t.Fatalf("the session: %v", err)
	}
	if file, err := cookie.Load(data); err != nil || len(file.Sets) != 1 || file.Sets[0].Note != "direct, run "+id {
		t.Errorf("the session saved is %+v, %v", file, err)
	}
}
