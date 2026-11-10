package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// agentServer answers each request with the User-Agent it came with, which is
// the profile it wore as a server sees it.
func agentServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, r.UserAgent())
	}))
	t.Cleanup(server.Close)
	return server
}

// drawing makes the profiles a run draws repeatable.
func drawing(t *testing.T, seed int64) {
	t.Helper()
	original := pickProfile
	t.Cleanup(func() { pickProfile = original })
	pickProfile = rand.New(rand.NewSource(seed))
}

// keptAs writes a shipped profile into the profiles directory under another
// name, the replacements made in its JSON: a profile kept on this machine.
func keptAs(t *testing.T, dir, name string, replace ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "profile", "data", "chrome_156", "linux.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(data), `"name": "chrome_156_linux"`, `"name": "`+name+`"`, 1)
	for i := 0; i+1 < len(replace); i += 2 {
		if !strings.Contains(text, replace[i]) {
			t.Fatalf("no %s in the profile", replace[i])
		}
		text = strings.Replace(text, replace[i], replace[i+1], 1)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEachRequestWearsAProfileDrawnForIt(t *testing.T) {
	keepProfilesIn(t)
	drawing(t, 7)
	server := agentServer(t)
	var urls []string
	for i := range 24 {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}
	code, stdout, stderr := exec(t, append([]string{"fetch", "--random-profile", "--insecure", "--progress", "never",
		"-c", "4"}, urls...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	names := map[string]bool{}
	for _, p := range wearable() {
		names[p.Name] = true
	}
	worn := map[string]int{}
	for url, r := range lines(t, stdout) {
		// The profile the line says is the one the server saw, and one of
		// those it was drawn from.
		if !names[r.Profile] || r.Body != resolved(t, r.Profile).UserAgent {
			t.Errorf("%s said it wore %q, and the server saw %q", url, r.Profile, r.Body)
		}
		worn[r.Profile]++
	}
	if len(worn) < 4 {
		t.Errorf("24 requests wore %d profiles: %v", len(worn), worn)
	}
	for _, want := range []string{"profile     random · each request wears one of " + fmt.Sprint(len(names)) + ", drawn for it",
		"profiles    chrome_151_linux, chrome_151_macos,", fmt.Sprintf("from        %d shipped with tls-forge\n", len(names)),
		"tcp/ip      this machine's, " + platformLabel(profile.HostPlatform()) + ": 14 of the 21 are another platform's"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the header does not say %q:\n%s", want, stderr)
		}
	}
}

func TestARequestDrawsItsProfileOnceForAllOfItsTries(t *testing.T) {
	keepProfilesIn(t)
	drawing(t, 3)
	asked := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Turned away the first time each URL is asked for.
		if !asked[r.URL.Path] {
			asked[r.URL.Path] = true
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = fmt.Fprint(w, r.UserAgent())
	}))
	t.Cleanup(server.Close)
	var urls []string
	for i := range 8 {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}
	dir := t.TempDir()
	code, stdout, stderr := exec(t, append([]string{"fetch", "--random-profile", "--insecure", "--progress", "never",
		"-c", "1", "--retry", "1", "--repeat", "2", "-o", dir, "--report", "--log", filepath.Join(dir, "run.jsonl")}, urls...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	var said []result
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		said = append(said, r)
	}
	if len(said) != 16 {
		t.Fatalf("%d lines for 16 requests:\n%s", len(said), stdout)
	}
	for _, r := range said {
		// Its second try wears what its first did: the page kept is that
		// profile's.
		page, err := os.ReadFile(r.File)
		if err != nil || string(page) != resolved(t, r.Profile).UserAgent {
			t.Errorf("%s, run %d, wore %s and came back as %q (%v)", r.URL, r.Run, r.Profile, page, err)
		}
	}

	// The log says the run draws, and each result what it wore.
	records := logRecords(t, filepath.Join(dir, "run.jsonl"))
	runs := recordsOf(records, "run")
	if len(runs) != 1 || runs[0].get("profile") != "random" || !strings.Contains(runs[0].get("profiles"), "chrome_156_linux") {
		t.Errorf("the run record: %v", runs)
	}
	for _, r := range recordsOf(records, "result") {
		if !strings.HasPrefix(r.get("profile"), "chrome_") {
			t.Errorf("a result record says no profile: %v", r)
		}
	}
	// Each kept request says the profile it wore, as do the reports.
	kept, _ := filepath.Glob(filepath.Join(dir, "*-logs.log"))
	if len(kept) != 16 {
		t.Fatalf("%d requests kept", len(kept))
	}
	for _, file := range kept {
		data, _ := os.ReadFile(file)
		if !regexp.MustCompile(`(?m)^\s*profile\s+chrome_`).Match(data) {
			t.Errorf("%s says no profile it wore:\n%s", file, data)
		}
	}
	reports, _ := filepath.Glob(filepath.Join(dir, "report-*.html"))
	if len(reports) != 1 {
		t.Fatalf("reports: %v", reports)
	}
	page, _ := os.ReadFile(reports[0])
	if !strings.Contains(string(page), "random") || !strings.Contains(string(page), ">Profile</dt>") {
		t.Error("the report does not say the run drew its profiles, or what a request wore")
	}
}

func TestARunDrawsFromTheProfilesKeptHereThatItCanWear(t *testing.T) {
	dir := keepProfilesIn(t)
	// One of this machine's, which it draws; one made for another engine,
	// which it cannot wear; and one that would send a POST as given, where the
	// newest Chrome sends it as an XHR of its own page: drawn only when the
	// requests do not depend on that.
	keptAs(t, dir, "mine")
	keptAs(t, dir, "older", `"engine_major": 2`, `"engine_major": 0`)
	keptAs(t, dir, "plain", `"headers.without_context": "typed-navigation"`, `"headers.without_context": "as-given"`)
	var names []string
	for _, p := range wearable() {
		names = append(names, p.Name)
	}
	if !slices.Contains(names, "mine") || !slices.Contains(names, "plain") || slices.Contains(names, "older") ||
		slices.Contains(names, "firefox_148") {
		t.Fatalf("drawn from %v", names)
	}

	drawing(t, 1)
	server := agentServer(t)
	code, _, stderr := exec(t, "fetch", "--random-profile", "--insecure", "-X", "POST", "-d", "a=1", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	want := fmt.Sprintf("one of %d, drawn for it", len(names)-1)
	if !strings.Contains(stderr, want) || strings.Contains(stderr, "plain") ||
		!strings.Contains(stderr, fmt.Sprintf("from        %d shipped with tls-forge, 1 kept on this machine", len(names)-2)) {
		t.Errorf("did not draw from all but plain:\n%s", stderr)
	}
}

func TestRandomProfileRefusesWhatOneBrowserDoes(t *testing.T) {
	keepProfilesIn(t)
	for _, tc := range []struct {
		args []string
		said string
	}{
		{[]string{"--profile", "chrome_155"}, "--profile and --random-profile both say what the requests wear"},
		{[]string{"--reuse-connection"}, "--reuse-connection keeps a URL's connection for its repeats"},
		{[]string{"--retry", "1", "--retry-as-browser"}, "isolates every request"},
	} {
		args := append(append([]string{"fetch", "--random-profile"}, tc.args...), "https://"+deadAddr(t)+"/")
		if code, _, stderr := exec(t, args...); code != 2 || !strings.Contains(stderr, tc.said) {
			t.Errorf("%v: exit %d:\n%s", tc.args, code, stderr)
		}
	}
}

func TestTheRunTraceSaysTheProfilesItDrawsFrom(t *testing.T) {
	keepProfilesIn(t)
	server := agentServer(t)
	trace := filepath.Join(t.TempDir(), "trace.json")
	if code, _, stderr := exec(t, "fetch", "--random-profile", "--insecure", "--trace", trace, server.URL+"/"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	data, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"drawn_from":["chrome_151_linux"`) || !strings.Contains(string(data), `"name":"random"`) {
		t.Errorf("the trace does not say what the run draws from:\n%.2000s", data)
	}
}
