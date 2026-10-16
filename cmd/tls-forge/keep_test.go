package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// What is kept of each request in the directory --output names.

// keptIn is what a directory holds, by name, in order.
func keptIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{err.Error()}
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestOutputKeepsThreeFilesForEveryRequest(t *testing.T) {
	// A clock that stands still, so what the files will be called is known
	// before the run.
	clock := fakeClock(t)
	server, _ := replying(t, 503, 200)
	dir := filepath.Join(t.TempDir(), "out")
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--repeat", "2", "-o", dir, "--report="+path, "--report-format", "json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	name := "127.0.0.1-" + stamp(clock.now())
	// And the log of the whole run, named for when it began.
	runLog := "run-" + stamp(clock.now()) + ".log"
	want := []string{
		name + "-1.log", name + "-1.txt", name + "-2.log", name + "-2.txt", runLog,
		"trace-" + name + "-1.json", "trace-" + name + "-2.json",
	}
	if got := keptIn(t, dir); !slices.Equal(got, want) {
		t.Fatalf("the directory holds %v, want %v", got, want)
	}

	// The first run was turned away with a 503, and its page is kept all the
	// same: what a server says when it refuses is the page worth reading.
	for run, page := range map[string]string{"1": "answer-1", "2": "answer-2"} {
		if kept, err := os.ReadFile(filepath.Join(dir, name+"-"+run+".txt")); err != nil || string(kept) != page {
			t.Errorf("run %s kept %q (%v), want %q", run, kept, err, page)
		}
	}
	log, err := os.ReadFile(filepath.Join(dir, name+"-1.log"))
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	for _, want := range []string{
		"GET " + server.URL + "\n",
		"  request  1 of 2\n",
		"  outcome  503 Service Unavailable · 8 B\n",
		"  page     " + filepath.Join(dir, name+"-1.txt") + "\n",
		"try 1 of 1: 503 Service Unavailable · 8 B",
		"request headers, as written",
		"the body began\n    answer-1\n",
	} {
		if !strings.Contains(string(log), want) {
			t.Errorf("the log has no %q:\n%s", want, log)
		}
	}
	events := traceFile(t, filepath.Join(dir, "trace-"+name+"-1.json"))
	checkShape(t, events)
	if began := one(t, events, phaseBegin, "GET "+server.URL); began.Args["request"] != 1.0 {
		t.Errorf("the request was traced as %+v", began)
	}

	// A report says where each request was kept, under the names a line uses.
	doc := decoded(t, []byte(reportOf(t, path)))
	first := doc.Requests[0]
	if first.File != filepath.Join(dir, name+"-1.txt") || first.Log != filepath.Join(dir, name+"-1.log") ||
		first.Trace != filepath.Join(dir, "trace-"+name+"-1.json") {
		t.Errorf("the report has the first request kept at %q, %q and %q", first.File, first.Log, first.Trace)
	}

	if runtime.GOOS != "windows" {
		// All of it is private, as a report and a trace of the whole run are:
		// what describes a request names where it went, and a page can be one
		// that only a session could open.
		for file, mode := range map[string]os.FileMode{
			name + "-1.txt": 0o600, name + "-1.log": 0o600, "trace-" + name + "-1.json": 0o600, runLog: 0o600,
		} {
			if info, err := os.Stat(filepath.Join(dir, file)); err != nil || info.Mode().Perm() != mode {
				t.Errorf("%s: mode %v (%v), want %v", file, info.Mode().Perm(), err, mode)
			}
		}
	}
}

func TestOutputKeepsALogAndATraceOfARequestThatGotNothing(t *testing.T) {
	// Nothing came back, so there is no page, and the log and the trace are
	// what there is to read about why.
	dir := filepath.Join(t.TempDir(), "out")

	code, _, stderr := exec(t, "fetch", "-o", dir, "--timeout", "3s", "https://127.0.0.1:1/gone")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	kept := keptIn(t, dir)
	if len(kept) != 3 || !strings.HasSuffix(kept[0], "-1.log") || !strings.HasPrefix(kept[1], "run-") ||
		!strings.HasPrefix(kept[2], "trace-127.0.0.1-") {
		t.Fatalf("the directory holds %v, want a log and a trace, and the run's log", kept)
	}
	log, _ := os.ReadFile(filepath.Join(dir, kept[0]))
	if !strings.Contains(string(log), "  outcome  no response · ") || !strings.Contains(string(log), "127.0.0.1:1") {
		t.Errorf("the log does not say why nothing came back:\n%s", log)
	}
	events := traceFile(t, filepath.Join(dir, kept[2]))
	checkShape(t, events)
	if ended := events[len(events)-1]; ended.Phase != phaseEnd || ended.Args["error"] == nil {
		t.Errorf("the trace ends as %+v", ended)
	}
}

func TestRequestName(t *testing.T) {
	when := time.Date(2026, 8, 16, 1, 9, 45, 123_000_000, time.UTC)
	for _, tc := range []struct{ url, want string }{
		// The host as it is written, without its port and in lower case.
		{"https://Example.COM:8443/path?q=1", "example.com-2026-08-16-010945-123-7"},
		// Anything a file name on some system cannot hold is an underscore.
		{"http://[2001:db8::1]:8080/", "2001_db8__1-2026-08-16-010945-123-7"},
		{"http://ünïcode.test/", "_n_code.test-2026-08-16-010945-123-7"},
		// No host to name it after.
		{"::not a URL::", "request-2026-08-16-010945-123-7"},
		{"mailto:somebody@example.test", "request-2026-08-16-010945-123-7"},
		// As long as a host may be kept whole; one more, and it is cut.
		{"https://" + strings.Repeat("a", maxNameHost) + "/", strings.Repeat("a", maxNameHost) + "-2026-08-16-010945-123-7"},
		{"https://" + strings.Repeat("a", maxNameHost+1) + "/",
			strings.Repeat("a", maxNameHost-9) + "_" + hostHash(strings.Repeat("a", maxNameHost+1)) + "-2026-08-16-010945-123-7"},
	} {
		if got := requestName(tc.url, when, 7); got != tc.want {
			t.Errorf("requestName(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// hostHash is the hash a cut host ends in.
func hostHash(host string) string {
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:4])
}

func TestRequestNameFitsAFileName(t *testing.T) {
	// A file name is 255 bytes at most, and a host may be longer than that
	// before a URL is refused: as long as DNS allows, in labels of 63, or a
	// thousand letters, or in a script that is a byte to each of its
	// characters only once it is underscores.
	when := time.Date(2026, 8, 16, 1, 9, 45, 123_000_000, time.UTC)
	label := strings.Repeat("x", 63)
	dns := strings.Join([]string{label, label, label, strings.Repeat("y", 61)}, ".")
	cyrillic := strings.Repeat("пример", 60) + ".рф"
	longest := slices.MaxFunc(slices.Collect(maps.Values(pageExtensions)), func(a, b string) int { return len(a) - len(b) })
	seen := map[string]string{}
	for _, host := range []string{dns, strings.Repeat("z", 1000), cyrillic, dns + "x"} {
		name := requestName("https://"+host+"/", when, math.MaxInt)
		for _, file := range []string{name + longest, name + ".log", "trace-" + name + ".json"} {
			if len(file) > 255 {
				t.Errorf("%d bytes for a host of %d: %s", len(file), len(host), file)
			}
		}
		if !utf8.ValidString(name) || strings.ContainsFunc(name, func(r rune) bool { return r > 0x7f }) {
			t.Errorf("%q is not ASCII", name)
		}
		// Hosts that begin alike are told apart by the hash of the whole.
		if other, ok := seen[name]; ok {
			t.Errorf("%q and %q are kept under one name", host, other)
		}
		seen[name] = host
	}

	// And a file of that name can be made.
	name := requestName("https://"+strings.Repeat("z", 1000)+"/", when, math.MaxInt)
	if err := os.WriteFile(filepath.Join(t.TempDir(), "trace-"+name+".json"), nil, 0o600); err != nil {
		t.Errorf("the name of a request's trace cannot be a file's: %v", err)
	}
}

// keptRequest is a request with a little of everything in it: a try refused
// and waited after, a redirect, and a try that got the page.
func keptRequest() (result, job, requestAbout) {
	const ms = time.Millisecond
	started := time.Date(2026, 3, 4, 9, 30, 0, 12_000_000, time.UTC)
	r := result{
		URL: "https://example.test/a", Proxy: "http://user:s3cr3t@proxy.test:8080",
		Started: started, Ended: started.Add(400 * ms), Status: 200, Bytes: 577, Attempts: 2, Run: 2,
		FinalURL: "https://example.test/b", File: "out/example.test-2026-03-04-093000-012-3.html",
		ID: 3, Exit: egress{IP: "203.0.113.7", Country: "pl"},
		Tries: []try{
			{
				Began: started, Took: 100 * ms, Status: 503, Bytes: 19, Wait: 250 * ms,
				Answer: "retry-after: 1\nserver: test", Body: "<h1>slow down</h1>",
				Connected: true, Conn: tlsforge.ConnInfo{RemoteAddr: "198.51.100.7:8080", TLSVersion: "TLS 1.3",
					CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2"},
				Steps: []step{
					{Name: "dns", Took: 2 * ms, Note: "proxy.test → 198.51.100.7"},
					{Name: "send", From: 2 * ms, Written: ":method: GET\ncookie: session=***"},
					{Name: "wait", From: 2 * ms, Took: 98 * ms},
				},
			},
			{
				Began: started.Add(350 * ms), Took: 50 * ms, Status: 200, Bytes: 577,
				Connected: true, Conn: tlsforge.ConnInfo{Reused: true, RemoteAddr: "198.51.100.7:8080"},
				Steps: []step{
					{Name: "send", Took: ms, Note: "on the connection already open to 198.51.100.7:8080",
						Written: ":method: GET"},
					{Name: "wait", From: ms, Took: 20 * ms},
					{Name: redirectStep, From: 21 * ms, Note: "301 → https://example.test/b"},
					{Name: "send", From: 22 * ms, Took: ms, Written: ":method: GET\n:path: /b"},
					{Name: "receive", From: 23 * ms, Took: 27 * ms, Cut: true},
				},
			},
		},
	}
	about := requestAbout{method: "GET", profile: "chrome_155_macos", run: "2026-10-16-120000-000", requests: 6, runs: 2}
	return r, job{id: 3, run: 2}, about
}

func TestRequestLog(t *testing.T) {
	r, j, about := keptRequest()
	log := requestLog(r, j, about)
	for _, want := range []string{
		"GET https://example.test/a\n\n",
		"  request    3 of 6\n",
		// A list gone through twice: which pass this was.
		"  pass       2 of 2\n",
		"  run        2026-10-16-120000-000\n",
		"  profile    chrome_155_macos\n",
		"  proxy      http://user@proxy.test:8080\n",
		"  exit-ip    203.0.113.7 · PL\n",
		"  started    04 Mar 2026 09:30:00.012\n",
		"  took       400ms\n",
		"  outcome    200 OK · 577 B\n",
		"  tries      2\n",
		"  final URL  https://example.test/b\n",
		"  page       out/example.test-2026-03-04-093000-012-3.html\n",
		"\ntry 1 of 2: 503 Service Unavailable · 19 B, 100ms\n",
		"  connection  new connection to 198.51.100.7:8080 · TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2\n",
		"  dns         2.0ms  proxy.test → 198.51.100.7\n",
		// Nothing to say, and nothing left at the end of the line for it.
		"  send          0µs\n",
		"\n  request headers, as written\n    :method: GET\n    cookie: session=***\n",
		"\n  response headers\n    retry-after: 1\n    server: test\n",
		"\n  the body began\n    <h1>slow down</h1>\n",
		"\n  then 250ms of waiting before the next try\n",
		"\ntry 2 of 2: 200 OK · 577 B, 50ms\n",
		"  connection  connection already open to 198.51.100.7:8080\n",
		// A redirect is a moment, and has no length to give.
		"  redirect           301 → https://example.test/b\n",
		"  receive      27ms  the try ended here\n",
		// A redirect sent the request twice, so the two are numbered.
		"\n  request headers, as written (1 of 2)\n    :method: GET\n",
		"\n  request headers, as written (2 of 2)\n    :method: GET\n    :path: /b\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the log has no %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "s3cr3t") {
		t.Errorf("the log holds a password:\n%s", log)
	}
	for i, line := range strings.Split(log, "\n") {
		if strings.TrimRight(line, " ") != line {
			t.Errorf("line %d ends in spaces: %q", i+1, line)
		}
	}

	// A request made once, of one made several times: which run it was is
	// already its number. One that never went out has nothing more to say.
	one := requestLog(result{URL: "https://example.test/", Error: "no such proxy", Started: r.Started, Ended: r.Started},
		job{id: 2, run: 2}, requestAbout{method: "GET", profile: "chrome", requests: 3, runs: 3})
	for _, unwanted := range []string{"pass", "exit-ip", "try 1", "page"} {
		if strings.Contains(one, unwanted) {
			t.Errorf("the log of a request that never went out has %q:\n%s", unwanted, one)
		}
	}
	if !strings.Contains(one, "  outcome  no response · no such proxy\n") || !strings.Contains(one, "  proxy    direct\n") {
		t.Errorf("the log of a request that never went out:\n%s", one)
	}

	// Asked where it came out, and nobody could say.
	r.Exit, r.ExitError = egress{}, "nobody answered"
	if log := requestLog(r, j, about); !strings.Contains(log, "  exit-ip    unknown · nobody answered\n") {
		t.Errorf("the log of a request whose address nobody knew:\n%s", log)
	}
}

func TestRequestTrace(t *testing.T) {
	r, _, about := keptRequest()
	events := requestTrace(r, about.method)
	// Everything a viewer needs to put the bars inside one another.
	checkShape(t, events)

	if events[1].Args["name"] != "request 3" {
		t.Errorf("the row is called %v", events[1].Args["name"])
	}
	began := one(t, events, phaseBegin, "GET https://example.test/a")
	if began.Args["request"] != 3 || began.Args["run"] != 2 || began.Args["proxy"] != "http://user@proxy.test:8080" {
		t.Errorf("the request begins as %+v", began)
	}
	for _, name := range []string{"try 1", "try 2"} {
		one(t, events, phaseBegin, name)
	}
	// A step that took no time is drawn a microsecond long rather than dropped.
	sent := named(events, phaseComplete, "send")
	if len(sent) != 3 || sent[0].Dur != 1 || sent[0].Args["headers"] == nil {
		t.Errorf("the sends were traced as %+v", sent)
	}
	if cut := one(t, events, phaseComplete, "receive"); cut.Args["unfinished"] != true {
		t.Errorf("the step the try ended in was traced as %+v", cut)
	}
	if moved := one(t, events, phaseInstant, redirectStep); moved.Args["note"] != "301 → https://example.test/b" {
		t.Errorf("the redirect was traced as %+v", moved)
	}
	if waited := one(t, events, phaseInstant, "retry"); waited.Args["wait_ms"] != int64(250) {
		t.Errorf("the wait was traced as %+v", waited)
	}
	if ended := events[len(events)-1]; ended.Args["status"] != 200 || ended.Args["file"] != r.File ||
		ended.Args["exit_ip"] != "203.0.113.7" || ended.Args["exit_country"] != "PL" {
		t.Errorf("the request ends as %+v", ended)
	}
	refused := named(events, phaseEnd, "")[0]
	if refused.Args["status"] != 503 || refused.Args["body"] != "<h1>slow down</h1>" || refused.Args["headers"] == nil {
		t.Errorf("the first try ends as %+v", refused)
	}

	// A request that never went out is the request alone, and why.
	gone := requestTrace(result{URL: "https://example.test/", Error: "no such proxy", Started: r.Started, Ended: r.Started,
		ID: 1}, about.method)
	checkShape(t, gone)
	if ended := gone[len(gone)-1]; len(gone) != 4 || ended.Args["error"] != "no such proxy" || ended.Args["exit_ip"] != nil {
		t.Errorf("a request that never went out is traced as %+v", gone)
	}
	// An address without a country is the address alone.
	r.Exit = egress{IP: "203.0.113.7"}
	if ended := requestTrace(r, about.method); ended[len(ended)-1].Args["exit_country"] != nil {
		t.Errorf("a country was made up for %+v", ended[len(ended)-1])
	}
}

func TestKeepRequestReportsAFileItCannotWrite(t *testing.T) {
	// Every one of the three, so that whichever fails, the run hears of it.
	r, j, about := keptRequest()
	for _, blocked := range []string{".html", ".log", ".json"} {
		dir := t.TempDir()
		name := requestName(r.URL, r.Started, j.id)
		target := filepath.Join(dir, name+blocked)
		if blocked == ".json" {
			target = filepath.Join(dir, "trace-"+name+blocked)
		}
		// A directory where the file would go.
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		r := r
		page := &tlsforge.Response{Status: 200, Header: map[string][]string{"Content-Type": {"text/html"}}, Body: []byte("page")}
		err := keepRequest(dir, &r, page, j, about, nil)
		var notAFile *os.PathError
		if !errors.As(err, &notAFile) {
			t.Errorf("with %s in the way: %v", blocked, err)
		}
	}
}
