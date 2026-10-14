package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// A report in more than one format: which, where each goes, and what the one
// for programs holds.

// reportFlagsFrom parses a command line down to its report flags.
func reportFlagsFrom(t *testing.T, args ...string) reportFlags {
	t.Helper()
	fs := newFlagSet("fetch", newPrinter(io.Discard))
	flags := addReportFlags(fs)
	if err := parse(fs, args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return flags
}

func TestReportFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"no report asked for", nil, nil},
		// The page unless somebody asks for the document, whatever the file is
		// called.
		{"the flag alone", []string{"--report"}, []string{"html"}},
		{"its letter alone", []string{"-R"}, []string{"html"}},
		{"a page by name", []string{"--report=run.html"}, []string{"html"}},
		{"a page into a file called json", []string{"--report=run.json"}, []string{"html"}},
		{"a document", []string{"--report", "--report-format", "json"}, []string{"json"}},
		{"both", []string{"--report=run", "--report-format", "html,json"}, []string{"html", "json"}},
		// In the order given, once each, however they are spaced and cased.
		{"both, untidily", []string{"--report=run", "--report-format", " JSON , html,json"}, []string{"json", "html"}},
	} {
		got, err := reportFlagsFrom(t, tc.args...).formats()
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: formats = %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}

	// A word that is not a format, and a list with a hole in it, are said to be
	// that. One of them is a typo away from the other.
	// Two formats there are, and no third that guesses between them.
	for _, bad := range []string{"pdf", "html,", "html;json", "", "auto"} {
		_, err := reportFlagsFrom(t, "--report=run", "--report-format", bad).formats()
		var refused *badFlag
		if !errors.As(err, &refused) || !strings.Contains(err.Error(), "--report-format") {
			t.Errorf("--report-format %q: %v", bad, err)
		}
	}
	// And a format for a report nobody asked for is a mistake rather than
	// something to ignore: the report it was meant for would not be written.
	if _, err := reportFlagsFrom(t, "--report-format", "json").formats(); !errors.Is(err, errUsage) {
		t.Errorf("a format with no report: %v", err)
	}
}

func TestReportFiles(t *testing.T) {
	when := time.Date(2026, 8, 16, 1, 9, 45, 123_000_000, time.UTC)
	dir := t.TempDir()
	both := []string{"html", "json"}
	paths := func(files []reportFile) []string {
		var out []string
		for _, file := range files {
			out = append(out, file.format+" "+file.path)
		}
		return out
	}
	in := func(name string) string { return filepath.Join(dir, name) }

	for _, tc := range []struct {
		name    string
		given   string
		formats []string
		want    []string
	}{
		// Given no path, beside what the run kept, and here when it kept nothing.
		{"no path, beside the requests", reportBeside, both, []string{
			"html " + in("report-"+stamp(when)+".html"), "json " + in("report-"+stamp(when)+".json"),
		}},
		// A directory names each of them after the same moment.
		{"a directory", dir, both, []string{
			"html " + in("report-"+stamp(when)+".html"), "json " + in("report-"+stamp(when)+".json"),
		}},
		{"a directory that is yet to be made", in("runs") + string(os.PathSeparator), []string{"json"}, []string{
			"json " + filepath.Join(dir, "runs", "report-"+stamp(when)+".json"),
		}},
		// One format goes to the path as given, whatever that is called.
		{"one, as named", in("run.html"), []string{"html"}, []string{"html " + in("run.html")}},
		{"one, into a file named for the other", in("run.html"), []string{"json"}, []string{"json " + in("run.html")}},
		// Two cannot, so the path names them both.
		{"two, from a name with one of their extensions", in("run.html"), both, []string{
			"html " + in("run.html"), "json " + in("run.json"),
		}},
		{"two, in the order asked for", in("run.JSON"), []string{"json", "html"}, []string{
			"json " + in("run.json"), "html " + in("run.html"),
		}},
		{"two, from a bare name", in("run"), both, []string{"html " + in("run.html"), "json " + in("run.json")}},
		// An extension that is not one of theirs is part of the name.
		{"two, from a name with some other extension", in("run.2026.txt"), both, []string{
			"html " + in("run.2026.txt.html"), "json " + in("run.2026.txt.json"),
		}},
	} {
		if got := paths(reportFiles(tc.given, dir, tc.formats, when)); !slices.Equal(got, tc.want) {
			t.Errorf("%s:\n got %v\nwant %v", tc.name, got, tc.want)
		}
	}
	if got := paths(reportFiles(reportBeside, "", []string{"html"}, when)); !slices.Equal(got, []string{
		"html report-" + stamp(when) + ".html",
	}) {
		t.Errorf("no path and nothing kept: %v, want the current directory", got)
	}
}

func TestReportWithoutAPathGoesBesideTheRequests(t *testing.T) {
	server, _ := replying(t, 200)

	// Into the directory the requests were kept in.
	kept := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "-o", kept, "--report", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	reports, _ := filepath.Glob(filepath.Join(kept, "report-*.html"))
	if len(reports) != 1 || !strings.HasSuffix(stderr, "\n  Report        "+reports[0]+"\n") {
		t.Errorf("the directory holds %v, and stderr names:\n%s", keptIn(t, kept), stderr)
	}

	// And into the current directory when there is none: wherever the command
	// was run, which for this test is a directory of its own.
	here := t.TempDir()
	t.Chdir(here)
	code, _, stderr = exec(t, "fetch", "-R", "--report-format", "json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	written := keptIn(t, here)
	if len(written) != 1 || !strings.HasPrefix(written[0], "report-") || !strings.HasSuffix(written[0], ".json") ||
		!strings.HasSuffix(stderr, "\n  report written to "+written[0]+"\n") {
		t.Errorf("the current directory holds %v, and stderr names:\n%s", written, stderr)
	}
}

func TestReportPathAfterASpaceIsTakenForAURL(t *testing.T) {
	// The flag needs no path, so what follows it after a space is the next
	// argument. When that is not a URL, the likeliest reason is said.
	server, asked := replying(t, 200)
	code, _, stderr := exec(t, "fetch", "--report", "reports/", server.URL)
	if code != 1 || !strings.Contains(stderr, "--report=PATH") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by a command that was refused", got)
	}
	// Not when the flag was given a path, which leaves nothing to suspect.
	_, _, stderr = exec(t, "fetch", "--report=run.html", "not-a-url")
	if strings.Contains(stderr, "--report=PATH") {
		t.Errorf("the path that was given is suspected all the same: %q", stderr)
	}
}

// decoded reads a report document back.
func decoded(t *testing.T, data []byte) reportDocument {
	t.Helper()
	var doc reportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the report is not JSON: %v\n%s", err, data)
	}
	return doc
}

func TestReportAsJSON(t *testing.T) {
	const ms = time.Millisecond
	clock := fakeClock(t)
	started := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	clock.at = started.Add(time.Minute)
	const proxy = "http://user:s3cr3t@proxy.test:8080"

	records := []result{
		// Out of order on purpose: the document puts them back in the order the
		// requests went out, as the page does.
		{
			URL: "https://example.test/b?x=1&y=2", Proxy: proxy, Started: started.Add(time.Second),
			Ended: started.Add(1400 * ms), Millis: 400, Status: 200, FinalURL: "https://example.test/b/",
			Bytes: 577, File: "page-2.html", Run: 2, Attempts: 2,
			Tries: []try{
				{
					Began: started.Add(time.Second), Took: 100300 * time.Microsecond, Status: 503, Bytes: 19,
					Wait: 250 * ms, Answer: "Retry-After: 1\nServer: test", Body: "<h1>slow down</h1>",
					Connected: true, Conn: tlsforge.ConnInfo{
						RemoteAddr: "198.51.100.7:8080", TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
						ALPN: "h2", Resumed: true,
					},
					Steps: []step{
						{Name: "dns", Took: 1900 * time.Microsecond, Note: "example.test → 192.0.2.1"},
						{Name: "send", From: 10 * ms, Took: 65 * time.Microsecond, Written: ":method: GET\ncookie: session=***"},
						{Name: "wait", From: 10065 * time.Microsecond, Took: 90 * ms},
					},
				},
				{
					Began: started.Add(1350 * ms), Took: 50 * ms, Error: "connection reset",
					Steps: []step{{Name: "send", Took: 50 * ms, Cut: true}},
				},
			},
		},
		{
			URL: "https://example.test/a", Started: started, Ended: started.Add(300 * ms),
			Millis: 300, Attempts: 1, Error: "no route to host",
		},
		{URL: "https://example.test/c", Started: started.Add(2 * time.Second), Status: 404, Millis: 200, Attempts: 1},
	}
	exits := map[string]egress{proxy: {IP: "203.0.113.7", Country: "pl"}}
	var out strings.Builder
	if err := renderReportJSON(&out, "fetch", records, summarise(records, 3*time.Second, exits), exits); err != nil {
		t.Fatalf("renderReportJSON: %v", err)
	}
	raw := out.String()
	doc := decoded(t, []byte(raw))

	if doc.Command != "fetch" || doc.Version != version || !doc.Generated.Equal(clock.now()) {
		t.Errorf("the document is headed %q %q %s", doc.Command, doc.Version, doc.Generated)
	}
	wantSummary := documentSummary{
		Requests: 3, Scraped: 1, Not2xx: 1, NoResponse: 1, SuccessRate: 33.3,
		Bytes: 577, Retries: 1, ElapsedMS: 3000, AvgMS: 300,
	}
	if doc.Summary != wantSummary {
		t.Errorf("summary = %+v, want %+v", doc.Summary, wantSummary)
	}
	// The one proxy, without its password, with what came back through it and
	// where it came out.
	if len(doc.Proxies) != 1 {
		t.Fatalf("proxies = %+v", doc.Proxies)
	}
	if p := doc.Proxies[0]; p.Proxy != "http://user@proxy.test:8080" || p.Requests != 1 || p.CameBack != 1 || !p.Alive ||
		p.Exit == nil || *p.Exit != (documentExit{IP: "203.0.113.7", Country: "PL"}) {
		t.Errorf("the proxy is written as %+v, out of %+v", p, p.Exit)
	}
	if strings.Contains(raw, "s3cr3t") {
		t.Errorf("the document holds a password:\n%s", raw)
	}

	// In the order they went out.
	var urls []string
	for _, r := range doc.Requests {
		urls = append(urls, r.URL)
	}
	if want := []string{"https://example.test/a", "https://example.test/b?x=1&y=2", "https://example.test/c"}; !slices.Equal(urls, want) {
		t.Fatalf("requests = %v", urls)
	}
	failed, page := doc.Requests[0], doc.Requests[1]
	// A request is the line of JSON written for it, under the names it has there.
	if failed.Error != "no route to host" || failed.Millis != 300 || failed.Exit != nil || failed.Tries != nil {
		t.Errorf("the request that failed is written as %+v", failed)
	}
	if page.Status != 200 || page.FinalURL != "https://example.test/b/" || page.Bytes != 577 || page.File != "page-2.html" ||
		page.Run != 2 || page.Attempts != 2 || page.Proxy != "http://user@proxy.test:8080" ||
		!page.Started.Equal(started.Add(time.Second)) || page.Exit == nil || page.Exit.IP != "203.0.113.7" {
		t.Errorf("the request that got its page is written as %+v", page)
	}

	if len(page.Tries) != 2 {
		t.Fatalf("tries = %+v", page.Tries)
	}
	first, second := page.Tries[0], page.Tries[1]
	wantConn := documentConnection{
		Remote: "198.51.100.7:8080", TLS: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ALPN: "h2", Resumed: true,
	}
	if first.MS != 100.3 || first.Status != 503 || first.Bytes != 19 || first.WaitMS != 250 ||
		first.Connection == nil || *first.Connection != wantConn || first.BodyStart != "<h1>slow down</h1>" ||
		!slices.Equal(first.ResponseHeaders, []string{"Retry-After: 1", "Server: test"}) {
		t.Errorf("the first try is written as %+v", first)
	}
	if len(first.Steps) != 3 {
		t.Fatalf("steps = %+v", first.Steps)
	}
	if lookup := first.Steps[0]; lookup.Name != "dns" || lookup.FromMS != 0 || lookup.MS != 1.9 ||
		lookup.Note != "example.test → 192.0.2.1" || lookup.RequestHeaders != nil {
		t.Errorf("the lookup is written as %+v", lookup)
	}
	// The request as it went out, a field to an entry, in the order written.
	if sent := first.Steps[1]; sent.FromMS != 10 || sent.MS != 0.065 ||
		!slices.Equal(sent.RequestHeaders, []string{":method: GET", "cookie: session=***"}) {
		t.Errorf("the sending is written as %+v", sent)
	}
	if second.Error != "connection reset" || second.Connection != nil || second.WaitMS != 0 ||
		len(second.Steps) != 1 || !second.Steps[0].Unfinished {
		t.Errorf("the try that got nothing is written as %+v", second)
	}

	// For whoever opens it as well: indented, and with a URL and a page left as
	// they are rather than escaped for a browser that will never see them.
	for _, want := range []string{
		"\n  \"summary\": {\n", `"url": "https://example.test/b?x=1&y=2"`, `"body_start": "<h1>slow down</h1>"`,
		`"success_rate": 33.3`, `"from_ms": 10.065`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the document has no %q:\n%s", want, raw)
		}
	}
	// What was not there is left out rather than written as nothing.
	for _, absent := range []string{`"body"`, `"Tries"`, `"tries": null`, `"unfinished": false`, `"wait_ms": 0`} {
		if strings.Contains(raw, absent) {
			t.Errorf("the document has %q", absent)
		}
	}
}

func TestReportAsJSONOfNothing(t *testing.T) {
	// A run of nothing made no requests, which is a list of none and a rate of
	// none, not a null and a division by zero.
	var out strings.Builder
	if err := renderReportJSON(&out, "fetch", nil, summarise(nil, time.Second, nil), nil); err != nil {
		t.Fatalf("renderReportJSON: %v", err)
	}
	if raw := out.String(); !strings.Contains(raw, `"requests": []`) || !strings.Contains(raw, `"success_rate": 0`) ||
		strings.Contains(raw, "proxies") {
		t.Errorf("the document of nothing:\n%s", raw)
	}

	err := renderReportJSON(failingWriter{}, "fetch", nil, summary{}, nil)
	if err == nil || !strings.Contains(err.Error(), "fetch: writing the report") {
		t.Errorf("a document that could not be written: %v", err)
	}
}

func TestFetchWritesAReportAsJSON(t *testing.T) {
	server, _ := replying(t, 503, 200, 200)
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--retry", "1", "--report="+path,
		"--report-format", "json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if want := "\n  Report        " + path + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming the report (%q):\n%s", want, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	doc := decoded(t, data)
	if doc.Command != "fetch" || doc.Summary.Requests != 2 || doc.Summary.Scraped != 2 || doc.Summary.Retries != 1 ||
		doc.Summary.SuccessRate != 100 {
		t.Errorf("the document is headed %q, with %+v", doc.Command, doc.Summary)
	}
	if len(doc.Requests) != 2 {
		t.Fatalf("requests = %+v", doc.Requests)
	}
	first, second := doc.Requests[0], doc.Requests[1]
	if first.Run != 1 || second.Run != 2 || first.URL != server.URL || first.Status != 200 || first.Attempts != 2 {
		t.Errorf("the runs are written as %+v and %+v", first, second)
	}
	// Where it came out, from the lookup the run had already made.
	if first.Exit == nil || first.Exit.IP != "203.0.113.7" || first.Exit.Country != "PL" {
		t.Errorf("the exit address is written as %+v", first.Exit)
	}
	// The first run was refused and then answered: two tries, each with what it
	// went out on, what it sent and what came back.
	if len(first.Tries) != 2 || len(second.Tries) != 1 {
		t.Fatalf("tries = %d and %d, want 2 and 1", len(first.Tries), len(second.Tries))
	}
	refused, answered := first.Tries[0], first.Tries[1]
	if refused.Status != 503 || refused.BodyStart != "answer-1" || answered.Status != 200 || answered.BodyStart != "" {
		t.Errorf("the tries ended as %+v and %+v", refused, answered)
	}
	if refused.Connection == nil || refused.Connection.Reused || answered.Connection == nil || !answered.Connection.Reused {
		t.Errorf("the connections are written as %+v and %+v", refused.Connection, answered.Connection)
	}
	sent := slices.IndexFunc(refused.Steps, func(s documentStep) bool { return s.Name == "send" })
	if sent < 0 || len(refused.Steps[sent].RequestHeaders) == 0 || len(refused.ResponseHeaders) == 0 {
		t.Errorf("the first try has no request or no answer: %+v", refused)
	}
	// Private, as the page is: it names every URL the run asked for.
	if info, err := os.Stat(path); err != nil || (info.Mode().Perm() != 0o600 && os.PathSeparator == '/') {
		t.Errorf("the document's permissions: %v, %v", info.Mode().Perm(), err)
	}
}

func TestFetchWritesBothReports(t *testing.T) {
	server, _ := replying(t, 200)
	dir := t.TempDir()

	// Into a directory, where each is named after the same moment.
	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--report="+dir, "--report-format", "html,json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	pages, _ := filepath.Glob(filepath.Join(dir, "report-*.html"))
	documents, _ := filepath.Glob(filepath.Join(dir, "report-*.json"))
	if len(pages) != 1 || len(documents) != 1 {
		t.Fatalf("the directory holds %v and %v, want one of each", pages, documents)
	}
	if strings.TrimSuffix(pages[0], ".html") != strings.TrimSuffix(documents[0], ".json") {
		t.Errorf("the two are not named after the same moment: %s and %s", pages[0], documents[0])
	}
	// Both named, in the order they were asked for.
	if want := "\n  Report        " + pages[0] + "\n  Report        " + documents[0] + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming both (%q):\n%s", want, stderr)
	}
	if html := reportOf(t, pages[0]); !strings.Contains(html, "2 of 2 requests") {
		t.Error("the page is not the report of the run")
	}
	if doc := decoded(t, []byte(reportOf(t, documents[0]))); doc.Summary.Requests != 2 {
		t.Errorf("the document is not the report of the run: %+v", doc.Summary)
	}

	// One request, and a name for the two of them to share.
	base := filepath.Join(dir, "single.html")
	code, _, stderr = exec(t, "fetch", "--report="+base, "--report-format", "json,html", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	want := fmt.Sprintf("\n  report written to %s\n  report written to %s\n", filepath.Join(dir, "single.json"), base)
	if !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming both (%q):\n%s", want, stderr)
	}
}

func TestFetchReportFormatsAreCheckedBeforeTheRun(t *testing.T) {
	server, asked := replying(t, 200)
	path := filepath.Join(t.TempDir(), "run")

	code, _, stderr := exec(t, "fetch", "--report="+path, "--report-format", "pdf", server.URL)
	if code != 1 || !strings.Contains(stderr, "--report-format") || !strings.Contains(stderr, "pdf") {
		t.Errorf("an unknown format: exit code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = exec(t, "fetch", "--report-format", "json", server.URL)
	if code != 2 || !strings.Contains(stderr, "--report-format requires --report") {
		t.Errorf("a format with no report: exit code = %d, stderr = %q", code, stderr)
	}
	code, _, _ = exec(t, "fetch", "--report="+path, "--report-format", "pdf", server.URL)
	if code != 1 {
		t.Errorf("a list with an unknown format: exit code = %d", code)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("%d requests were made by commands that were refused", got)
	}
}

func TestOneReportIsWrittenWhenTheOtherCannotBe(t *testing.T) {
	// The document's name is taken by a directory, so only the page can be
	// written. It is named all the same, beside the reason its companion is not.
	dir := t.TempDir()
	base := filepath.Join(dir, "run")
	if err := os.Mkdir(base+".json", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	server, _ := replying(t, 200)

	code, _, stderr := exec(t, "fetch", "--report="+base, "--report-format", "html,json", server.URL)
	if code != 1 {
		t.Errorf("exit code = %d, want 1\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "  report written to "+base+".html\n") || !strings.Contains(stderr, "tlsforge: fetch: ") {
		t.Errorf("stderr does not name the page, or the failure:\n%s", stderr)
	}
	if html := reportOf(t, base+".html"); !strings.Contains(html, "1 of 1 URLs") {
		t.Error("the page that could be written is not the report of the run")
	}

	// A list does the same, and names the page among what the run came to.
	code, _, stderr = exec(t, "fetch", "--report="+base, "--report-format", "html,json", "--report-ip=false",
		server.URL+"/one", server.URL+"/two")
	if code != 1 || !strings.Contains(stderr, "  Report        "+base+".html\n") || !strings.Contains(stderr, "tlsforge: fetch: ") {
		t.Errorf("a list: exit code = %d\n%s", code, stderr)
	}
}

func TestListWritesBothReports(t *testing.T) {
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	server := pathServer(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "run")

	code, _, stderr := exec(t, "fetch", "--report="+base, "--report-format", "json,html", "--report-ip=false",
		server.URL+"/a", server.URL+"/b", server.URL+"/c")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The page stops at what a browser can open and says so, once, beside its
	// own name. The document has every request.
	want := "  Avg time      0ms\n  Report        " + base + ".json\n" +
		"  Report        " + base + ".html  (without 1 of the requests)\n"
	if !strings.HasSuffix(stderr, want) || strings.Count(stderr, "of the requests") != 1 {
		t.Errorf("stderr does not name the two, or says more than once what the page left out (%q):\n%s", want, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, base+".json")))
	if doc.Command != "fetch" || len(doc.Requests) != 3 || doc.Summary.Requests != 3 {
		t.Errorf("the document has %d requests of %+v", len(doc.Requests), doc.Summary)
	}
	if html := reportOf(t, base+".html"); !strings.Contains(html, "1 more rows are not shown") {
		t.Error("the page does not say what it left out")
	}
	// Only as many as the page could show keep their tries, in the document too.
	withTries := 0
	for _, r := range doc.Requests {
		if len(r.Tries) > 0 {
			withTries++
		}
	}
	if withTries != 2 {
		t.Errorf("%d requests kept their tries, want the 2 there was room for", withTries)
	}
}

func TestFetchReportOfManyNamesWhatThePageLeftOut(t *testing.T) {
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	server, _ := replying(t, 200)
	base := filepath.Join(t.TempDir(), "run")

	code, _, stderr := exec(t, "fetch", "--repeat", "3", "--report="+base, "--report-format", "html,json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Said of the page, which stops at what a browser can open, and not of the
	// document, which has all three.
	want := "  Report        " + base + ".html  (without 1 of the requests)\n  Report        " + base + ".json\n"
	if !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not say which report left a request out (%q):\n%s", want, stderr)
	}
	if doc := decoded(t, []byte(reportOf(t, base+".json"))); len(doc.Requests) != 3 {
		t.Errorf("the document has %d requests, want all 3", len(doc.Requests))
	}
}
