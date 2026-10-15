package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// standInIPService answers the way the real one does, so no test reaches a
// service on the internet to find out what its own address is.
//
// It returns how many times it was asked, for the tests whose point is that
// nobody was, or that somebody was exactly once.
func standInIPService(t *testing.T, body string, status int) *atomic.Int32 {
	t.Helper()
	asked := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	askOnly(t, addressService{URL: server.URL, read: readJSON})
	return asked
}

// inputOf is what a report of these records is written from.
func inputOf(records []result) reportInput {
	return reportInput{command: "fetch", records: records, summary: summarise(records, time.Second)}
}

// askOnly makes these the address services for one test, in this order.
func askOnly(t *testing.T, services ...addressService) {
	t.Helper()
	original := ipServices
	t.Cleanup(func() { ipServices = original })
	ipServices = services
}

// insecureFlags are a run's flags, set to talk to a stand-in's self-signed
// certificate.
func insecureFlags(t *testing.T) clientFlags {
	t.Helper()
	fs := newFlagSet("fetch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	if err := parse(fs, []string{"--insecure"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return flags
}

// cookiesSeenByIPService stands in for the address service and keeps the Cookie
// header each question arrived with, so a test can check that none did.
func cookiesSeenByIPService(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Cookie"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","country":"PL"}`))
	}))
	t.Cleanup(server.Close)

	askOnly(t, addressService{URL: server.URL, read: readJSON})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestFlagFromCountryCode(t *testing.T) {
	// Arithmetic, not a table: a flag emoji is the two letters of the ISO
	// 3166-1 alpha-2 code as regional indicator symbols.
	for _, tc := range []struct{ country, want string }{
		{"PL", "\U0001F1F5\U0001F1F1"},
		{"us", "\U0001F1FA\U0001F1F8"},
		{" DE ", "\U0001F1E9\U0001F1EA"},
		// Nothing to make a flag from, and no guessing.
		{"", ""},
		{"POL", ""},
		{"P", ""},
		{"P1", ""},
	} {
		if got := (egress{Country: tc.country}).Flag(); got != tc.want {
			t.Errorf("Flag(%q) = %q, want %q", tc.country, got, tc.want)
		}
	}
}

func TestSummarise(t *testing.T) {
	pl, de := egress{IP: "203.0.113.7", Country: "PL"}, egress{IP: "198.51.100.9", Country: "DE"}
	records := []result{
		{URL: "https://a/", Status: 200, Bytes: 1_000, Attempts: 1, Millis: 100, Exit: de},
		{URL: "https://b/", Status: 200, Bytes: 2_000, Attempts: 3, Millis: 1_400, Proxy: "http://good", Exit: pl},
		{URL: "https://c/", Attempts: 2, Millis: 300, Proxy: "http://dead", Error: "refused"},
		{URL: "https://d/", Attempts: 2, Millis: 300, Proxy: "http://dead", Error: "refused"},
		// A response that is not the page: neither scraped nor a dead connection.
		{URL: "https://e/", Status: 503, Bytes: 500, Attempts: 1, Millis: 400, Proxy: "http://good", Exit: pl},
		{URL: "https://f/", Status: 200, Attempts: 1, Proxy: "http://good", Exit: de},
	}
	s := summarise(records, 90*time.Second)

	if s.Total != 6 || s.Succeeded != 3 || s.Warned != 1 || s.Failed != 2 {
		t.Errorf("counts: %+v", s)
	}
	if s.Bytes != 3_500 {
		t.Errorf("Bytes = %d", s.Bytes)
	}
	// One attempt is the request; the rest are retries. 0 + 2 + 1 + 1 + 0 + 0.
	if s.Retries != 4 {
		t.Errorf("Retries = %d, want 4", s.Retries)
	}
	// Two and a half seconds of requests in a run of ninety: what one request
	// took is its own time, tries included, and not a share of the run's.
	if s.Spent != 2500*time.Millisecond || s.Average() != 2500*time.Millisecond/6 {
		t.Errorf("Spent = %s and Average = %s, want 2.5s and a sixth of it", s.Spent, s.Average())
	}
	if !s.Direct {
		t.Error("a URL went without a proxy and the summary did not notice")
	}
	if len(s.Proxies) != 2 || s.AliveProxies() != 1 {
		t.Errorf("proxies: %+v", s.Proxies)
	}
	// Dead first: it is the reason someone is reading this.
	if s.Proxies[0].Proxy != "http://dead" || s.Proxies[0].Alive() {
		t.Errorf("the dead proxy is not at the top: %+v", s.Proxies)
	}
	// Every address the live one came out of, each once, in the order they
	// were met; none for the one that carried nothing, and the direct request's
	// is nobody's.
	if got := s.Proxies[1].Exits; !slices.Equal(got, []egress{pl, de}) {
		t.Errorf("the live proxy came out of %+v", got)
	}
	if got := s.Proxies[0].Exits; got != nil {
		t.Errorf("the dead proxy came out of %+v", got)
	}
}

func TestProxyListsAFewOfItsAddresses(t *testing.T) {
	// A rotating proxy can have an address for every request, and its row is
	// there to say which proxy it is and how it did.
	var p proxyStat
	if len(p.ListedExits()) != 0 || p.MoreExits() != 0 {
		t.Errorf("a proxy of no addresses lists %+v and %d more", p.ListedExits(), p.MoreExits())
	}
	for i := range 5 {
		p.Exits = append(p.Exits, egress{IP: fmt.Sprintf("203.0.113.%d", i+1)})
	}
	if got := p.ListedExits(); len(got) != 3 || got[2].IP != "203.0.113.3" || p.MoreExits() != 2 {
		t.Errorf("five addresses are listed as %+v and %d more", got, p.MoreExits())
	}
}

func TestSummaryProxyRows(t *testing.T) {
	s := summarise([]result{
		{URL: "https://a/", Status: 200, Bytes: 1_000, Attempts: 1, Millis: 240},
		{URL: "https://b/", Attempts: 2, Millis: 2_760, Proxy: "http://dead", Error: "refused"},
		{URL: "https://c/", Status: 200, Attempts: 1, Proxy: "http://user:secret@alive"},
	}, 3*time.Minute)

	want := [][2]string{
		{"Proxies", "2 used, 1 alive, some direct"},
		// Named, not just counted: "1 alive" does not say which one to replace.
		{"dead proxy", "http://dead  (1 requests, none came back)"},
	}
	if got := s.proxyRows(); !slices.Equal(got, want) {
		t.Errorf("proxy rows = %q, want %q", got, want)
	}
	if s.Average() != time.Second {
		t.Errorf("Average = %s, want the three seconds between three requests", s.Average())
	}

	// A run that used no proxy has nothing to say about any, and one whose
	// every request went through one does not mention going direct.
	if got := summarise([]result{{Status: 200}}, time.Second).proxyRows(); got != nil {
		t.Errorf("a run without proxies has %q", got)
	}
	through := summarise([]result{{Status: 200, Proxy: "http://p1"}}, time.Second)
	if got := through.proxyRows(); !slices.Equal(got, [][2]string{{"Proxies", "1 used, 1 alive"}}) {
		t.Errorf("a run through one proxy has %q", got)
	}
}

func TestSummaryOfNothing(t *testing.T) {
	// A percentage of nothing is 0%, not a division by zero, and so is the time
	// that none of its requests took.
	s := summarise(nil, time.Second)
	if s.SuccessRate() != "0.0%" || s.Average() != 0 {
		t.Errorf("a run of nothing: %s scraped, %s each", s.SuccessRate(), s.Average())
	}
}

func TestPreciseDuration(t *testing.T) {
	// One page's time, where "0s" is not an answer.
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0ms"},
		{0, "0ms"},
		{65 * time.Millisecond, "65ms"},
		{999 * time.Millisecond, "999ms"},
		{time.Second, "1.0s"},
		{2500 * time.Millisecond, "2.5s"},
		{90 * time.Second, "1m30s"},
	} {
		if got := preciseDuration(tc.d); got != tc.want {
			t.Errorf("preciseDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestWriteReport(t *testing.T) {
	started := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	// The header carries the time the report was written; a fixed clock makes
	// that something the test can assert.
	clock := fakeClock(t)
	clock.at = started.Add(time.Minute)
	records := []result{
		// Out of order on purpose: the report puts them back in the order the
		// requests went out, not the order the answers came back.
		{
			URL: "https://second/", Proxy: "http://p1", Started: started.Add(time.Second),
			Ended: started.Add(2 * time.Second), Millis: 1_000, Status: 200, Bytes: 2_048, Attempts: 1,
			Exit: egress{IP: "203.0.113.7", Country: "PL"},
		},
		{
			URL: "https://first/", Started: started, Ended: started.Add(300 * time.Millisecond),
			Millis: 300, Attempts: 3, Error: "no route to host", ExitError: "nobody answered",
		},
	}
	in := inputOf(records)
	in.summary.Elapsed = 2 * time.Second

	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeReport(reportFile{formatHTML, path}, in); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	html := string(data)

	for _, want := range []string{
		"<title>",
		"04 Mar 2026 09:31:00", // generated
		"04 Mar 2026 09:30:00", // started
		"300ms",                // took
		"1.0s",
		"2.0 kB",
		"no response",
		"no route to host", // the reason, on the cell's title
		"http://p1",
		"203.0.113.7",
		"\U0001F1F5\U0001F1F1", // the flag
		"direct",
		"unknown",
		// Why, in the row that opens.
		"unknown · nobody answered",
		// Where the address the proxy gave came from, for whoever wonders whether
		// to believe it.
		"Where a request through a proxy came out is what the proxy said",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}

	// In start order, so the failed one that went out first comes first.
	if strings.Index(html, "https://first/") > strings.Index(html, "https://second/") {
		t.Error("the rows are not in the order the requests went out")
	}

	// Self-contained: nothing is fetched from anywhere when this is opened, and
	// a run that was not traced has nothing for a script to do.
	for _, forbidden := range []string{"<script", "src=", "@import", "<link", "url(http", "Open in Perfetto"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the report reaches outside itself: %q", forbidden)
		}
	}
}

func TestLinkTo(t *testing.T) {
	for _, tc := range []struct{ file, report, want string }{
		// Beside the report, and below where it is.
		{"out/trace-a.json", "out/report.html", "trace-a.json"},
		{"out/trace-a.json", "report.html", "out/trace-a.json"},
		// Somewhere else, which is up and down again, escaped as a URL is.
		{"out/trace-a.json", "reports/r.html", "../out/trace-a.json"},
		{"/runs/out/trace a#1?.json", "/runs/reports/r.html", "../out/trace%20a%231%3F.json"},
		// A colon in the first part of a path does not make it a scheme.
		{"c:odd.json", "r.html", "./c:odd.json"},
	} {
		if got := linkTo(tc.file, tc.report); string(got) != tc.want {
			t.Errorf("linkTo(%q, %q) = %q, want %q", tc.file, tc.report, got, tc.want)
		}
	}
	// One given in full and the other not: the file where it is.
	if got := string(linkTo("trace.json", filepath.Join(t.TempDir(), "r.html"))); !strings.HasPrefix(got, "file:///") ||
		!strings.HasSuffix(got, "/trace.json") || strings.Contains(got, "\\") {
		t.Errorf("a file the report has no relative way to is linked as %q", got)
	}
}

func TestPerfettoOf(t *testing.T) {
	r, _, about := keptRequest()
	got := perfettoOf(r, about.method)

	// The trace kept beside the request, byte for byte, once it is unpacked.
	packed, err := base64.StdEncoding.DecodeString(got.Data)
	if err != nil {
		t.Fatalf("the trace is not base64: %v", err)
	}
	unzipper, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("the trace is not gzip: %v", err)
	}
	trace, _ := io.ReadAll(unzipper)
	if !bytes.Equal(trace, traceFileOf(requestTrace(r, about.method))) {
		t.Errorf("the trace handed over is not the request's:\n%s", trace)
	}
	// Named as the file it is kept in would be, in what the viewer keeps of a
	// name: anything else it makes a space of.
	if got.Title != "GET https://example.test/a - request 3" || got.Name != "trace-example.test-2026-03-04-093000-012-3.json" {
		t.Errorf("the trace is opened as %q, %q", got.Title, got.Name)
	}
	kept := regexp.MustCompile(`^[A-Za-z0-9.\-_#:/?=&;%+$ ]*$`)
	if !kept.MatchString(got.Title) || !kept.MatchString(got.Name) {
		t.Errorf("the viewer would change %q or %q", got.Title, got.Name)
	}
}

func TestReportOpensEveryRequestInPerfetto(t *testing.T) {
	r, _, _ := keptRequest()
	r.Log, r.Trace = "out/a.log", "out/trace-a.json"
	bare := result{URL: "https://example.test/b", ID: 4, Started: r.Started.Add(time.Second)}
	in := inputOf([]result{r, bare})
	in.method, in.trace, in.at = "GET", "run.trace.json", "out/report.html"

	var out strings.Builder
	if err := renderReport(&out, in); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		// The trace of the run, and of each request, from where the report is.
		`The run was traced to <a class="font-mono underline`, `href="../run.trace.json">run.trace.json</a>`,
		`href="a.log">out/a.log</a>`, `href="trace-a.json">out/trace-a.json</a>`,
		// A request kept nowhere of its own is in the trace of the run.
		`href="../run.trace.json">run.trace.json</a>`,
		`data-title="GET https://example.test/a - request 3"`, `data-title="GET https://example.test/b - request 4"`,
		"Open in Perfetto", "it asks before\n       it opens what it was handed",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	// One script, written into the page, and still nothing fetched from
	// anywhere when it is opened.
	if strings.Count(html, "<script") != 1 || strings.Contains(html, "src=") || !strings.Contains(html, `"https://ui.perfetto.dev"`) {
		t.Error("the report does not have its one script, or reaches outside itself")
	}
	if got := strings.Count(html, "data-trace="); got != 2 {
		t.Errorf("%d traces to open, want one for each request", got)
	}
}

func TestWriteReportEscapesWhatItIsGiven(t *testing.T) {
	// A URL is not the report's to trust: it came from a file someone else may
	// have written, and it lands in a document that gets opened in a browser.
	records := []result{{
		URL:    `https://x/?q=<script>alert(1)</script>`,
		Error:  `<img src=x onerror="alert(2)">`,
		Status: 200,
	}}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeReport(reportFile{formatHTML, path}, inputOf(records)); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "<script>alert(1)") {
		t.Error("a URL was written into the document as markup")
	}
	if strings.Contains(string(data), `onerror="alert(2)"`) {
		t.Error("an error message was written into the document as markup")
	}
}

func TestWriteReportToAPathThatWillNotOpen(t *testing.T) {
	// A parent that is a regular file, so the directory cannot be made and the
	// file cannot be created. A merely absent directory is no longer a failure:
	// writeReport makes it, which is what `--report reports/` needs.
	blocked := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := writeReport(reportFile{formatHTML, filepath.Join(blocked, "r.html")}, reportInput{command: "fetch"})
	if err == nil {
		t.Error("no error")
	}
}

// TestWriteReportMakesTheDirectory covers the documented `--report reports/`
// spelling, which fetched the whole list and then failed at the last step
// because nothing created the directory.
func TestWriteReportMakesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "r.html")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Rewriting a pre-existing report must tighten permissions too; OpenFile's
	// mode alone only applies when a file is first created.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := writeReport(reportFile{formatHTML, path}, reportInput{command: "fetch"}); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("report was not written: %v", err)
	} else if got := info.Mode().Perm(); runtime.GOOS == "windows" {
		// Windows has no Unix permission bits. Go's Chmod uses only 0200 to
		// control the read-only attribute, and Stat reports writable files as
		// 0666. The exact 0600 assertion is meaningful only on Unix.
		if got&0o200 == 0 {
			t.Errorf("report permissions = %#o, want a writable file", got)
		}
	} else if got != 0o600 {
		t.Errorf("report permissions = %#o, want 0600", got)
	}
}

func TestWriteReportReportsAChmodFailure(t *testing.T) {
	original := chmodReport
	t.Cleanup(func() { chmodReport = original })
	chmodReport = func(_ *os.File, _ os.FileMode) error { return fmt.Errorf("permission denied") }

	err := writeReport(reportFile{formatHTML, filepath.Join(t.TempDir(), "report.html")}, reportInput{command: "fetch"})
	if err == nil || !strings.Contains(err.Error(), "securing report") {
		t.Fatalf("writeReport error = %v", err)
	}
}

func TestLookupExit(t *testing.T) {
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL","city":"Warsaw"}`, http.StatusOK)

	found, err := lookupExit(context.Background(), insecureFlags(t), "")
	if err != nil {
		t.Fatalf("lookupExit: %v", err)
	}
	if found.IP != "203.0.113.7" || found.Country != "PL" {
		t.Errorf("got %+v", found)
	}
}

func TestLookupExitErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"a status that is not 2xx", `{"ip":"1.2.3.4"}`, http.StatusTooManyRequests},
		{"an answer that is not JSON", "<html>blocked</html>", http.StatusOK},
		{"JSON without an address", `{"country":"PL"}`, http.StatusOK},
		// Somebody else's text, which fetch prints on a terminal: it is an
		// address or it is nothing.
		{"an address that is not one", `{"ip":"203.0.113.7\u001b[2J"}`, http.StatusOK},
		{"an address with a zone", `{"ip":"fe80::1%\u001b[2J"}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standInIPService(t, tc.body, tc.status)
			if _, err := lookupExit(context.Background(), insecureFlags(t), ""); err == nil {
				t.Error("no error")
			}
		})
	}

	t.Run("a service that cannot be reached", func(t *testing.T) {
		askOnly(t, addressService{URL: "https://127.0.0.1:1/", read: readJSON})
		if _, err := lookupExit(context.Background(), insecureFlags(t), ""); err == nil {
			t.Error("no error")
		}
	})

	t.Run("a run that was interrupted", func(t *testing.T) {
		// The service would answer; nobody is waiting for it any more.
		standInIPService(t, `{"ip":"203.0.113.7"}`, http.StatusOK)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := lookupExit(ctx, insecureFlags(t), ""); err == nil {
			t.Error("no error")
		}
	})

	t.Run("a proxy that is not one", func(t *testing.T) {
		// There is no client to ask with, so nobody is asked.
		asked := standInIPService(t, `{"ip":"203.0.113.7"}`, http.StatusOK)
		if _, err := lookupExit(context.Background(), insecureFlags(t), "://not a proxy"); err == nil {
			t.Error("no error")
		}
		if got := asked.Load(); got != 0 {
			t.Errorf("the service was asked %d times", got)
		}
	})

	t.Run("nobody to ask", func(t *testing.T) {
		askOnly(t)
		if _, err := lookupExit(context.Background(), insecureFlags(t), ""); err == nil {
			t.Error("no error")
		}
	})
}

func TestListWritesAReport(t *testing.T) {
	// A clock that stands still, so what the requests took does not depend on
	// the machine.
	fakeClock(t)
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)
	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--report="+path, "--insecure",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	// What the run came to lands on stderr, with everything else that is
	// commentary, and ends by naming the report.
	want := "\n  Requests      2\n  Retries       0\n  Success rate  100.0%\n  Avg time      0ms\n" +
		"  Report        " + path + "\n"
	if !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end with what the run came to (%q):\n%s", want, stderr)
	}
	// Both went the same way, so where that came out was asked once, before the
	// first of them, and is said where the run says what it is wearing.
	if !strings.Contains(stderr, "  exit-ip     203.0.113.7 · PL\n") {
		t.Errorf("stderr does not say where the run came out:\n%s", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	// The same address for both, said once.
	for _, want := range []string{
		server.URL + "/one", "and came out of <span class=\"not-italic\">\U0001F1F5\U0001F1F1</span> " +
			"<span class=\"font-mono\">203.0.113.7</span>.",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if strings.Contains(string(data), ">Exit address</span>") {
		t.Error("every row says the address they all came out of")
	}
}

func TestListKeepsItsSessionFromTheAddressService(t *testing.T) {
	// A cookie that names no domain is filed against every host a client talks
	// to. That is how it reaches the pages it is for, and how the question
	// about the address, asked through the same client, used to hand the
	// session to the address service as well.
	seen := cookiesSeenByIPService(t)
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "run.html")

	code, stdout, stderr := exec(t, "fetch", "--insecure", "--progress", "never",
		"-b", "session=s3cr3t", "--report="+path, server.URL+"/")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "session=s3cr3t") {
		t.Errorf("the page was not sent its cookie: %s", stdout)
	}
	if got := seen(); len(got) != 1 || got[0] != "" {
		t.Errorf("the address service was asked with Cookie headers %q, want one question and no cookie", got)
	}
	// Asked without the session, and answered all the same.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if !strings.Contains(string(data), "203.0.113.7") {
		t.Error("the report has no exit address")
	}
}

func TestListReportWithoutAskingAboutEachRequest(t *testing.T) {
	// Where the run came out is asked once, before it, as it is for every run
	// that goes one way, and a report asks nobody again for each request. The
	// stand-in counts what it is asked.
	asked := standInIPService(t, `{"ip":"203.0.113.7"}`, http.StatusOK)

	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "run.html")
	code, _, stderr := exec(t, "fetch", "--report="+path, "--insecure",
		server.URL+"/one", server.URL+"/two", server.URL+"/three")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the service was asked %d times, want once", got)
	}
	// What the one answer was, for every request, and that it was the one.
	html := reportOf(t, path)
	for _, want := range []string{"203.0.113.7", "once, before the"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestListReportToAPathThatWillNotOpen(t *testing.T) {
	server := pathServer(t)
	blocked := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	code, _, stderr := exec(t, "fetch", "--report="+filepath.Join(blocked, "r.html"),
		server.URL+"/one")
	if code != 1 || !strings.Contains(stderr, "a-file") {
		t.Errorf("an unwritable report path: exit code %d\n%s", code, stderr)
	}
}

// TestListReportToADirectoryThatDoesNotExist is the README's own spelling, end
// to end: the run must succeed and leave a report behind.
func TestListReportToADirectoryThatDoesNotExist(t *testing.T) {
	server := pathServer(t)
	dir := filepath.Join(t.TempDir(), "reports")
	code, _, _ := exec(t, "fetch", "--report="+dir+string(os.PathSeparator),
		server.URL+"/one")
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("the report directory was not made: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files in the report directory, want 1", len(entries))
	}
}

func TestListSummaryNamesADeadProxy(t *testing.T) {
	// The question the summary exists for: which of my proxies is the reason
	// those pages are missing.
	server := pathServer(t)
	path := writeList(t, "dead.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/one,http://127.0.0.1:9001\n%[1]s/two,\n", server.URL))

	code, _, stderr := exec(t, "fetch", "--input", path, "--timeout", "5s")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	for _, want := range []string{"1 used, 0 alive", "dead proxy", "127.0.0.1:9001", "50.0%"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
}

func TestRenderReportReportsAWriteFailure(t *testing.T) {
	// A full disk part way through the document.
	if err := renderReport(failingWriter{}, reportInput{command: "fetch"}); err == nil {
		t.Error("no error")
	}
}

func TestListReportWithAProxyThatCannotBeBuilt(t *testing.T) {
	// The proxy column had a typo, so the URL failed and there was no proxy to
	// say where it came out. The report is still written, and says that is not
	// known rather than failing the run.
	asked := standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)
	server := pathServer(t)
	// Two of the three went without a proxy. The list went two ways, so nobody
	// was asked where the machine comes out, and that is said as well.
	list := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/bad,::not a proxy::\n%[1]s/good,\n%[1]s/also-good,\n", server.URL))

	path := filepath.Join(t.TempDir(), "run.html")
	code, _, stderr := exec(t, "fetch", "--input", list, "--report="+path, "--insecure")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	for _, want := range []string{
		"Where the requests came out is not known.", "unknown · not asked, as the run went more than one way",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("the service was asked %d times, want never", got)
	}
}

func TestReportBesideTheRequestsOpensTheirTraces(t *testing.T) {
	// The report goes beside what the run kept, so every request's files are a
	// name away, and what it opens in Perfetto is the trace kept with each.
	clock := fakeClock(t)
	server, _ := replying(t, 200)
	dir := t.TempDir()
	t.Chdir(dir)

	code, _, stderr := exec(t, "fetch", "--repeat", "2", "-o", "out", "--report", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	name := "127.0.0.1-" + stamp(clock.now())
	page := reportOf(t, filepath.Join("out", "report-"+stamp(clock.now())+".html"))
	for _, want := range []string{`href="` + name + `-1.log"`, `href="trace-` + name + `-2.json"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if strings.Contains(page, "The run was traced to") {
		t.Error("the report names a trace of the run, which was not traced as a whole")
	}
	found := regexp.MustCompile(`data-trace="([^"]+)" data-title="[^"]*" data-name="([^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(found) != 2 {
		t.Fatalf("%d traces to open, want 2", len(found))
	}
	for _, opened := range found {
		// As a browser reads the attribute, which is escaped as every one is.
		packed, err := base64.StdEncoding.DecodeString(html.UnescapeString(opened[1]))
		if err != nil {
			t.Fatalf("the trace is not base64: %v", err)
		}
		unzipper, err := gzip.NewReader(bytes.NewReader(packed))
		if err != nil {
			t.Fatalf("the trace is not gzip: %v", err)
		}
		trace, _ := io.ReadAll(unzipper)
		if kept, _ := os.ReadFile(filepath.Join("out", opened[2])); !bytes.Equal(trace, kept) {
			t.Errorf("what the report opens is not %s:\n%s\n%s", opened[2], trace, kept)
		}
	}
}

func TestReportOfARunTracedToOneFile(t *testing.T) {
	server, _ := replying(t, 200)
	dir := t.TempDir()
	trace, report := filepath.Join(dir, "run.trace.json"), filepath.Join(dir, "reports", "run")

	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--trace", trace, "--report="+report,
		"--report-format", "html,json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Every row is in the trace of the run, and opens a trace of its own.
	html := reportOf(t, report+".html")
	if got := strings.Count(html, `href="../run.trace.json"`); got != 3 {
		t.Errorf("the trace of the run is linked to %d times, want once above the rows and once in each", got)
	}
	if got := strings.Count(html, "data-trace="); got != 2 {
		t.Errorf("%d traces to open, want 2", got)
	}
	// And the document names it, for a program to open.
	if doc := decoded(t, []byte(reportOf(t, report+".json"))); doc.Trace != trace {
		t.Errorf("the document names the trace %q, want %q", doc.Trace, trace)
	}
}

func TestReportTakesWhereEachRequestCameOutFromItsProxy(t *testing.T) {
	// A proxy that hands every connection an address of its own, and says which
	// in its answer to CONNECT: the nth tunnel comes out at 203.0.113.n. Where a
	// request came out is the address of the tunnel it went through, and nobody
	// is asked about it: the one question before the run is its own tunnel.
	clock := fakeClock(t)
	asked := standInIPService(t, `{"ip":"192.0.2.9","country":"DE"}`, http.StatusOK)
	via := startProxySaying(t, func(n int) string { return fmt.Sprintf("X-Exit-IP: 203.0.113.%d\r\n", n) })
	first, second := tlsPathServer(t), tlsPathServer(t)
	list := writeList(t, "rotating.txt", first.URL+"/a\n"+second.URL+"/b\n"+first.URL+"/c\n")
	tmp := t.TempDir()
	dir, report, trace := filepath.Join(tmp, "out"), filepath.Join(tmp, "run"), filepath.Join(tmp, "run.trace.json")

	code, _, stderr := exec(t, "fetch", "--input", list, "--proxy", "http://"+via.addr, "--insecure", "-c", "1",
		"-o", dir, "--trace", trace, "--report="+report, "--report-format", "html,json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 1 {
		t.Errorf("the address service was asked %d times, want only before the run", got)
	}
	// The question before the run went through the first tunnel. The pages took
	// the next two, one for each server, and the last request went out on the
	// connection the first one had left open, so it came out where that did.
	doc := decoded(t, []byte(reportOf(t, report+".json")))
	var exits []string
	for _, r := range doc.Requests {
		if r.Exit == nil || r.ExitError != "" {
			t.Fatalf("%s came out of %+v (%q)", r.URL, r.Exit, r.ExitError)
		}
		exits = append(exits, r.Exit.IP)
	}
	if want := []string{"203.0.113.2", "203.0.113.3", "203.0.113.2"}; !slices.Equal(exits, want) {
		t.Errorf("the requests came out of %v, want %v", exits, want)
	}
	if got := doc.Requests[0].Tries[0].Connection; got == nil || got.Exit == nil || got.Exit.IP != "203.0.113.2" ||
		!slices.Equal(got.ProxyAnswer, []string{"x-exit-ip: 203.0.113.2"}) {
		t.Errorf("the first try went out on %+v", got)
	}

	page := reportOf(t, report+".html")
	for _, want := range []string{
		"and came out of 2 different addresses.", ">Exit address</span>",
		"The proxy answered CONNECT with 1 header field", "x-exit-ip: 203.0.113.2",
		"came out at 203.0.113.3",
		"Where a request through a proxy came out is what the proxy said",
		// The one question asked before the run, which is given to no request.
		"192.0.2.9</span>. That was a connection of its own",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}

	// The log and the trace each request is kept with say the same, and so does
	// the trace of the run.
	name := "127.0.0.1-" + stamp(clock.now())
	log, _ := os.ReadFile(filepath.Join(dir, name+"-3.log"))
	for _, want := range []string{
		"  exit-ip  203.0.113.2\n", "came out at 203.0.113.2",
		"\n  the proxy's answer to CONNECT\n    x-exit-ip: 203.0.113.2\n",
	} {
		if !strings.Contains(string(log), want) {
			t.Errorf("the log of the last request has no %q:\n%s", want, log)
		}
	}
	kept := traceFile(t, filepath.Join(dir, "trace-"+name+"-2.json"))
	if ended := kept[len(kept)-1]; ended.Args["exit_ip"] != "203.0.113.3" {
		t.Errorf("the trace of the second request ends as %+v", ended)
	}
	answered := 0
	for _, event := range traceFile(t, trace) {
		if event.Name == "proxy+tls" && event.Args["proxy_answer"] != nil {
			answered++
		}
	}
	if answered != 2 {
		t.Errorf("the trace of the run has the proxy's answer to %d tunnels, want the two the pages opened", answered)
	}
}

func TestListTakesWhereEachRequestCameOutFromItsOwnProxy(t *testing.T) {
	// Two proxies, each saying where it comes out in a field of its own, and a
	// third that says nothing. Nobody else is asked about any of them.
	asked := standInIPService(t, `{"ip":"192.0.2.9"}`, http.StatusOK)
	massive := startProxySaying(t, func(int) string { return "X-Exit-IP: 198.51.100.1\r\nX-Exit-Country: NL\r\n" })
	mesh := startProxySaying(t, func(int) string { return "X-ProxyMesh-IP: 2001:db8::0:1\r\n" })
	silent := startProxy(t)
	server := tlsPathServer(t)
	list := writeList(t, "routed.csv", fmt.Sprintf("url,proxy\n%[1]s/a,http://%[2]s\n%[1]s/b,http://%[3]s\n%[1]s/c,http://%[4]s\n",
		server.URL, massive.addr, mesh.addr, silent.addr))
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--input", list, "--insecure", "--report="+path, "--report-format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("the address service was asked %d times", got)
	}
	doc := decoded(t, []byte(reportOf(t, path)))
	got := map[string]string{}
	for _, r := range doc.Requests {
		switch {
		case r.Exit != nil:
			got[r.URL] = r.Exit.IP + " " + r.Exit.Country
		default:
			got[r.URL] = r.ExitError
		}
	}
	want := map[string]string{
		server.URL + "/a": "198.51.100.1 NL",
		// Written the way an address is written, whatever the proxy wrote.
		server.URL + "/b": "2001:db8::1 ",
		server.URL + "/c": "the proxy did not say",
	}
	if !maps.Equal(got, want) {
		t.Errorf("the requests came out of %v, want %v", got, want)
	}
}

func TestReportTakesAProxysHashOfTheAddress(t *testing.T) {
	// Bright Data does not say the address a tunnel comes out of. It says a hash
	// of it, the same for the same address, and that is where a request came
	// out: every new tunnel here comes out of another one.
	clock := fakeClock(t)
	hash := func(n int) string { return fmt.Sprintf("r%032x", n) }
	via := startProxySaying(t, func(n int) string { return "x-brd-ip: " + hash(n) + "\r\n" })
	first, second := tlsPathServer(t), tlsPathServer(t)
	list := writeList(t, "hashed.txt", first.URL+"/a\n"+second.URL+"/b\n")
	tmp := t.TempDir()
	dir, report := filepath.Join(tmp, "out"), filepath.Join(tmp, "run")
	// The field alone, without the example's way of asking Bright Data what a
	// hash stands for, which would ask brdtest.com on the internet.
	fields := filepath.Join(tmp, "exit-headers.json")
	if err := os.WriteFile(fields, []byte(`{"fields": [{"header": "x-brd-ip"}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, _, stderr := exec(t, "fetch", "--input", list, "--proxy", "http://"+via.addr, "--insecure", "-c", "1",
		"--exit-headers", fields, "-o", dir, "--report="+report, "--report-format", "html,json")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// The question before the run took the first tunnel, and the pages the next.
	doc := decoded(t, []byte(reportOf(t, report+".json")))
	var exits []string
	for _, r := range doc.Requests {
		if r.Exit == nil || r.Exit.IP != "" {
			t.Fatalf("%s came out of %+v", r.URL, r.Exit)
		}
		exits = append(exits, r.Exit.Hash)
	}
	if want := []string{hash(2), hash(3)}; !slices.Equal(exits, want) {
		t.Errorf("the requests came out of %v, want %v", exits, want)
	}

	page := reportOf(t, report+".html")
	for _, want := range []string{
		"and came out of 2 different addresses.",
		// The whole of each, in a column wide enough for it.
		"</span> " + hash(2) + "\n", "</span> " + hash(3) + "\n", "min-width:72rem",
		"came out at " + hash(3) + " (the proxy&#39;s name for the address)",
		"names it instead, as Bright Data does\n       with a hash of it in x-brd-ip",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	name := "127.0.0.1-" + stamp(clock.now())
	if log, _ := os.ReadFile(filepath.Join(dir, name+"-1.log")); !strings.Contains(string(log),
		"  exit-ip  "+hash(2)+" (the proxy's name for the address)\n") {
		t.Errorf("the log of the first request does not say where it came out:\n%s", log)
	}
	kept := traceFile(t, filepath.Join(dir, "trace-"+name+"-2.json"))
	if ended := kept[len(kept)-1]; ended.Args["exit_hash"] != hash(3) || ended.Args["exit_ip"] != nil {
		t.Errorf("the trace of the second request ends as %+v", ended)
	}
}

func TestAProxyThatSaysOnlyWhenAsked(t *testing.T) {
	// SOAX names the node a tunnel came out of when the CONNECT asks for it
	// with Respond-With, which the file says every CONNECT is to say.
	via := startProxyHearing(t, func(_ int, asked []string) string {
		if slices.Contains(asked, "Respond-With: ip,country") {
			return "Node-Ip: 203.0.113.30\r\nNode-Country: al\r\n"
		}
		return ""
	})
	server := tlsPathServer(t)
	path := filepath.Join(t.TempDir(), "run.json")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--report="+path,
		"--report-format", "json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	doc := decoded(t, []byte(reportOf(t, path)))
	if got := doc.Requests[0].Exit; got == nil || *got != (documentExit{IP: "203.0.113.30", Country: "AL"}) {
		t.Errorf("the request came out of %+v", got)
	}
}

func TestReportOfAProxyNobodyCouldBeAskedThrough(t *testing.T) {
	// The question before the run went unanswered, which the report says, and a
	// proxy that says nothing either leaves every request's exit unknown.
	standInIPService(t, "busy", http.StatusServiceUnavailable)
	via := startProxy(t)
	server := tlsPathServer(t)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--proxy", "http://"+via.addr, "--insecure", "--report="+path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	page := reportOf(t, path)
	for _, want := range []string{
		"comes out was asked of " + askedOf() + ",\n       and nobody could say: ", ": HTTP 503. That was a connection",
		"Where it came out is not known.", "unknown · the proxy did not say",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestExitHeadersTeachAFieldAProxySaysItIn(t *testing.T) {
	via := startProxySaying(t, func(int) string { return "X-Egress: 192.0.2.44\r\n" })
	server := tlsPathServer(t)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "run.html")

	// Not a field anybody is known to say it in, so it is not known.
	args := []string{"fetch", "--proxy", "http://" + via.addr, "--insecure", "--report=" + path, server.URL}
	if code, _, stderr := exec(t, args...); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if page := reportOf(t, path); !strings.Contains(page, "unknown · the proxy did not say") ||
		!strings.Contains(page, "a proxy that says it in another is taught it in a file") {
		t.Error("the report does not say the proxy did not say where it came out")
	}
	// Named in a file, it is read.
	mine := filepath.Join(tmp, "exit-headers.json")
	if err := os.WriteFile(mine, []byte(`{"fields": [{"header": "X-Egress", "value": "address"}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if code, _, stderr := exec(t, append(args, "--exit-headers", mine)...); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if page := reportOf(t, path); !strings.Contains(page, "and came out of <span class=\"not-italic\"></span> "+
		"<span class=\"font-mono\">192.0.2.44</span>.") {
		t.Error("the report does not say where the named field said it came out")
	}
	// A file that was named and is not there ends the run before it begins.
	none := filepath.Join(tmp, "none.json")
	if code, _, stderr := exec(t, append(args, "--exit-headers", none)...); code != 1 || !strings.Contains(stderr, none) {
		t.Errorf("exit code = %d, want 1 and the file named\n%s", code, stderr)
	}
}

func TestReportStylesheetCoversTheTemplate(t *testing.T) {
	// report.css is generated from report.html by `make report-css` and
	// committed, so building tls-forge needs nothing but Go. The cost of that
	// is that the two can drift: edit the template, forget to regenerate, and
	// the new classes quietly do nothing. This is the check that they have not.
	// The template's own actions come out first: a class attribute holds
	// branches as well as classes, and `{{if gt .Attempts 1}}` is not a class
	// however it is split on whitespace.
	markup := regexp.MustCompile(`(?s)\{\{.*?\}\}`).ReplaceAllString(reportMarkup, " ")

	classes := map[string]bool{}
	for _, attr := range regexp.MustCompile(`class="([^"]*)"`).FindAllStringSubmatch(markup, -1) {
		for _, name := range strings.Fields(attr[1]) {
			classes[name] = true
		}
	}
	if len(classes) < 30 {
		t.Fatalf("only %d classes found; the scan is not reading the template", len(classes))
	}

	var missing []string
	for name := range classes {
		// Tailwind escapes the characters CSS reserves, so `bg-good/12` is
		// written `.bg-good\/12` and `min-w-[72rem]` `.min-w-\[72rem\]`.
		selector := "." + regexp.MustCompile(`([/.:\[\]%()])`).ReplaceAllString(name, `\$1`)
		if !strings.Contains(reportCSS, selector) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the stylesheet is stale; run `make report-css`.\nmissing: %s",
			strings.Join(missing, " "))
	}
}

func TestSummaryMeterWidths(t *testing.T) {
	s := summarise([]result{
		{Status: 200}, {Status: 200}, {Status: 503}, {Error: "refused"},
	}, time.Second)
	if got := s.SuccessWidth(); got != "50.0000%" {
		t.Errorf("SuccessWidth = %q", got)
	}
	if got := s.WarnWidth(); got != "25.0000%" {
		t.Errorf("WarnWidth = %q", got)
	}
	// A meter for a run of nothing is empty, not a division by zero.
	empty := summarise(nil, time.Second)
	if got := empty.SuccessWidth(); got != "0%" {
		t.Errorf("SuccessWidth of nothing = %q", got)
	}
}

func TestReportRowStates(t *testing.T) {
	// Three states, each with its own glyph, so the colour is never the only
	// thing saying which one it is.
	for _, tc := range []struct {
		name           string
		row            reportRow
		glyph, label   string
		failed, warned bool
	}{
		{"a page", reportRow{result: result{Status: 200}}, "✓", "200", false, false},
		{"a redirect that was followed to a 2xx", reportRow{result: result{Status: 204}}, "✓", "204", false, false},
		{"an answer that is not the page", reportRow{result: result{Status: 503}}, "!", "503", false, true},
		{"nothing came back", reportRow{result: result{Error: "refused"}}, "✕", "no response", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.row.Glyph(); got != tc.glyph {
				t.Errorf("Glyph = %q, want %q", got, tc.glyph)
			}
			if got := tc.row.Outcome(); got != tc.label {
				t.Errorf("Outcome = %q, want %q", got, tc.label)
			}
			if tc.row.Failed() != tc.failed || tc.row.Warned() != tc.warned {
				t.Errorf("Failed = %v, Warned = %v", tc.row.Failed(), tc.row.Warned())
			}
		})
	}
}

func TestTimestampFormatting(t *testing.T) {
	when := time.Date(2026, 8, 16, 0, 54, 6, 868_000_000, time.UTC)
	if got := at(when); got != "16 Aug 2026 00:54:06" {
		t.Errorf("at() = %q, want DD Mon YYYY HH:MM:SS", got)
	}
	// A record that never started has no time to show, rather than the zero one.
	if got := at(time.Time{}); got != "" {
		t.Errorf("at(zero) = %q, want empty", got)
	}
	// The day stays zero-padded and so does the clock, so the columns line up
	// as far as a spelled month lets them.
	if got := at(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != "02 Jan 2026 03:04:05" {
		t.Errorf("at() = %q", got)
	}
}

func TestReportPath(t *testing.T) {
	when := time.Date(2026, 8, 16, 1, 9, 45, 123_000_000, time.UTC)
	stamped := "report-" + stamp(when) + ".html"
	dir := t.TempDir()

	// A directory gets a name of its own, so a run does not need one invented
	// for it and a second run does not land on the first.
	if got := reportPath(dir, formatHTML, when); got != filepath.Join(dir, stamped) {
		t.Errorf("a directory: %q", got)
	}
	// Trailing separator, for a directory that is about to be made.
	notYet := filepath.Join(dir, "runs") + string(os.PathSeparator)
	if got := reportPath(notYet, formatHTML, when); got != filepath.Join(dir, "runs", stamped) {
		t.Errorf("a trailing separator: %q", got)
	}
	// README uses '/', while a Windows shell naturally supplies '\\'. Accept
	// both even before the directory exists, on every platform.
	otherSeparator := `\`
	if os.PathSeparator == '\\' {
		otherSeparator = "/"
	}
	other := filepath.Join(dir, "other") + otherSeparator
	if got := reportPath(other, formatHTML, when); got == other || filepath.Base(got) != stamped {
		t.Errorf("the other platform's separator was not a directory hint: %q", got)
	}

	// A named file is used as given, whether or not it is there already.
	named := filepath.Join(dir, "run.html")
	if got := reportPath(named, formatHTML, when); got != named {
		t.Errorf("a named file: %q", got)
	}
	if err := os.WriteFile(named, nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if got := reportPath(named, formatHTML, when); got != named {
		t.Errorf("a named file that exists: %q", got)
	}

	// Ordered largest unit first, so a directory of them sorts into the order
	// they were made.
	earlier := reportPath(dir, formatHTML, when.Add(-time.Hour))
	if earlier >= reportPath(dir, formatHTML, when) {
		t.Errorf("%q does not sort before %q", earlier, reportPath(dir, formatHTML, when))
	}
}

func TestListNamesTheReportAfterTheRun(t *testing.T) {
	server := pathServer(t)
	dir := t.TempDir()

	code, _, stderr := exec(t, "fetch", "--report="+dir, server.URL+"/one")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	written, err := filepath.Glob(filepath.Join(dir, "report-*.html"))
	if err != nil || len(written) != 1 {
		t.Fatalf("files in the directory: %v, %v", written, err)
	}
	// And says where it went, since the name was not the caller's to predict.
	if !strings.Contains(stderr, written[0]) {
		t.Errorf("stderr does not name the report:\n%s", stderr)
	}
}

func TestReportFileStamp(t *testing.T) {
	when := time.Date(2026, 8, 16, 1, 9, 45, 123_000_000, time.UTC)

	if got := stamp(when); got != "2026-08-16-010945-123" {
		t.Errorf("stamp = %q", got)
	}

	// Zero-padded throughout, and ordered largest unit first, so a directory of
	// them sorts into the order they were made. It contains no colons, so the
	// exact same name is valid on Windows too.
	early := stamp(time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC))
	if early != "2026-01-02-030405-006" {
		t.Errorf("stamp = %q", early)
	}
	if early >= stamp(when) {
		t.Errorf("%q does not sort before %q", early, stamp(when))
	}
}

// FuzzRenderReport checks that a run's own strings cannot break the document
// they land in.
//
// A URL comes from a file someone else may have written and an error message
// from whatever the network said, and both are rendered into a page that gets
// opened in a browser. The contract: never panic, always produce a document,
// and never let either string out as markup.
func FuzzRenderReport(f *testing.F) {
	f.Add("https://example.com/", "", 200)
	f.Add("https://x/?q=<script>alert(1)</script>", `<img src=x onerror="alert(2)">`, 0)
	f.Add("", "", 0)
	f.Add("\x00\xff\xfe", "\xc3\x28", 503)

	f.Fuzz(func(t *testing.T, url, failure string, status int) {
		records := []result{{URL: url, Error: failure, Status: status, Proxy: url}}
		var html strings.Builder
		if err := renderReport(&html, inputOf(records)); err != nil {
			t.Fatalf("renderReport: %v", err)
		}
		out := html.String()
		if !strings.HasPrefix(out, "<!doctype html>") || !strings.Contains(out, "</html>") {
			t.Fatalf("the document is not whole for %q", url)
		}
		// html/template escapes what it is given; this is the check that the
		// template never puts one of these somewhere it would not.
		for _, raw := range []string{"<script>alert(1)", `onerror="alert(2)"`} {
			if strings.Contains(url+failure, raw) && strings.Contains(out, raw) {
				t.Fatalf("%q was written into the document as markup", raw)
			}
		}
	})
}

func rowsFor(n int, failEvery int) []result {
	start := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	rows := make([]result, 0, n)
	for i := range n {
		r := result{
			URL:     fmt.Sprintf("https://example.com/%04d", i),
			Started: start.Add(time.Duration(i) * time.Millisecond),
			Status:  200,
		}
		if failEvery > 0 && i%failEvery == 0 {
			r.Status, r.Error = 0, "refused"
		}
		rows = append(rows, r)
	}
	return rows
}

func TestLimitRows(t *testing.T) {
	t.Run("a table that fits is left alone", func(t *testing.T) {
		rows := rowsFor(10, 0)
		kept, dropped := limitRows(rows, 10)
		if len(kept) != 10 || dropped != 0 {
			t.Errorf("kept %d, dropped %d", len(kept), dropped)
		}
	})

	t.Run("trouble is kept and the rest fills what is left", func(t *testing.T) {
		// 100 rows, every tenth one a failure, room for 20.
		kept, dropped := limitRows(rowsFor(100, 10), 20)
		if len(kept) != 20 || dropped != 80 {
			t.Fatalf("kept %d, dropped %d", len(kept), dropped)
		}
		failures := 0
		for _, r := range kept {
			if r.Failed() {
				failures++
			}
		}
		// All ten of them, because that is what a report is opened for.
		if failures != 10 {
			t.Errorf("%d of the 10 failures survived", failures)
		}
		// Ordering is the renderer's job, checked in TestWriteReport.
	})

	t.Run("more trouble than there is room for", func(t *testing.T) {
		kept, dropped := limitRows(rowsFor(100, 1), 20)
		if len(kept) != 20 || dropped != 80 {
			t.Errorf("kept %d, dropped %d", len(kept), dropped)
		}
	})
}

func TestReportSaysWhatItLeftOut(t *testing.T) {
	// Never silently: a table that quietly stops reads as a complete one.
	records := rowsFor(reportRowLimit+5, 0)
	var html strings.Builder
	if err := renderReport(&html, inputOf(records)); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	if !strings.Contains(html.String(), "5 more rows are not shown") {
		t.Error("the report does not say how many rows it left out")
	}
	if !strings.Contains(html.String(), "The URLs worth looking at") {
		t.Error("the heading still claims to show every URL")
	}
	// And where the rest of them are to be had.
	if !strings.Contains(html.String(), "The same report written as JSON has every request.") {
		t.Error("the report does not say where the rows it left out can be found")
	}
}

func TestReportCards(t *testing.T) {
	// The figures the run ends with on a terminal, where a report has them.
	s := summarise([]result{
		{Status: 200, Bytes: 1_000, Attempts: 2, Millis: 300},
		{Status: 200, Bytes: 1_000, Attempts: 1, Millis: 100, Proxy: "http://p1"},
	}, 2*time.Second)
	s.Passes = 2
	want := []card{
		{Label: "Requests", Value: "2"},
		{Label: "Data", Value: "2.0 kB", Note: "decompressed"},
		{Label: "Retries", Value: "1"},
		{Label: "Elapsed", Value: "2.0s"},
		// What one request took, which two seconds between two of them is not.
		{Label: "Avg time", Value: "200ms", Note: "per request"},
		{Label: "Proxies alive", Value: "1/1", Note: "all carried a page"},
	}
	if got := cards(s); !slices.Equal(got, want) {
		t.Errorf("cards = %+v\nwant    %+v", got, want)
	}

	// A list gone through once is so many URLs, and a proxy nothing came back
	// through is said to have carried nothing.
	dead := summarise([]result{{Proxy: "http://p1", Error: "refused"}}, time.Second)
	got := cards(dead)
	if got[0].Label != "URLs" || got[len(got)-1] != (card{Label: "Proxies alive", Value: "0/1", Note: "1 carried nothing"}) {
		t.Errorf("cards of a run through a dead proxy = %+v", got)
	}
}

func TestSummaryNamesWhatItCounts(t *testing.T) {
	// A list gone through once is so many URLs. Gone through again, or one URL
	// asked for again, a URL is no longer one row.
	if s := (summary{Passes: 1}); s.Things() != "URLs" || s.Thing() != "URL" {
		t.Errorf("one pass counts %q, each a %q", s.Things(), s.Thing())
	}
	if s := (summary{Passes: 3}); s.Things() != "requests" || s.Thing() != "request" {
		t.Errorf("three passes count %q, each a %q", s.Things(), s.Thing())
	}
}

func TestListSaysWhatTheReportLeftOut(t *testing.T) {
	// The cap is announced on the terminal as well as in the document: a table
	// that quietly stops reads as a complete one.
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "run.html")
	urls := []string{server.URL + "/a", server.URL + "/b", server.URL + "/c", server.URL + "/d"}

	args := append([]string{"fetch", "--report=" + path}, urls...)
	code, _, stderr := exec(t, args...)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if want := "  Report        " + path + "  (without 2 of the requests)\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not say what was left out (%q):\n%s", want, stderr)
	}
}

// TestWriteReportToAPathThatIsADirectory reaches the create failure that
// survives the directory being made: the parent exists, so MkdirAll succeeds,
// and the target itself is not a file that can be opened for writing.
func TestWriteReportToAPathThatIsADirectory(t *testing.T) {
	err := writeReport(reportFile{formatHTML, t.TempDir()}, reportInput{command: "fetch"})
	if err == nil {
		t.Error("no error")
	}
}

// The same report, of a fetch.

// reportOf reads back the report a run wrote.
func reportOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	return string(data)
}

func TestFetchWritesAReport(t *testing.T) {
	server, _ := replying(t, 200, 404, 200)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--repeat", "3", "--report="+path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Named last, with the rest of what the run came to.
	if want := "\n  Report        " + path + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming the report (%q):\n%s", want, stderr)
	}

	html := reportOf(t, path)
	for _, want := range []string{
		">tls-forge fetch</h1>",
		"2 of 3 requests in ",
		">Requests</p>",
		"Every request",
		// A row for every run, told apart by which one it was.
		">Run</span>",
		server.URL,
		// Where the runs came out, which was asked while each was made.
		"203.0.113.7", "\U0001F1F5\U0001F1F1",
		"direct",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if got := strings.Count(html, server.URL); got != 3 {
		t.Errorf("the report names the URL %d times, want once for each of three runs", got)
	}
	// In the order the runs were made: the one that was refused is the second.
	page, refused := "✓</span> 200</span>", "!</span> 404</span>"
	first, second, last := strings.Index(html, page), strings.Index(html, refused), strings.LastIndex(html, page)
	if first < 0 || first >= second || second >= last {
		t.Errorf("the rows are not the three runs in order: 200 at %d and %d, 404 at %d", first, last, second)
	}
}

func TestFetchReportOfOneRequest(t *testing.T) {
	// One request has nothing to number, and a directory to put the report in
	// gets a file named after the run.
	server, _ := replying(t, 200)
	dir := t.TempDir()

	code, _, stderr := exec(t, "fetch", "--report="+dir, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	written, _ := filepath.Glob(filepath.Join(dir, "report-*.html"))
	if len(written) != 1 {
		t.Fatalf("the directory holds %v, want one report", written)
	}
	if want := "\n  report written to " + written[0] + "\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not end by naming the report (%q):\n%s", want, stderr)
	}

	html := reportOf(t, written[0])
	// Where it came out was asked before it, which answers for the one request.
	for _, want := range []string{"1 of 1 URLs in ", ">URLs</p>", "Every URL", "once, before the"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if strings.Contains(html, ">Run</span>") {
		t.Error("a single request was numbered")
	}
}

func TestFetchReportsTheRequestThatFailed(t *testing.T) {
	// The run somebody opens a report about is the one that went wrong.
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--report="+path, "--timeout", "3s", "https://127.0.0.1:1/gone")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "\n  report written to "+path+"\n") {
		t.Errorf("stderr does not name the report:\n%s", stderr)
	}
	html := reportOf(t, path)
	for _, want := range []string{"0 of 1 URLs in ", "no response", "https://127.0.0.1:1/gone"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestFetchReportThatCannotBeWritten(t *testing.T) {
	// A parent that is a regular file, so there is nowhere to put the report.
	blocked := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	path := filepath.Join(blocked, "run.html")
	server, _ := replying(t, 200)

	// The page was fetched and handed over all the same. It is the run that did
	// not do everything it was asked.
	code, stdout, stderr := exec(t, "fetch", "--report="+path, server.URL)
	if code != 1 || stdout != "answer-1" {
		t.Errorf("exit code = %d and stdout = %q, want 1 and the page\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "tlsforge: fetch: ") || strings.Contains(stderr, "report written") {
		t.Errorf("stderr does not say the report failed, or says it was written:\n%s", stderr)
	}

	// Several runs say what they came to without a report among it.
	_, _, stderr = exec(t, "fetch", "--repeat", "2", "--report="+path, server.URL)
	if strings.Contains(stderr, "  Report  ") || !strings.Contains(stderr, "  Avg time  ") {
		t.Errorf("the figures name a report that was not written:\n%s", stderr)
	}

	// And when the request failed as well, both are said.
	code, _, stderr = exec(t, "fetch", "--report="+path, "--timeout", "3s", "https://127.0.0.1:1/gone")
	if code != 1 || !strings.Contains(stderr, "127.0.0.1:1") || !strings.Contains(stderr, "a-file") {
		t.Errorf("exit code = %d, and stderr does not give both reasons:\n%s", code, stderr)
	}
}

func TestFetchReportSaysWhatItLeftOut(t *testing.T) {
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	server, _ := replying(t, 200)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--repeat", "3", "--report="+path, server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if want := "  Report        " + path + "  (without 1 of the requests)\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr does not say what the report left out (%q):\n%s", want, stderr)
	}
	html := reportOf(t, path)
	if !strings.Contains(html, "1 more rows are not shown") || !strings.Contains(html, "The requests worth looking at") {
		t.Error("the report does not say that it left a row out")
	}
	// The pages of a request made again are not a record of it, so what the
	// page points at for the rest is the report that has every request.
	if strings.Contains(html, "JSON lines") || !strings.Contains(html, "written as JSON has every request") {
		t.Error("the report does not say where every request can be had")
	}
}

func TestFetchReportWithoutAnAddress(t *testing.T) {
	// Nobody to ask where the run comes out, which the report says rather than
	// leaving a gap.
	askOnly(t)
	server, _ := replying(t, 200)
	path := filepath.Join(t.TempDir(), "run.html")

	if code, _, stderr := exec(t, "fetch", "--report="+path, server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if html := reportOf(t, path); !strings.Contains(html, "nobody could say: no address service to ask.") ||
		strings.Contains(html, "203.0.113.7") {
		t.Error("the report claims to know where the run came out")
	}
}

func TestListReportNumbersTheRunsOfARepeat(t *testing.T) {
	server := pathServer(t)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "fetch", "--repeat", "2", "--report="+path,
		server.URL+"/one")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	html := reportOf(t, path)
	for _, want := range []string{">tls-forge fetch</h1>", "2 of 2 requests in ", "Every request", ">Run</span>"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}
