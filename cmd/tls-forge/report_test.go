package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// standInIPService answers the way the real one does, so no test reaches a
// service on the internet to find out what its own address is.
func standInIPService(t *testing.T, body string, status int) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	original := ipService
	t.Cleanup(func() { ipService = original })
	ipService = server.URL
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
	records := []result{
		{URL: "https://a/", Status: 200, Bytes: 1_000, Attempts: 1},
		{URL: "https://b/", Status: 200, Bytes: 2_000, Attempts: 3, Proxy: "http://good"},
		{URL: "https://c/", Attempts: 2, Proxy: "http://dead", Error: "refused"},
		{URL: "https://d/", Attempts: 2, Proxy: "http://dead", Error: "refused"},
		// A response that is not the page: neither scraped nor a dead connection.
		{URL: "https://e/", Status: 503, Bytes: 500, Attempts: 1, Proxy: "http://good"},
	}
	s := summarise(records, 90*time.Second, map[string]egress{
		"http://good": {IP: "203.0.113.7", Country: "PL"},
	})

	if s.Total != 5 || s.Succeeded != 2 || s.Warned != 1 || s.Failed != 2 {
		t.Errorf("counts: %+v", s)
	}
	if s.Bytes != 3_500 {
		t.Errorf("Bytes = %d", s.Bytes)
	}
	// One attempt is the request; the rest are retries. 0 + 2 + 1 + 1 + 0.
	if s.Retries != 4 {
		t.Errorf("Retries = %d, want 4", s.Retries)
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
	if s.Proxies[1].Exit.IP != "203.0.113.7" {
		t.Errorf("the live proxy lost its address: %+v", s.Proxies[1])
	}
}

func TestSummaryTable(t *testing.T) {
	s := summarise([]result{
		{URL: "https://a/", Status: 200, Bytes: 1_000, Attempts: 1},
		{URL: "https://b/", Attempts: 2, Proxy: "http://dead", Error: "refused"},
	}, 3*time.Minute, nil)
	s.Output = "results.jsonl"

	table := s.table()
	for _, want := range []string{
		"2 URLs in 3m00s",
		"Scraped      1  (50.0%)",
		"Not 2xx      0  (0.0%)",
		"No response  1  (50.0%)",
		"1.0 kB",
		"Retries      1",
		"1 used, 0 alive, some direct",
		// Named, not just counted: "0 alive" does not say which one to replace.
		"dead proxy   http://dead  (1 requests, none came back)",
		"results.jsonl",
	} {
		if !strings.Contains(table, want) {
			t.Errorf("the table has no %q:\n%s", want, table)
		}
	}
}

func TestSummaryOfNothing(t *testing.T) {
	// A percentage of nothing is 0%, not a division by zero.
	s := summarise(nil, time.Second, nil)
	if got := s.table(); !strings.Contains(got, "0  (0.0%)") {
		t.Errorf("table: %s", got)
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
		},
		{
			URL: "https://first/", Started: started, Ended: started.Add(300 * time.Millisecond),
			Millis: 300, Attempts: 3, Error: "no route to host",
		},
	}
	exits := map[string]egress{"http://p1": {IP: "203.0.113.7", Country: "PL"}}
	s := summarise(records, 2*time.Second, exits)

	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeReport(path, records, s, exits); err != nil {
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
		"not looked up",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %q", want)
		}
	}

	// In start order, so the failed one that went out first comes first.
	if strings.Index(html, "https://first/") > strings.Index(html, "https://second/") {
		t.Error("the rows are not in the order the requests went out")
	}

	// Self-contained: nothing is fetched from anywhere when this is opened.
	for _, forbidden := range []string{"<script", "src=", "@import", "<link", "url(http"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the report reaches outside itself: %q", forbidden)
		}
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
	if err := writeReport(path, records, summarise(records, time.Second, nil), nil); err != nil {
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
	err := writeReport(filepath.Join(t.TempDir(), "no-such-directory", "r.html"), nil, summary{}, nil)
	if err == nil {
		t.Error("no error")
	}
}

func TestLookupExit(t *testing.T) {
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL","city":"Warsaw"}`, http.StatusOK)

	client, err := tlsforgeClient(t)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	found, err := lookupExit(client)
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			standInIPService(t, tc.body, tc.status)
			client, err := tlsforgeClient(t)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			defer func() { _ = client.Close() }()

			if _, err := lookupExit(client); err == nil {
				t.Error("no error")
			}
		})
	}

	t.Run("a service that cannot be reached", func(t *testing.T) {
		original := ipService
		t.Cleanup(func() { ipService = original })
		ipService = "https://127.0.0.1:1/"

		client, err := tlsforgeClient(t)
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		defer func() { _ = client.Close() }()

		if _, err := lookupExit(client); err == nil {
			t.Error("no error")
		}
	})
}

func TestBatchWritesAReport(t *testing.T) {
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)
	server := batchServer(t)
	path := filepath.Join(t.TempDir(), "run.html")

	code, _, stderr := exec(t, "batch", "--report", path, "--insecure",
		server.URL+"/one", server.URL+"/two")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}

	// The table lands on stderr, with everything else that is commentary.
	for _, want := range []string{"Ran", "2 URLs", "Scraped", "100.0%", "Retries"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	// And the third party is named rather than contacted quietly.
	if !strings.Contains(stderr, ipService) {
		t.Errorf("the lookup was not announced:\n%s", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	for _, want := range []string{server.URL + "/one", "203.0.113.7", "\U0001F1F5\U0001F1F1"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestBatchReportWithoutTheAddressLookup(t *testing.T) {
	// --report-ip=false, so nothing is asked of anyone.
	original := ipService
	t.Cleanup(func() { ipService = original })
	ipService = "https://127.0.0.1:1/" // would fail loudly if it were reached

	server := batchServer(t)
	path := filepath.Join(t.TempDir(), "run.html")
	code, _, stderr := exec(t, "batch", "--report", path, "--report-ip=false", server.URL+"/one")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if strings.Contains(stderr, "asking") {
		t.Errorf("a lookup was announced anyway:\n%s", stderr)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "not looked up") {
		t.Error("the report does not say the address was not looked up")
	}
}

func TestBatchReportToAPathThatWillNotOpen(t *testing.T) {
	server := batchServer(t)
	code, _, _ := exec(t, "batch", "--report",
		filepath.Join(t.TempDir(), "nope", "r.html"), "--report-ip=false", server.URL+"/one")
	if code == 0 {
		t.Error("an unwritable report path should fail")
	}
}

func TestBatchSummaryNamesADeadProxy(t *testing.T) {
	// The question the summary exists for: which of my proxies is the reason
	// those pages are missing.
	server := batchServer(t)
	path := writeList(t, "dead.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/one,http://127.0.0.1:9001\n%[1]s/two,\n", server.URL))

	code, _, stderr := exec(t, "batch", "--input", path, "--timeout", "5s")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	for _, want := range []string{"1 used, 0 alive", "dead proxy", "127.0.0.1:9001", "50.0%"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
}

// tlsforgeClient is a plain client that will talk to a stand-in server's
// self-signed certificate.
func tlsforgeClient(t *testing.T) (*tlsforge.Client, error) {
	t.Helper()
	return tlsforge.New(tlsforge.WithInsecureSkipVerify())
}

func TestRenderReportReportsAWriteFailure(t *testing.T) {
	// A full disk part way through the document.
	if err := renderReport(failingWriter{}, nil, summary{}, nil); err == nil {
		t.Error("no error")
	}
}

func TestBatchReportWithAProxyThatCannotBeBuilt(t *testing.T) {
	// The proxy column had a typo, so the URL failed and there is no client to
	// ask where it would have come out. The report is still written, and says
	// the address was not looked up rather than failing the run.
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)
	server := batchServer(t)
	list := writeList(t, "typo.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/bad,::not a proxy::\n%[1]s/good,\n", server.URL))

	path := filepath.Join(t.TempDir(), "run.html")
	code, _, stderr := exec(t, "batch", "--input", list, "--report", path, "--insecure")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if !strings.Contains(string(data), "not looked up") {
		t.Error("the report claims to know where a broken proxy came out")
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
	}, time.Second, nil)
	if got := s.SuccessWidth(); got != "50.0000%" {
		t.Errorf("SuccessWidth = %q", got)
	}
	if got := s.WarnWidth(); got != "25.0000%" {
		t.Errorf("WarnWidth = %q", got)
	}
	// A meter for a run of nothing is empty, not a division by zero.
	empty := summarise(nil, time.Second, nil)
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
	if got := reportPath(dir, when); got != filepath.Join(dir, stamped) {
		t.Errorf("a directory: %q", got)
	}
	// Trailing separator, for a directory that is about to be made.
	notYet := filepath.Join(dir, "runs") + string(os.PathSeparator)
	if got := reportPath(notYet, when); got != filepath.Join(dir, "runs", stamped) {
		t.Errorf("a trailing separator: %q", got)
	}

	// A named file is used as given, whether or not it is there already.
	named := filepath.Join(dir, "run.html")
	if got := reportPath(named, when); got != named {
		t.Errorf("a named file: %q", got)
	}
	if err := os.WriteFile(named, nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if got := reportPath(named, when); got != named {
		t.Errorf("a named file that exists: %q", got)
	}

	// Ordered largest unit first, so a directory of them sorts into the order
	// they were made.
	earlier := reportPath(dir, when.Add(-time.Hour))
	if earlier >= reportPath(dir, when) {
		t.Errorf("%q does not sort before %q", earlier, reportPath(dir, when))
	}
}

func TestBatchNamesTheReportAfterTheRun(t *testing.T) {
	server := batchServer(t)
	dir := t.TempDir()

	code, _, stderr := exec(t, "batch", "--report", dir, "--report-ip=false", server.URL+"/one")
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

	original := goos
	t.Cleanup(func() { goos = original })

	goos = "darwin"
	if got := stamp(when); got != "2026-08-16-01:09:45:123" {
		t.Errorf("stamp = %q", got)
	}
	// Windows forbids a colon in a file name: there it means an alternate data
	// stream, and os.Create fails on one.
	goos = "windows"
	if got := stamp(when); got != "2026-08-16-01-09-45-123" {
		t.Errorf("stamp on windows = %q", got)
	}

	// Zero-padded throughout, and ordered largest unit first, so a directory of
	// them sorts into the order they were made.
	goos = "linux"
	early := stamp(time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC))
	if early != "2026-01-02-03:04:05:006" {
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
		if err := renderReport(&html, records, summarise(records, time.Second, nil), nil); err != nil {
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
	if err := renderReport(&html, records, summarise(records, time.Second, nil), nil); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	if !strings.Contains(html.String(), "5 more rows are not shown") {
		t.Error("the report does not say how many rows it left out")
	}
	if !strings.Contains(html.String(), "The URLs worth looking at") {
		t.Error("the heading still claims to show every URL")
	}
}

func TestLookupExitsStopsAskingAfterAWhile(t *testing.T) {
	// One request each, to somebody else's free service. A rotating list can
	// name thousands of proxies; asking about every one would earn the rate
	// limit it deserves.
	standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)

	fs := newFlagSet("batch", newPrinter(io.Discard))
	flags := addClientFlags(fs)
	if err := parse(fs, []string{"--insecure"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	clients := newPool(flags, "")
	defer clients.close()

	records := make([]result, 0, exitLookupLimit+7)
	for i := range exitLookupLimit + 7 {
		records = append(records, result{URL: "https://x/", Proxy: fmt.Sprintf("http://p%d:8080", i)})
	}

	exits, skipped := lookupExits(clients, records)
	if skipped != 7 {
		t.Errorf("skipped = %d, want 7", skipped)
	}
	// The ones it did ask about are unreachable proxies, so none answered; what
	// is being checked is that it stopped asking.
	if len(exits) != 0 {
		t.Errorf("unreachable proxies answered: %v", exits)
	}
}

func TestEither(t *testing.T) {
	if got := either("results.jsonl", "the JSON lines"); got != "results.jsonl" {
		t.Errorf("either = %q", got)
	}
	if got := either("", "the JSON lines"); got != "the JSON lines" {
		t.Errorf("either = %q", got)
	}
}

func TestBatchSaysWhatTheReportLeftOut(t *testing.T) {
	// The caps are announced on the terminal as well as in the document. A
	// table that quietly stops, and a set of addresses that quietly is not
	// looked up, both read as complete.
	original := reportRowLimit
	t.Cleanup(func() { reportRowLimit = original })
	reportRowLimit = 2

	server := batchServer(t)
	path := filepath.Join(t.TempDir(), "run.html")
	urls := []string{server.URL + "/a", server.URL + "/b", server.URL + "/c", server.URL + "/d"}

	args := append([]string{"batch", "--report", path, "--report-ip=false",
		"--output", os.DevNull}, urls...)
	code, _, stderr := exec(t, args...)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "2 rows are in "+os.DevNull+" but not in the report") {
		t.Errorf("stderr does not say what was left out:\n%s", stderr)
	}
}

func TestBatchSaysWhichProxiesItDidNotAskAbout(t *testing.T) {
	original := exitLookupLimit
	t.Cleanup(func() { exitLookupLimit = original })
	exitLookupLimit = 1

	standInIPService(t, `{"ip":"203.0.113.7","country":"PL"}`, http.StatusOK)
	server := batchServer(t)
	list := writeList(t, "many.csv", fmt.Sprintf(
		"url,proxy\n%[1]s/a,http://127.0.0.1:9001\n%[1]s/b,http://127.0.0.1:9002\n", server.URL))

	path := filepath.Join(t.TempDir(), "run.html")
	_, _, stderr := exec(t, "batch", "--input", list, "--report", path, "--timeout", "5s")
	if !strings.Contains(stderr, "1 further proxies were not asked about") {
		t.Errorf("stderr does not say which proxies went unasked:\n%s", stderr)
	}
}
