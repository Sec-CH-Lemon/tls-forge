package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// pages answers /shop with a page that has a #price and says it is in stock,
// /sold with one that has the price and says it is sold out, /flaky with a page
// that has neither the first time it is asked and the shop after, /gone with a
// 503, /denied with a 403 that is a CDN's block page, /forbidden-shop with the
// shop under a 403, and anything else with a 200 that is somebody's challenge
// rather than the page.
func pages(t *testing.T) *httptest.Server {
	t.Helper()
	var flaky atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case r.URL.Path == "/shop", r.URL.Path == "/flaky" && flaky.Add(1) > 1:
			_, _ = io.WriteString(w, shop)
		case r.URL.Path == "/sold":
			_, _ = io.WriteString(w, sold)
		case r.URL.Path == "/gone":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, challenge)
		case r.URL.Path == "/denied":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, denied)
		case r.URL.Path == "/forbidden-shop":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, shop)
		default:
			_, _ = io.WriteString(w, challenge)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestWaitForElementPassesThePageThatHasIt(t *testing.T) {
	server := pages(t)
	code, stdout, stderr := exec(t, "fetch", "--wait-for-element", "#price", server.URL+"/shop")
	if code != 0 || stdout != shop || strings.Contains(stderr, "no element") {
		t.Errorf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
}

func TestWaitForElementFailsA200WithoutIt(t *testing.T) {
	// The page it got is still what it prints, being what came back; but it is
	// not the page, and the run fails for it.
	server := pages(t)
	code, stdout, stderr := exec(t, "fetch", "--wait-for-element", "#price", server.URL+"/challenge")
	if code != 1 || stdout != challenge || !strings.Contains(stderr, "✗ 200 OK, no #price") ||
		!strings.Contains(stderr, "fetch: the page has no element matching #price") {
		t.Errorf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
}

func TestWaitForElementIsSaidEverywhereARequestIs(t *testing.T) {
	server := pages(t)
	tmp := t.TempDir()
	report, trace, out := filepath.Join(tmp, "run"), filepath.Join(tmp, "run.trace.json"), filepath.Join(tmp, "out")
	urls := server.URL + "/shop," + server.URL + "/challenge," + server.URL + "/gone"
	code, stdout, stderr := exec(t, "fetch", "--wait-for-element", "#price", "-c", "1", "-o", out, "--trace", trace,
		"--report="+report, "--report-format", "html,json", "--urls", urls)
	// The 503 is without it as the 200 is, and is not the page for the same
	// reason: its body says so, and not its status.
	if code != 1 || !strings.Contains(stderr, "fetch: 2 of 3 pages have no element matching #price") {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, want := range []string{"✓ 200 OK", "✗ 200 OK, no #price", "✗ 503 Service Unavailable, no #price"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the count has no %q:\n%s", want, stderr)
		}
	}

	// The line of JSON for each request.
	got := lines(t, stdout)
	if got[server.URL+"/challenge"].MissingElement != "#price" || got[server.URL+"/shop"].Lacked() ||
		got[server.URL+"/gone"].MissingElement != "#price" {
		t.Errorf("the lines say %+v", got)
	}

	// The report, as a document: the run, the request and its try.
	doc := decoded(t, []byte(reportOf(t, report+".json")))
	if s := doc.Summary; s.WaitForElement != "#price" || s.NoElement == nil || *s.NoElement != 2 || s.Scraped != 1 ||
		s.Not2xx != 0 || s.SuccessRate != 33.3 {
		t.Errorf("the summary is %+v", s)
	}
	for _, r := range doc.Requests {
		if r.URL != server.URL+"/challenge" {
			continue
		}
		if r.MissingElement != "#price" || len(r.Tries) != 1 || r.Tries[0].MissingElement != "#price" ||
			!strings.Contains(r.Tries[0].BodyStart, "checking your browser") {
			t.Errorf("the request without the element is %+v", r)
		}
	}

	// And as a page: its row says the status it got and what it did not have.
	page := reportOf(t, report+".html")
	for _, want := range []string{
		"200, no #price", "503, no #price", "2 answers with no <span class=\"font-mono\">#price</span> (66.7%)",
		"An answer counts as the page when its HTML has an element matching\n       <span class=\"font-mono\">#price</span>, " +
			"as --wait-for-element asked,\n       whatever its status",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}

	// The log and the trace the request was kept with, and the trace of the run.
	logs, _ := filepath.Glob(filepath.Join(out, "*-2.log"))
	if len(logs) != 1 {
		t.Fatalf("kept %v", keptIn(t, out))
	}
	if log, _ := os.ReadFile(logs[0]); !strings.Contains(string(log), fmt.Sprintf("200 OK · %d B · no element matching #price", len(challenge))) {
		t.Errorf("the log of the request without the element:\n%s", log)
	}
	kept := traceFile(t, filepath.Join(out, "trace-"+strings.TrimSuffix(filepath.Base(logs[0]), ".log")+".json"))
	if ended := kept[len(kept)-1]; ended.Args["missing_element"] != "#price" {
		t.Errorf("its trace ends as %+v", ended)
	}
	events := traceFile(t, trace)
	if seen := named(events, phaseInstant, "no element"); len(seen) != 2 || seen[0].Args["selector"] != "#price" {
		t.Errorf("the run's trace says %+v", seen)
	}
	if summed := named(events, phaseInstant, "summary"); len(summed) != 1 || summed[0].Args["no_element"] != 2.0 {
		t.Errorf("the run's summary is %+v", summed)
	}
}

func TestWaitForElementAsksAgain(t *testing.T) {
	// A challenge the first time and the page the second: --retry makes the
	// request again, as for a 503, and the run comes to the page.
	server := pages(t)
	path := filepath.Join(t.TempDir(), "run.json")
	code, stdout, stderr := exec(t, "fetch", "--wait-for-element", "#price", "--retry", "1", "-v",
		"--report="+path, server.URL+"/flaky")
	if code != 0 || stdout != shop || !strings.Contains(stderr, "try 1 of 2: no element matching #price, trying again in") {
		t.Fatalf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	r := decoded(t, []byte(reportOf(t, path))).Requests[0]
	var missing []string
	for _, try := range r.Tries {
		missing = append(missing, try.MissingElement)
	}
	if r.Attempts != 2 || r.misses() || !slices.Equal(missing, []string{"#price", ""}) {
		t.Errorf("the request was %d tries, without %+v, its tries %q", r.Attempts, r.finding, missing)
	}
}

func TestWaitForElementDecidesWhateverTheStatus(t *testing.T) {
	// The shop under a 403 is the page, and a challenge under a 200 is not.
	server := pages(t)
	code, _, stderr := exec(t, "fetch", "--wait-for-element", "#price", "-c", "1",
		"--urls", server.URL+"/forbidden-shop,"+server.URL+"/challenge")
	if code != 1 || !strings.Contains(stderr, "✓ 403 Forbidden") || !strings.Contains(stderr, "✗ 200 OK, no #price") ||
		!strings.Contains(stderr, "fetch: 1 of 2 pages have no element matching #price") || strings.Contains(stderr, "→") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestWaitForElementThatCannotBeLookedFor(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "--wait-for-element", "div[", "https://example.test/")
	if code != 2 || !strings.Contains(stderr, `--wait-for-element "div[" is not a CSS selector`) {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	// A HEAD gets no body to look into, in whatever case it is written.
	code, _, stderr = exec(t, "fetch", "--wait-for-element", "#price", "--method", "head", "https://example.test/")
	if code != 2 || !strings.Contains(stderr, "into the body, and -X HEAD gets none") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestAPageWithoutWhatThePageHasInTheCount(t *testing.T) {
	// Under its status and what it was without, after the ones of that status
	// that were not without anything, and before the ones that got nothing. One
	// without what the page has is not the page, whatever its status; one whose
	// body was looked into and had it is, whatever its status; one whose body was
	// not looked into is what its status says.
	without, page := finding{MissingElement: "#price", looked: true}, finding{looked: true}
	other := finding{MissingElement: "#cart", looked: true}
	p := newProgress(15)
	for _, r := range []result{
		{Status: 200}, {Status: 200}, {Status: 200, finding: without}, {Status: 200, finding: other},
		{Status: 200, finding: without}, {Status: 203, finding: without}, {Status: 503},
		{Status: 403, finding: page}, {Status: 403}, {Status: 403, finding: without}, {Status: 403, finding: page},
		{Status: 301, finding: without}, {Status: 301}, {Status: 301, finding: page}, {Error: "refused"},
	} {
		p.begin()
		p.finish(r)
	}
	var rows []string
	for _, row := range p.tallies() {
		rows = append(rows, fmt.Sprintf("%s %s %d", verdictMark[row.how], row.label, row.count))
	}
	want := []string{"✓ 200 OK 2", "✗ 200 OK, no #cart 1", "✗ 200 OK, no #price 2",
		"✗ 203 Non-Authoritative Information, no #price 1",
		"✓ 301 Moved Permanently 1", "→ 301 Moved Permanently 1", "✗ 301 Moved Permanently, no #price 1",
		"✓ 403 Forbidden 2", "✗ 403 Forbidden 1", "✗ 403 Forbidden, no #price 1",
		"✗ 503 Service Unavailable 1", "✗ no response 1"}
	if !slices.Equal(rows, want) {
		t.Errorf("rows %q\nwant %q", rows, want)
	}
	// The pages: the two 200s, the 403s and the 301 that had what it has.
	if rate := p.summary()[2]; rate[1] != "33.3%" {
		t.Errorf("the success rate is %q", rate[1])
	}
	if line := verboseLine(result{Status: 403, finding: without, URL: "https://example.test/"}); !strings.HasSuffix(line,
		"  no element matching #price") {
		t.Errorf("verboseLine = %q", line)
	}
	if line := verboseLine(result{Status: 403, finding: page, URL: "https://example.test/"}); strings.Contains(line, "  no ") {
		t.Errorf("verboseLine = %q", line)
	}
}

func TestAPageWithoutWhatThePageHasIsTrouble(t *testing.T) {
	lacked := result{Status: 200, finding: finding{MissingElement: "#price", looked: true}}
	records := []result{
		{Status: 200}, lacked, {Status: 503}, {Error: "x"},
		// Whatever the status: without it, not the page; with it, the page.
		{Status: 503, finding: finding{MissingElement: "#price", looked: true}}, {Status: 403, finding: finding{looked: true}},
	}
	s := summarise(records, 0)
	if s.Succeeded != 2 || s.Lacked != 2 || s.NoElement != 2 || s.Warned != 1 || s.Failed != 1 ||
		s.LackRate() != "33.3%" {
		t.Errorf("summarise = %+v", s)
	}
	// One outcome each, even of a finding that says something is missing of a
	// body it does not say was looked into.
	odd := result{Status: 404, finding: finding{MissingElement: "#price"}}
	if !odd.Lacked() || odd.Warned() || odd.Failed() {
		t.Errorf("%+v: lacked %v, warned %v", odd, odd.Lacked(), odd.Warned())
	}
	// Kept with the others in trouble when a report has to leave rows out, and
	// with its tries while there is room for those.
	kept, dropped := limitRows([]result{{Status: 200, URL: "a"}, lacked, {Status: 200, URL: "b"}}, 1)
	if len(kept) != 1 || kept[0].MissingElement != "#price" || dropped != 2 {
		t.Errorf("limitRows kept %+v, dropped %d", kept, dropped)
	}
	var budget tryBudget
	budget.fine = reportRowLimit
	if got := budget.trim(result{finding: finding{MissingElement: "#price", looked: true}, Tries: []try{{}}}); len(got.Tries) != 1 {
		t.Error("a request without the element was counted as fine for its tries")
	}
	for _, tc := range []struct {
		row            reportRow
		glyph, outcome string
	}{
		{reportRow{result: lacked}, "✕", "200, no #price"},
		{reportRow{result: records[2]}, "!", "503"},
		{reportRow{result: records[4]}, "✕", "503, no #price"},
		{reportRow{result: records[5]}, "✓", "403"},
	} {
		if tc.row.Glyph() != tc.glyph || tc.row.Outcome() != tc.outcome {
			t.Errorf("the row is %s %s, want %s %s", tc.row.Glyph(), tc.row.Outcome(), tc.glyph, tc.outcome)
		}
	}
	// And a try of each, as its row in the report shows it.
	for _, tc := range []struct {
		try            try
		lacked, warned bool
		glyph          string
	}{
		{try{Status: 403, finding: finding{looked: true}}, false, false, "✓"},
		{try{Status: 403}, false, true, "!"},
		{try{Status: 403, finding: finding{MissingElement: "#price", looked: true}}, true, false, "✕"},
		{try{Status: 200, finding: finding{MissingElement: "#price", looked: true}}, true, false, "✕"},
	} {
		row := tryRow{try: tc.try}
		if row.Lacked() != tc.lacked || row.Warned() != tc.warned || row.Glyph() != tc.glyph {
			t.Errorf("%+v: lacked %v, warned %v, %s", tc.try, row.Lacked(), row.Warned(), row.Glyph())
		}
	}
}
