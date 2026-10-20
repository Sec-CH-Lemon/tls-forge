package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWaitForPassesThePageThatHasIt(t *testing.T) {
	server := pages(t)
	for _, given := range []string{"In stock", `/in stock: \d+/i`} {
		code, stdout, stderr := exec(t, "fetch", "--wait-for", given, server.URL+"/shop")
		if code != 0 || stdout != shop || strings.Contains(stderr, "no text") {
			t.Errorf("%q: exit code = %d, stdout = %q\n%s", given, code, stdout, stderr)
		}
	}
	// Nothing is no check, and a challenge is then as good as the page.
	if code, _, stderr := exec(t, "fetch", "--wait-for", "", server.URL+"/challenge"); code != 0 {
		t.Errorf("no text: exit code = %d\n%s", code, stderr)
	}
}

func TestWaitForFailsA200WithoutIt(t *testing.T) {
	// What it got is still what it prints, being what came back; but it is not
	// the page, and the run fails for it.
	server := pages(t)
	code, stdout, stderr := exec(t, "fetch", "--wait-for", "In stock", server.URL+"/sold")
	if code != 1 || stdout != sold || !strings.Contains(stderr, `✗ 200 OK, no "In stock"`) ||
		!strings.Contains(stderr, `fetch: the page has no text matching "In stock"`) {
		t.Errorf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
}

func TestWaitForIsSaidEverywhereARequestIs(t *testing.T) {
	server := pages(t)
	tmp := t.TempDir()
	report, trace, out := filepath.Join(tmp, "run"), filepath.Join(tmp, "run.trace.json"), filepath.Join(tmp, "out")
	const stock = `/in stock: \d+/i`
	urls := server.URL + "/shop," + server.URL + "/sold," + server.URL + "/gone"
	code, stdout, stderr := exec(t, "fetch", "--wait-for", stock, "-c", "1", "-o", out, "--trace", trace,
		"--report="+report, "--report-format", "html,json", "--urls", urls)
	// The 503 is without it as the 200 is, and is not the page for the same
	// reason: its body says so, and not its status.
	if code != 1 || !strings.Contains(stderr, "fetch: 2 of 3 pages have no text matching "+stock) ||
		strings.Contains(stderr, "no element") {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, want := range []string{"✓ 200 OK", "✗ 200 OK, no " + stock, "✗ 503 Service Unavailable, no " + stock} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the count has no %q:\n%s", want, stderr)
		}
	}

	// The line of JSON for each request.
	got := lines(t, stdout)
	if s, g := got[server.URL+"/sold"], got[server.URL+"/gone"]; s.MissingText != stock || s.MissingElement != "" ||
		got[server.URL+"/shop"].misses() || g.MissingText != stock || !g.Lacked() {
		t.Errorf("the lines say %+v", got)
	}

	// The report, as a document: the run, the request and its try.
	doc := decoded(t, []byte(reportOf(t, report+".json")))
	if s := doc.Summary; s.WaitFor != stock || s.NoText == nil || *s.NoText != 2 || s.WaitForElement != "" ||
		s.NoElement != nil || s.Scraped != 1 || s.Not2xx != 0 || s.SuccessRate != 33.3 {
		t.Errorf("the summary is %+v", s)
	}
	for _, r := range doc.Requests {
		if r.URL != server.URL+"/sold" {
			continue
		}
		if r.MissingText != stock || len(r.Tries) != 1 || r.Tries[0].MissingText != stock ||
			!strings.Contains(r.Tries[0].BodyStart, "Sold out") {
			t.Errorf("the request without the text is %+v", r)
		}
	}

	// And as a page: its row says the status it got and what it did not have,
	// the "+" in it written as the page's template writes one.
	page, shown := reportOf(t, report+".html"), `/in stock: \d&#43;/i`
	for _, want := range []string{
		"200, no " + shown, "503, no " + shown, `2 answers with no <span class="font-mono">` + shown + `</span> (66.7%)`,
		"An answer counts as the page when its body has text matching\n       <span class=\"font-mono\">" + shown +
			"</span>, as --wait-for asked,\n       whatever its status: a 403 with it is the page, and a 200 without it is not",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	// No answer of a run that names what the page has is merely not a 2xx.
	if strings.Contains(page, "answered, not 2xx") {
		t.Error("the report counts answers that were not a 2xx")
	}

	// The log and the trace the request was kept with, and the trace of the run.
	logs, _ := filepath.Glob(filepath.Join(out, "*-2-logs.log"))
	if len(logs) != 1 {
		t.Fatalf("kept %v", keptIn(t, out))
	}
	if log, _ := os.ReadFile(logs[0]); !strings.Contains(string(log), fmt.Sprintf("200 OK · %d B · no text matching %s", len(sold), stock)) {
		t.Errorf("the log of the request without the text:\n%s", log)
	}
	kept := traceFile(t, strings.TrimSuffix(logs[0], logSuffix)+traceSuffix)
	if ended := kept[len(kept)-1]; ended.Args["missing_text"] != stock || ended.Args["missing_element"] != nil {
		t.Errorf("its trace ends as %+v", ended)
	}
	events := traceFile(t, trace)
	// One for the 200 without it, and one for the 503.
	if seen := named(events, phaseInstant, "no text"); len(seen) != 2 || seen[0].Args["text"] != stock {
		t.Errorf("the run's trace says %+v", seen)
	}
	if summed := named(events, phaseInstant, "summary"); len(summed) != 1 || summed[0].Args["no_text"] != 2.0 ||
		summed[0].Args["no_element"] != nil || summed[0].Args["not_2xx"] != 0.0 {
		t.Errorf("the run's summary is %+v", summed)
	}
}

func TestWaitForAndWaitForElementAskBoth(t *testing.T) {
	// The shop has both, the sold-out page the price only, the challenge
	// neither: a line of the exit for each thing, counting the pages without it.
	server := pages(t)
	report := filepath.Join(t.TempDir(), "run")
	urls := server.URL + "/shop," + server.URL + "/sold," + server.URL + "/challenge"
	code, stdout, stderr := exec(t, "fetch", "--wait-for-element", "#price", "--wait-for", "In stock", "-c", "1",
		"--report="+report, "--report-format", "html,json", "--urls", urls)
	if code != 1 || !strings.Contains(stderr, "fetch: 1 of 3 pages have no element matching #price\n") ||
		!strings.Contains(stderr, `fetch: 2 of 3 pages have no text matching "In stock"`) {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, want := range []string{"✓ 200 OK", `✗ 200 OK, no "In stock"`, `✗ 200 OK, no #price and no "In stock"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the count has no %q:\n%s", want, stderr)
		}
	}
	got := lines(t, stdout)
	if c := got[server.URL+"/challenge"]; c.MissingElement != "#price" || c.MissingText != "In stock" ||
		got[server.URL+"/sold"].MissingElement != "" || got[server.URL+"/sold"].MissingText != "In stock" {
		t.Errorf("the lines say %+v", got)
	}
	doc := decoded(t, []byte(reportOf(t, report+".json")))
	if s := doc.Summary; s.WaitForElement != "#price" || s.WaitFor != "In stock" || *s.NoElement != 1 || *s.NoText != 2 ||
		s.Scraped != 1 || s.SuccessRate != 33.3 {
		t.Errorf("the summary is %+v", s)
	}
	page := reportOf(t, report+".html")
	for _, want := range []string{
		"200, no #price and no &#34;In stock&#34;", "200, no &#34;In stock&#34;",
		`2 answers with no <span class="font-mono">#price</span> or no <span class="font-mono">&#34;In stock&#34;</span> (66.7%)`,
		"as --wait-for-element asked, and its body has text matching",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestWaitForAsksAgain(t *testing.T) {
	// A challenge the first time and the page the second: --retry makes the
	// request again, as for a 503, and the run comes to the page.
	server := pages(t)
	code, stdout, stderr := exec(t, "fetch", "--wait-for", "In stock", "--retry", "1", "-v", server.URL+"/flaky")
	if code != 0 || stdout != shop || !strings.Contains(stderr, `try 1 of 2: no text matching "In stock", trying again in`) {
		t.Errorf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	// A 503 without it is asked for again for what it is without, as a 200 is.
	code, _, stderr = exec(t, "fetch", "--wait-for", "In stock", "--retry", "1", "-v", server.URL+"/gone")
	if code != 1 || !strings.Contains(stderr, `try 1 of 2: no text matching "In stock", trying again in`) ||
		strings.Contains(stderr, "HTTP 503") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	// And a 403 with it is the page: nothing to ask for again.
	code, _, stderr = exec(t, "fetch", "--wait-for", "Access Denied", "--retry", "1", "-v", server.URL+"/denied")
	if code != 0 || strings.Contains(stderr, "try 1 of 2") || !strings.Contains(stderr, "✓ 403 Forbidden") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestWaitForThatCannotBeLookedFor(t *testing.T) {
	for _, tc := range []struct{ given, says string }{
		{"/in stock/g", "g is not a flag a regular expression takes"},
		{"//", "is an empty regular expression"},
		{"/a(/", "is not a regular expression"},
	} {
		code, _, stderr := exec(t, "fetch", "--wait-for", tc.given, "https://example.test/")
		if code != 2 || !strings.Contains(stderr, "tlsforge: bad usage: --wait-for") || !strings.Contains(stderr, tc.says) {
			t.Errorf("%q: exit code = %d\n%s", tc.given, code, stderr)
		}
	}
	// A HEAD gets no body to look into.
	code, _, stderr := exec(t, "fetch", "--wait-for", "In stock", "-X", "HEAD", "https://example.test/")
	if code != 2 || !strings.Contains(stderr, "--wait-for and --wait-for-element look into the body, and -X HEAD gets none") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestWaitForDecidesWhateverTheStatus(t *testing.T) {
	// A CDN's block page says what it is in its body, with a 403: named, it is
	// what the run counts as the page, and a 503 without it is not. The status
	// decides nothing.
	server := pages(t)
	tmp := t.TempDir()
	report, out := filepath.Join(tmp, "run"), filepath.Join(tmp, "out")
	const access = "You don't have permission to access "
	code, stdout, stderr := exec(t, "fetch", "--wait-for", access, "-c", "1", "-o", out,
		"--report="+report, "--report-format", "html,json", "--urls", server.URL+"/denied,"+server.URL+"/gone")
	if code != 1 || !strings.Contains(stderr, "✓ 403 Forbidden") ||
		!strings.Contains(stderr, `✗ 503 Service Unavailable, no "You don't have permission to access "`) ||
		!strings.Contains(stderr, `fetch: 1 of 2 pages have no text matching "You don't have permission to access "`) {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	got := lines(t, stdout)
	if d, g := got[server.URL+"/denied"], got[server.URL+"/gone"]; d.misses() || d.Lacked() ||
		g.MissingText != access || !g.Lacked() {
		t.Errorf("the lines say %+v", got)
	}

	doc := decoded(t, []byte(reportOf(t, report+".json")))
	if s := doc.Summary; s.Scraped != 1 || s.Not2xx != 0 || *s.NoText != 1 || s.SuccessRate != 50 {
		t.Errorf("the summary is %+v", s)
	}
	for _, r := range doc.Requests {
		// The 403 is the page, and how its body began is not kept as the reason
		// it was not; the 503's is.
		switch {
		case r.URL == server.URL+"/denied" && (r.misses() || r.Tries[0].BodyStart != ""):
			t.Errorf("the 403 is %+v", r)
		case r.URL == server.URL+"/gone" && !strings.Contains(r.Tries[0].BodyStart, "checking your browser"):
			t.Errorf("the 503 is %+v", r)
		}
	}
	page := reportOf(t, report+".html")
	for _, want := range []string{
		`<span aria-hidden="true">✓</span> 403</span>`,
		`<span aria-hidden="true">✕</span> 503, no &#34;You don&#39;t have permission to access &#34;</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	logs, _ := filepath.Glob(filepath.Join(out, "*-1-logs.log"))
	if len(logs) != 1 {
		t.Fatalf("kept %v", keptIn(t, out))
	}
	if log, _ := os.ReadFile(logs[0]); !strings.Contains(string(log), fmt.Sprintf("outcome  403 Forbidden · %d B\n", len(denied))) {
		t.Errorf("the log of the 403:\n%s", log)
	}
}
