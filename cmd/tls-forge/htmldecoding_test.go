package main

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// greetings is a site that says «Привет» four ways: in UTF-8 HTML that names
// windows-1251, which legacy reads as the UTF-8 it is and Chrome as what it
// names; in windows-1251 HTML that says so, which both read alike; in JSON,
// which both read as UTF-8; and in plain text, which Chrome reads as
// windows-1252.
func greetings(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/named":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<!doctype html><meta charset="windows-1251"><p title="Привет">Привет</p>`)
		case "/cp1251":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<!doctype html><meta charset="windows-1251"><p title="`+
				"\xcf\xf0\xe8\xe2\xe5\xf2"+`">`+"\xcf\xf0\xe8\xe2\xe5\xf2"+`</p>`)
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"greeting":"Привет"}`)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "Привет")
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// outcomes are what each path of a run came to, from its lines of JSON: the
// status, and what it was without.
func outcomes(t *testing.T, stdout string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for url, r := range lines(t, stdout) {
		outcome := strconv.Itoa(r.Status)
		if brief := r.brief(); brief != "" {
			outcome += ", " + brief
		}
		got[url[strings.LastIndex(url, "/"):]] = outcome
	}
	return got
}

func TestHTMLDecodingLegacyIsWhatPageChecksAlwaysDid(t *testing.T) {
	// No flag and legacy named: the same answers, read the same way, to the
	// text and to the element.
	server := greetings(t)
	urls := server.URL + "/named," + server.URL + "/cp1251," + server.URL + "/json," + server.URL + "/text"
	for _, check := range [][]string{{"--wait-for", "Привет"}, {"--wait-for-element", `p[title="Привет"]`},
		{"--wait-for", "/привет/i", "--wait-for-element", "p"}} {
		run := append([]string{"fetch", "--json", "-c", "1", "--urls", urls}, check...)
		code, stdout, stderr := exec(t, run...)
		legacyCode, legacyOut, legacyErr := exec(t, append(run, "--html-decoding", "legacy")...)
		got, legacy := outcomes(t, stdout), outcomes(t, legacyOut)
		if code != legacyCode || len(got) != 4 || len(legacy) != 4 {
			t.Fatalf("%q: exit code %d, legacy %d\n%s\n%s", check, code, legacyCode, stderr, legacyErr)
		}
		for path, outcome := range got {
			if legacy[path] != outcome {
				t.Errorf("%q, %s: %q, legacy %q", check, path, outcome, legacy[path])
			}
		}
	}
	// What legacy reads: UTF-8 is UTF-8, whatever the page names.
	code, stdout, stderr := exec(t, "fetch", "--json", "--wait-for", "Привет", "-c", "1", "--urls", urls)
	if want := map[string]string{"/named": "200", "/cp1251": "200", "/json": "200", "/text": "200"}; code != 0 ||
		!maps.Equal(outcomes(t, stdout), want) {
		t.Errorf("exit code = %d, %v\n%s", code, outcomes(t, stdout), stderr)
	}
}

func TestHTMLDecodingBrowserReadsAPageAsChromeDoes(t *testing.T) {
	server := greetings(t)
	urls := server.URL + "/named," + server.URL + "/cp1251," + server.URL + "/json," + server.URL + "/text"
	code, stdout, stderr := exec(t, "fetch", "--json", "--html-decoding", "browser", "--wait-for", "Привет", "-c",
		"1", "--urls", urls)
	want := map[string]string{"/named": `200, no "Привет"`, "/cp1251": "200", "/json": "200",
		"/text": `200, no "Привет"`}
	if got := outcomes(t, stdout); code != 1 || !maps.Equal(got, want) ||
		!strings.Contains(stderr, `fetch: 2 of 4 pages have no text matching "Привет"`) {
		t.Errorf("exit code = %d, %v\n%s", code, got, stderr)
	}
	// What Chrome shows of the UTF-8 page that names windows-1251, it finds;
	// and the element only as Chrome reads its attribute.
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--wait-for", "РџСЂРёРІРµС‚"}, 0},
		{[]string{"--wait-for-element", `p[title="Привет"]`}, 1},
		{[]string{"--wait-for-element", `p[title="РџСЂРёРІРµС‚"]`}, 0},
	} {
		args := append([]string{"fetch", "--html-decoding", "browser", server.URL + "/named"}, tc.args...)
		if code, _, stderr := exec(t, args...); code != tc.code {
			t.Errorf("%q: exit code = %d, want %d\n%s", tc.args, code, tc.code, stderr)
		}
	}
}

func TestHTMLDecodingIsSaidInTheReportAndTheLog(t *testing.T) {
	server := greetings(t)
	for _, tc := range []struct {
		args              []string
		decoding, footer  string
		notInFooter       string
		code              int
		loggedAs, summary string
	}{
		{[]string{"--html-decoding", "browser", "--wait-for", "Привет"}, "browser",
			"It is read as Chrome decodes a document of its type, as\n       --html-decoding browser asked.",
			"It is read in the encoding", 1, "browser", "browser"},
		{[]string{"--wait-for", "Привет"}, "legacy",
			"It is read in the encoding its byte order mark or Content-Type names, else as\n       UTF-8 when it is " +
				"UTF-8 throughout, whatever a &lt;meta&gt; says, as --html-decoding legacy\n       does.",
			"as Chrome decodes", 0, "legacy", "legacy"},
		// Nothing looked for: nothing said of how it would have been read.
		{nil, "", "", "It is read as", 0, "legacy", ""},
	} {
		tmp := t.TempDir()
		report, log := filepath.Join(tmp, "run"), filepath.Join(tmp, "run.jsonl")
		args := append([]string{"fetch", "--report=" + report, "--report-format", "html,json", "--log", log,
			server.URL + "/named"}, tc.args...)
		code, _, stderr := exec(t, args...)
		if code != tc.code {
			t.Fatalf("%q: exit code = %d\n%s", tc.args, code, stderr)
		}
		if doc := decoded(t, []byte(reportOf(t, report+".json"))); doc.Summary.HTMLDecoding != tc.summary {
			t.Errorf("%q: the summary says %q", tc.args, doc.Summary.HTMLDecoding)
		}
		page := reportOf(t, report+".html")
		if tc.footer != "" && !strings.Contains(page, tc.footer) || strings.Contains(page, tc.notInFooter) {
			t.Errorf("%q: the report's footer is not as it should be:\n%s", tc.args,
				page[strings.Index(page, "<footer"):])
		}
		if run := recordsOf(logRecords(t, log), "run"); len(run) != 1 || run[0].get("html_decoding") != tc.loggedAs {
			t.Errorf("%q: the run was logged as %v", tc.args, run)
		}
	}
}
