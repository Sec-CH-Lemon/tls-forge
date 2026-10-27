package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// TestBrowserHelper is the browser the end-to-end test launches: this test
// binary, opening the page it is given as tls-forge, as Chrome opens the
// capture page, so that the comparison has a browser to measure without one
// installed.
func TestBrowserHelper(t *testing.T) {
	url := os.Getenv("TLSFORGE_BROWSER_HELPER")
	if url == "" {
		t.Skip("not running as the browser stand-in")
	}
	browserProfile, err := profile.Get("chrome")
	if err != nil {
		os.Exit(1)
	}
	client, err := tlsforge.New(tlsforge.WithProfile(browserProfile.Name), tlsforge.WithInsecureSkipVerify(),
		tlsforge.WithoutRedirects())
	if err != nil {
		os.Exit(1)
	}
	defer client.Close()
	page, err := client.Do(&tlsforge.Request{URL: url, Header: tlsforge.NewHeader(
		"sec-fetch-site", "none", "sec-fetch-mode", "navigate", "sec-fetch-user", "?1", "sec-fetch-dest", "document",
	)})
	if err != nil {
		os.Exit(1)
	}
	if strings.Contains(url, "http1=cold") {
		os.Exit(0)
	}
	const marker = "fetch('"
	start := strings.Index(page.Text(), marker) + len(marker)
	end := strings.IndexByte(page.Text()[start:], '\'')
	navigator, _ := json.Marshal(map[string]string{"user_agent": browserProfile.UserAgent})
	final, _ := neturl.Parse(page.URL)
	// As the capture page's script posts its report.
	if _, err := client.Do(&tlsforge.Request{Method: "POST", URL: final.Scheme + "://" + final.Host +
		page.Text()[start:start+end], Body: navigator, Header: tlsforge.NewHeader("content-type", "application/json"),
		Browser: &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: page.URL}}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// bench is what a run is given: the browser, this test binary, and the
// fixtures of what a page does it is held to.
type bench struct {
	browser, requests, decoding string
}

// scenario is the one scenario the test fixture holds: what a page asks for,
// in nothing a machine or a profile decides.
var scenario = harness.MeasuredScenario{Note: "a page",
	H2: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/x", Headers: [][2]string{{":method", "GET"}, {"accept", "*/*"}}}},
	H1: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/x", Headers: [][2]string{{"Host", "www.example.com"}, {"Accept", "*/*"}}}},
}

// page is the one page the test fixture of decodings holds.
var page = harness.DecodingCase{Name: "page", Body: []byte("<p>a</p>"), Word: []byte("a"), Encoding: "UTF-8", Text: ptr("a")}

func ptr(s string) *string { return &s }

// thisPlatform is the platform this test runs on, as a release names it.
func thisPlatform() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

// stableOf is a version of Google Chrome Stable of the major the profile
// "chrome" is, whichever Chrome that is when the test runs.
func stableOf(t *testing.T) string {
	t.Helper()
	p, err := profile.Get("chrome")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	sent := majorSent.FindStringSubmatch(p.UserAgent)
	if sent == nil {
		t.Fatalf("no major of Chrome in %q", p.UserAgent)
	}
	return sent[1] + ".0.8059.80"
}

// laidOut writes the fixtures a run is held to, and names this test binary as
// the browser.
func laidOut(t *testing.T) bench {
	t.Helper()
	root := t.TempDir()
	b := bench{requests: filepath.Join(root, "requests.json"), decoding: filepath.Join(root, "decoding.json")}
	if err := (&harness.RequestsFixture{Scenarios: map[string]harness.MeasuredScenario{"x": scenario}}).Write(b.requests); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := (&harness.DecodingFixture{Cases: []harness.DecodingCase{page}}).Write(b.decoding); err != nil {
		t.Fatalf("Write: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	b.browser = self
	return b
}

func (b bench) args(more ...string) []string {
	return append([]string{"--browser", b.browser, "--requests", b.requests, "--decoding", b.decoding}, more...)
}

type comparer = func(context.Context, tlsforge.MeasureOptions, ...tlsforge.Option) (*tlsforge.Comparison, error)

// seams sets, for one test, what the browser says it is and what the
// comparison gives; and on the bench, the browser is what the fixtures say.
func seams(t *testing.T, said string, compared comparer) {
	t.Helper()
	oldVersion, oldCompare, oldRequests, oldDecoding, oldProfile := versionOf, compare, measureRequests, measureDecoding, profileOf
	versionOf = func(context.Context, string) (string, error) { return said, nil }
	compare = compared
	measureRequests = func(context.Context, harness.Browser, []string, io.Writer) (map[string]harness.MeasuredScenario, error) {
		return map[string]harness.MeasuredScenario{"x": scenario}, nil
	}
	measureDecoding = func(_ context.Context, _ harness.Browser, cases []harness.DecodingCase, _ io.Writer) ([]harness.DecodingCase, error) {
		return cases, nil
	}
	t.Cleanup(func() {
		versionOf, compare, measureRequests, measureDecoding, profileOf = oldVersion, oldCompare, oldRequests, oldDecoding, oldProfile
	})
}

var measured = &capture.Capture{Profile: "chrome", TLS: capture.TLS{JA4: "t13d1517h2_8daaf6152771_cb7bf5808d99"}}

// matching is a comparison in which nothing differs, noting what it was asked.
func matching(asked *tlsforge.MeasureOptions) comparer {
	return func(_ context.Context, options tlsforge.MeasureOptions, _ ...tlsforge.Option) (*tlsforge.Comparison, error) {
		*asked = options
		return &tlsforge.Comparison{Browser: measured, Client: measured}, nil
	}
}

func differing(context.Context, tlsforge.MeasureOptions, ...tlsforge.Option) (*tlsforge.Comparison, error) {
	return &tlsforge.Comparison{Browser: measured, Client: measured, TLS: fingerprint.Report{
		Differences: []fingerprint.Difference{{Field: "http2_hpack_path", Reference: "a", Candidate: "b"}},
	}}, nil
}

func failing(context.Context, tlsforge.MeasureOptions, ...tlsforge.Option) (*tlsforge.Comparison, error) {
	return nil, errors.New("no browser came")
}

var (
	aCommit = strings.Repeat("a", 40)
	aSet    = strings.Repeat("c", 64)
)

func TestTheGatePassesGoogleChromeThatMatches(t *testing.T) {
	b := laidOut(t)
	version := stableOf(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+version+"\n", matching(&asked))
	t.Setenv("GITHUB_SHA", aCommit)
	out := filepath.Join(t.TempDir(), "result.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args("--browser-arg=--no-sandbox", "--browser-arg", "--disable-gpu", "--out", out,
		"--timeout", "7s", "--set", aSet), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	// Launched with a window, given the arguments for the machine in order,
	// for as long as asked.
	if asked.Browser != b.browser || asked.Headless || !slices.Equal(asked.BrowserArgs, []string{"--no-sandbox", "--disable-gpu"}) ||
		asked.Timeout != 7*time.Second {
		t.Errorf("launched with %+v", asked)
	}
	if !strings.Contains(stdout.String(), "identical on every field compared") {
		t.Errorf("stdout: %s", stdout.String())
	}
	var result Result
	data, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(data, &result) != nil || !result.OK || result.Commit != aCommit || result.Set != aSet ||
		result.Chrome != version || result.Platform != thisPlatform() || result.Arch != runtime.GOARCH {
		t.Errorf("result: %s, %v", data, err)
	}
}

func TestTheResultIsForTheCommitAndTheSetItNames(t *testing.T) {
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	read := func(t *testing.T, args ...string) map[string]any {
		t.Helper()
		out := filepath.Join(t.TempDir(), "result.json")
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), b.args(append(args, "--out", out)...), &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		data, _ := os.ReadFile(out)
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("result: %s, %v", data, err)
		}
		return result
	}
	// --commit says it over the workflow's, and the set is written as set.
	t.Setenv("GITHUB_SHA", strings.Repeat("b", 40))
	if result := read(t, "--commit", aCommit, "--set", aSet); result["commit"] != aCommit || result["set"] != aSet {
		t.Errorf("commit %v and set %v, want --commit's and --set's", result["commit"], result["set"])
	}
	if result := read(t); result["commit"] != strings.Repeat("b", 40) {
		t.Errorf("commit %v, want GITHUB_SHA", result["commit"])
	}
	// Without either, a result says neither, rather than empty ones.
	t.Setenv("GITHUB_SHA", "")
	if result := read(t); result["commit"] != nil || result["set"] != nil {
		t.Errorf("a result for nothing named: %v", result)
	}
}

func TestTheGateRefusesToNameWhatIsNoCommitOrSet(t *testing.T) {
	b := laidOut(t)
	measuredAny := false
	seams(t, "Google Chrome "+stableOf(t), func(context.Context, tlsforge.MeasureOptions, ...tlsforge.Option) (*tlsforge.Comparison, error) {
		measuredAny = true
		return &tlsforge.Comparison{Browser: measured, Client: measured}, nil
	})
	for _, tc := range []struct {
		name, env string
		args      []string
		want      string
	}{
		{name: "a short commit", args: []string{"--commit", "abc123"}, want: `--commit "abc123" is not a full commit`},
		{name: "an upper-case commit", args: []string{"--commit", strings.Repeat("A", 40)}, want: "is not a full commit"},
		{name: "a commit and more", args: []string{"--commit", aCommit + "\n"}, want: "is not a full commit"},
		{name: "the workflow's, when it is none", env: "HEAD", want: `--commit "HEAD" is not a full commit`},
		{name: "a short set", args: []string{"--commit", aCommit, "--set", "abc"}, want: `--set "abc" is not a SHA-256`},
		{name: "a set as a commit", args: []string{"--commit", aCommit, "--set", aCommit}, want: "is not a SHA-256"},
		{name: "a set and more", args: []string{"--commit", aCommit, "--set", aSet + "0"}, want: "is not a SHA-256"},
		{name: "an upper-case set", args: []string{"--commit", aCommit, "--set", strings.Repeat("C", 64)}, want: "is not a SHA-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_SHA", tc.env)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), b.args(tc.args...), &stdout, &stderr); code != 2 ||
				!strings.Contains(stderr.String(), tc.want) {
				t.Errorf("exit %d: %s, want %q", code, stderr.String(), tc.want)
			}
		})
	}
	if measuredAny {
		t.Error("a browser was measured for a result no release could take")
	}
}

func TestTheGateRefusesWhatIsNotGoogleChromeOfTheProfile(t *testing.T) {
	version := stableOf(t)
	major, _, _ := strings.Cut(version, ".")
	n, _ := strconv.Atoi(major)
	next := fmt.Sprintf("%d.0.1.2", n+1)
	var asked tlsforge.MeasureOptions
	for _, tc := range []struct {
		name    string
		said    string
		worn    *profile.Profile
		compare comparer
		want    string
	}{
		{name: "Chrome for Testing", said: "Google Chrome for Testing " + version, want: "is Chrome for Testing, not Google Chrome"},
		{name: "Chromium", said: "Chromium " + version + " built on Debian", want: "is Chromium, not Google Chrome"},
		{name: "Chrome Beta", said: "Google Chrome " + version + " beta", want: "which is no Google Chrome Stable"},
		{name: "a version cut short", said: "Google Chrome " + major + ".0.1", want: "which is no Google Chrome Stable"},
		{name: "another browser", said: "Microsoft Edge " + version, want: "which is no Google Chrome Stable"},
		{name: "a Chrome the profile is not", said: "Google Chrome " + next,
			want: "the browser is Google Chrome " + next + ", and the profile chrome_"},
		{name: "a profile that says no Chrome", worn: &profile.Profile{Name: "odd", UserAgent: "Mozilla/5.0"},
			want: `the profile odd says no major of Chrome in its user agent, "Mozilla/5.0"`},
		{name: "no browser to compare with", compare: failing, want: "comparing: no browser came"},
		{name: "a profile that differs", compare: differing, want: "chrome does not match Google Chrome " + version},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := laidOut(t)
			said, compared := tc.said, tc.compare
			if said == "" {
				said = "Google Chrome " + version
			}
			if compared == nil {
				compared = matching(&asked)
			}
			seams(t, said, compared)
			if tc.worn != nil {
				profileOf = func(string) (*profile.Profile, error) { return tc.worn, nil }
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), b.args(), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("exit %d: %s, want %q", code, stderr.String(), tc.want)
			}
		})
	}
}

func TestTheGateAsksTheBrowserItsVersion(t *testing.T) {
	// This test binary is the browser: it takes no --version, and fails to
	// say one.
	b := laidOut(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args(), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "asking "+b.browser+" its version") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
}

func TestTheGateComparesWithTheBrowserLaunchedWithAWindow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in browser is a shell script")
	}
	// The browser measured is a stand-in, a script that runs this test binary
	// as TestBrowserHelper: the gate's own path from the browser to a result,
	// through the real comparison.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	standIn := filepath.Join(t.TempDir(), "stand-in")
	script := fmt.Sprintf("#!/bin/sh\nfor last; do :; done\nTLSFORGE_BROWSER_HELPER=\"$last\" exec %q -test.run='^TestBrowserHelper$'\n", self)
	if err := os.WriteFile(standIn, []byte(script), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), func(ctx context.Context, options tlsforge.MeasureOptions, opts ...tlsforge.Option) (*tlsforge.Comparison, error) {
		asked = options
		options.Browser = standIn
		return tlsforge.CompareToBrowser(ctx, options, opts...)
	})
	out := filepath.Join(t.TempDir(), "result.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args("--out", out), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	var result Result
	data, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(data, &result) != nil || !result.OK || result.Comparison.Measured.Mode != tlsforge.ModeWindow ||
		len(result.Comparison.Manifest) == 0 || asked.Browser != b.browser {
		t.Errorf("result: %s, %v; asked %+v", data, err, asked)
	}
}

func TestTheGateNeedsABrowserAndNothingElse(t *testing.T) {
	b := laidOut(t)
	for _, args := range [][]string{
		{},
		{"--profile", "chrome"},
		b.args("--profile", ""),
		append(b.args(), "extra"),
		{"--no-such-flag"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit %d, %s", args, code, stderr.String())
		}
	}
}

func TestTheGateSaysWhereItCouldNotWrite(t *testing.T) {
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	var stdout, stderr bytes.Buffer
	out := filepath.Join(t.TempDir(), "missing", "result.json")
	if code := run(context.Background(), b.args("--out", out), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "result.json") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
}

func TestTheGateNamesThePlatformAsAReleaseDoes(t *testing.T) {
	oldOS, oldArch := goos, goarch
	t.Cleanup(func() { goos, goarch = oldOS, oldArch })
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	for _, tc := range []struct{ goos, want string }{{"darwin", "macos"}, {"windows", "windows"}, {"linux", "linux"}} {
		goos, goarch = tc.goos, "riscv64"
		out := filepath.Join(t.TempDir(), "result.json")
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), b.args("--out", out), &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit %d, %s", tc.goos, code, stderr.String())
		}
		var result Result
		data, _ := os.ReadFile(out)
		if err := json.Unmarshal(data, &result); err != nil || result.Platform != tc.want || result.Arch != "riscv64" {
			t.Errorf("%s: result %s, %v", tc.goos, data, err)
		}
	}
}

func TestMainEntryPoint(t *testing.T) {
	// The wiring between argv and the exit code, which run does not cover.
	originalExit, originalArgs := exit, os.Args
	t.Cleanup(func() { exit, os.Args = originalExit, originalArgs })
	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"pinned"}
	main()
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
}

func TestTheGateHoldsTheBrowserToWhatAPageDoes(t *testing.T) {
	b := laidOut(t)
	version := stableOf(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+version, matching(&asked))
	var measuredWith harness.Browser
	var deadline time.Time
	measureRequests = func(ctx context.Context, browser harness.Browser, only []string, _ io.Writer) (map[string]harness.MeasuredScenario, error) {
		measuredWith, deadline = browser, func() time.Time { d, _ := ctx.Deadline(); return d }()
		if only != nil {
			t.Errorf("measured %v, not every scenario", only)
		}
		changed := scenario
		changed.H2 = []harness.Request{{Method: "GET", URL: "https://www.example.com/p/x", Headers: [][2]string{{":method", "GET"}, {"accept", "text/html"}}}}
		return map[string]harness.MeasuredScenario{"x": changed}, nil
	}
	measureDecoding = func(_ context.Context, _ harness.Browser, cases []harness.DecodingCase, _ io.Writer) ([]harness.DecodingCase, error) {
		out := slices.Clone(cases)
		out[0].Encoding = "windows-1252"
		return out, nil
	}
	out := filepath.Join(t.TempDir(), "result.json")
	start := time.Now()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args("--browser-arg=--no-sandbox", "--out", out, "--scenario-timeout", "3m"), &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !reflect.DeepEqual(measuredWith, harness.Chrome{Path: b.browser, Args: []string{"--no-sandbox"}}) ||
		deadline.Sub(start) < 2*time.Minute || deadline.Sub(start) > 4*time.Minute {
		t.Errorf("measured %v, by %v", measuredWith, deadline.Sub(start))
	}
	if !strings.Contains(stdout.String(), `x over h2, request 1: accept: "text/html", the fixture's "*/*"`) ||
		!strings.Contains(stdout.String(), `page: the browser read "a" as "windows-1252"`) {
		t.Errorf("stdout: %s", stdout.String())
	}
	if !strings.HasSuffix(stderr.String(), "pinned: chrome does not match Google Chrome "+version+": 2 differences in what a page does\n") {
		t.Errorf("stderr: %s", stderr.String())
	}
	var result Result
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &result); err != nil || result.OK || len(result.Scenarios) != 2 {
		t.Errorf("result: %s, %v", data, err)
	}
}

func TestOneDifferenceIsSaidAsOne(t *testing.T) {
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	measureDecoding = func(_ context.Context, _ harness.Browser, cases []harness.DecodingCase, _ io.Writer) ([]harness.DecodingCase, error) {
		out := slices.Clone(cases)
		out[0].Text = nil
		return out, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args(), &stdout, &stderr); code != 1 ||
		!strings.HasSuffix(stderr.String(), ": 1 difference in what a page does\n") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
}

func TestAResultWithNoDifferenceSaysSo(t *testing.T) {
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	out := filepath.Join(t.TempDir(), "result.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), b.args("--out", out), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, _ := os.ReadFile(out)
	if !bytes.Contains(data, []byte(`"scenarios": []`)) || !bytes.Contains(data, []byte(`"ok": true`)) {
		t.Errorf("result: %s", data)
	}
}

func TestTheGateNeedsItsFixturesAndTheirMeasurements(t *testing.T) {
	failing := errors.New("no browser came")
	for _, tc := range []struct {
		name   string
		change func(b *bench)
		seam   func()
		want   string
	}{
		{"no fixture of requests", func(b *bench) { b.requests = filepath.Join(filepath.Dir(b.requests), "none.json") }, nil, "none.json"},
		{"no fixture of decodings", func(b *bench) { b.decoding = filepath.Join(filepath.Dir(b.decoding), "none.json") }, nil, "none.json"},
		{"scenarios not measured", nil, func() {
			measureRequests = func(context.Context, harness.Browser, []string, io.Writer) (map[string]harness.MeasuredScenario, error) {
				return nil, failing
			}
		}, "measuring the scenarios: no browser came"},
		{"pages not measured", nil, func() {
			measureDecoding = func(context.Context, harness.Browser, []harness.DecodingCase, io.Writer) ([]harness.DecodingCase, error) {
				return nil, failing
			}
		}, "measuring the decodings: no browser came"},
		{"a profile there is none of", nil, func() {
			profileOf = func(string) (*profile.Profile, error) { return nil, errors.New(`no profile "chrome"`) }
		}, `no profile "chrome"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := laidOut(t)
			if tc.change != nil {
				tc.change(&b)
			}
			var asked tlsforge.MeasureOptions
			seams(t, "Google Chrome "+stableOf(t), matching(&asked))
			if tc.seam != nil {
				tc.seam()
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), b.args(), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("exit %d: %s, want %q", code, stderr.String(), tc.want)
			}
		})
	}
}

func TestAProfileSaysWhatItSendsByName(t *testing.T) {
	p := &profile.Profile{EngineMajor: profile.Major(1), UserAgent: "Mozilla", Headers: []profile.Field{{Name: "Sec-CH-UA", Value: "a"}, {Name: "accept", Value: "*/*"}},
		ClientHints: []profile.Field{{Name: "sec-ch-ua-arch", Value: `"arm"`}}}
	if got := valuesOf(p); len(got) != 4 || got["user-agent"] != "Mozilla" || got["sec-ch-ua"] != "a" || got["sec-ch-ua-arch"] != `"arm"` ||
		got["accept"] != "*/*" {
		t.Errorf("valuesOf: %v", got)
	}
}
