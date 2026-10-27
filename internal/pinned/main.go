// Command pinned holds tls-forge to Google Chrome as Google ships it: the
// Stable build a release's runner installs from Google that day, not the one
// the runner image carries, Chrome for Testing or Chromium. It checks that the
// browser says it is Google Chrome of the profile's major version, compares
// the profile with it, and then measures it on the bench in internal/harness,
// every scenario of a page and every page whose decoding is asked about, and
// holds it to the fixtures tls-forge is tested against, and to the profile. It
// exits 0 only when all of that holds. A browser it cannot ask, or one that is
// not that Google Chrome, is a failure, never a reason to measure it anyway:
// that would hold the release to whatever happened to be at hand.
//
//	go run ./internal/pinned --browser PATH [--profile NAME] [--browser-arg ARG]... \
//	    [--out result.json] [--commit SHA] [--set DIGEST] [--requests FILE] [--decoding FILE]
//
// The result is for the commit and the release set it names, so that a
// release takes it only for what it measured. It is not part of what ships: a
// release workflow runs it, and docs/pinned.md says how.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// exit is os.Exit, which a test of main replaces.
var exit = os.Exit

func main() { exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// Result is what a run writes to --out: the Google Chrome it held the profile
// to, the comparison, and how the browser differs from the fixtures of what a
// page does. Commit and Set are what the result is for: the commit a release
// is built from and the identity of its set, the SHA-256 of the set's
// manifest.
type Result struct {
	Commit     string               `json:"commit,omitempty"`
	Set        string               `json:"set,omitempty"`
	Chrome     string               `json:"chrome"`
	Platform   string               `json:"platform"`
	Arch       string               `json:"arch"`
	OK         bool                 `json:"ok"`
	Comparison *tlsforge.Comparison `json:"comparison"`
	Scenarios  []string             `json:"scenarios"`
}

// The seams the tests reach through.
var (
	goos, goarch = runtime.GOOS, runtime.GOARCH
	versionOf    = func(ctx context.Context, binary string) (string, error) {
		return harness.Chrome{Path: binary}.Version(ctx)
	}
	compare         = tlsforge.CompareToBrowser
	measureRequests = harness.Measure
	measureDecoding = harness.MeasureDecoding
	profileOf       = profile.Get
)

// options are what a run holds the browser to, and how long it gives it.
type options struct {
	browser, profile   string
	args               []string
	timeout            time.Duration
	requests, decoding string
	scenarios          time.Duration
	progress           io.Writer
}

// What a commit and a set's identity are written as: lower-case hex, whole.
var (
	fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	setDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pinned", flag.ContinueOnError)
	flags.SetOutput(stderr)
	browser := flags.String("browser", "", "the Google Chrome installed from Google to hold the profile to")
	profileName := flags.String("profile", "chrome", "the profile held to it")
	var browserArgs []string
	flags.Func("browser-arg", "an argument the browser is launched with, for the machine (--no-sandbox on a hosted runner); repeatable",
		func(arg string) error {
			browserArgs = append(browserArgs, arg)
			return nil
		})
	out := flags.String("out", "", "where to write the result as JSON")
	timeout := flags.Duration("timeout", 2*time.Minute, "how long the browser has to be measured")
	commit := flags.String("commit", os.Getenv("GITHUB_SHA"), "the commit the release is built from (default $GITHUB_SHA)")
	set := flags.String("set", "", "the release set's identity, the SHA-256 of its manifest")
	requests := flags.String("requests", "testdata/chrome155-requests.json", "the fixture of what Chrome asks for")
	decoding := flags.String("decoding", "testdata/chrome155-decoding.json", "the fixture of how Chrome decodes a page")
	scenarios := flags.Duration("scenario-timeout", 45*time.Minute, "how long the scenarios and pages have to be measured")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *browser == "" || *profileName == "" || flags.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "pinned: --browser and --profile are required, and nothing else")
		return 2
	}
	// Said before anything is measured: a result for what it cannot name is
	// one no release can take.
	if *commit != "" && !fullCommit.MatchString(*commit) {
		_, _ = fmt.Fprintf(stderr, "pinned: --commit %q is not a full commit in lower-case hex\n", *commit)
		return 2
	}
	if *set != "" && !setDigest.MatchString(*set) {
		_, _ = fmt.Fprintf(stderr, "pinned: --set %q is not a SHA-256 in lower-case hex\n", *set)
		return 2
	}

	result, err := hold(ctx, options{browser: *browser, profile: *profileName, args: browserArgs, timeout: *timeout,
		requests: *requests, decoding: *decoding, scenarios: *scenarios, progress: stderr})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pinned: %v\n", err)
		return 1
	}
	result.Commit, result.Set = *commit, *set
	_, _ = fmt.Fprint(stdout, result.Comparison.String())
	for _, d := range result.Scenarios {
		_, _ = fmt.Fprintln(stdout, d)
	}
	if *out != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "pinned: %v\n", err)
			return 1
		}
	}
	if !result.OK {
		_, _ = fmt.Fprintf(stderr, "pinned: %s does not match Google Chrome %s", result.Comparison.Client.Profile,
			result.Chrome)
		if n := len(result.Scenarios); n > 0 {
			word := "differences"
			if n == 1 {
				word = "difference"
			}
			_, _ = fmt.Fprintf(stderr, ": %d %s in what a page does", n, word)
		}
		_, _ = fmt.Fprintln(stderr)
		return 1
	}
	return 0
}

// hold checks the browser is Google Chrome of the profile's major, compares
// with it, and holds it to the fixtures of what a page does.
func hold(ctx context.Context, o options) (*Result, error) {
	// The fixtures first: nothing is measured that could not be held to them.
	requests, err := harness.LoadRequests(o.requests)
	if err != nil {
		return nil, err
	}
	decoding, err := harness.LoadDecoding(o.decoding)
	if err != nil {
		return nil, err
	}
	worn, err := profileOf(o.profile)
	if err != nil {
		return nil, err
	}
	said, err := versionOf(ctx, o.browser)
	if err != nil {
		return nil, err
	}
	version, err := identify(said, worn)
	if err != nil {
		return nil, err
	}
	// With a window, as people run it and as the profile was measured.
	comparison, err := compare(ctx, tlsforge.MeasureOptions{Browser: o.browser, BrowserArgs: o.args, Timeout: o.timeout},
		tlsforge.WithProfile(o.profile))
	if err != nil {
		return nil, fmt.Errorf("comparing: %w", err)
	}
	// On the bench as the fixtures were measured, headless, given the
	// arguments for the machine (--no-sandbox on a hosted runner): what the
	// browser asks for in each scenario, how it decodes each page.
	ctx, cancel := context.WithTimeout(ctx, o.scenarios)
	defer cancel()
	b := harness.Chrome{Path: o.browser, Args: o.args}
	got, err := measureRequests(ctx, b, nil, o.progress)
	if err != nil {
		return nil, fmt.Errorf("measuring the scenarios: %w", err)
	}
	pages, err := measureDecoding(ctx, b, decoding.Cases, o.progress)
	if err != nil {
		return nil, fmt.Errorf("measuring the decodings: %w", err)
	}
	// Said as a list, empty too.
	differences := append([]string{}, harness.Compare(requests.Scenarios, got, valuesOf(worn))...)
	differences = append(differences, harness.CompareDecoding(decoding.Cases, pages)...)
	platform := map[string]string{"darwin": "macos"}[goos]
	if platform == "" {
		platform = goos
	}
	return &Result{
		Chrome: version, Platform: platform, Arch: goarch,
		OK: comparison.OK() && len(differences) == 0, Comparison: comparison, Scenarios: differences,
	}, nil
}

var (
	// stable is what Google Chrome Stable says it is: its name and four
	// numbers, the first its major, and nothing after them, which a Beta, Dev
	// or Canary has.
	stable = regexp.MustCompile(`^Google Chrome (([0-9]+)\.[0-9]+\.[0-9]+\.[0-9]+)$`)
	// majorSent is the major a profile's user agent says it is.
	majorSent = regexp.MustCompile(`Chrome/([0-9]+)\.`)
)

// identify holds what the browser says it is, its --version, to Google Chrome
// Stable of the major the profile was measured on, and is its version. Not
// Chrome for Testing, which shares the name and runs experiments real users do
// not have, not Chromium, not another channel, and not a Chrome the profile
// does not say it is.
func identify(said string, p *profile.Profile) (string, error) {
	said = strings.TrimSpace(said)
	switch {
	case strings.HasPrefix(said, "Google Chrome for Testing"):
		return "", fmt.Errorf("%q is Chrome for Testing, not Google Chrome as Google ships it", said)
	case strings.HasPrefix(said, "Chromium"):
		return "", fmt.Errorf("%q is Chromium, not Google Chrome", said)
	}
	browser := stable.FindStringSubmatch(said)
	if browser == nil {
		return "", fmt.Errorf("the browser says %q, which is no Google Chrome Stable", said)
	}
	sent := majorSent.FindStringSubmatch(p.UserAgent)
	if sent == nil {
		return "", fmt.Errorf("the profile %s says no major of Chrome in its user agent, %q", p.Name, p.UserAgent)
	}
	if browser[2] != sent[1] {
		return "", fmt.Errorf("the browser is Google Chrome %s, and the profile %s is Chrome %s: a release needs a profile of Chrome %s",
			browser[1], p.Name, sent[1], browser[2])
	}
	return browser[1], nil
}

// valuesOf are the values p sends, by the name of the header: its user agent,
// its headers' and its client hints'.
func valuesOf(p *profile.Profile) map[string]string {
	values := map[string]string{"user-agent": p.UserAgent}
	for _, f := range append(slices.Clone(p.Headers), p.ClientHints...) {
		values[strings.ToLower(f.Name)] = f.Value
	}
	return values
}
