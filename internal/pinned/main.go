// Command pinned holds tls-forge to the reference Google Chrome, the build a
// release is measured against: it checks that the archived installer and the
// installed browser are the build the manifest names, that the browser says it
// is that build, and then compares the manifest's profile with it, launched as
// the manifest says. Then it measures the browser on the bench in
// internal/harness, every scenario of a page and every page whose decoding is
// asked about, and holds it to the fixtures tls-forge is tested against, and
// to the profile. It exits 0 only when all of that holds. A reference it
// cannot find or check is a failure, never a reason to measure another
// browser: that would hold the release to whatever happened to be at hand.
//
//	go run ./internal/pinned --manifest reference/chrome.json \
//	    --archive DIR --installed DIR [--out result.json] \
//	    [--commit SHA] [--set DIGEST] [--requests FILE] [--decoding FILE]
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
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v6"
	"github.com/Sec-CH-Lemon/tls-forge/v6/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v6/internal/reference"
	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
)

// exit is os.Exit, which a test of main replaces.
var exit = os.Exit

func main() { exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// Result is what a run writes to --out: what it held to what, the comparison,
// and how the browser differs from the fixtures of what a page does. Commit
// and Set are what the result is for: the commit a release is built from and
// the identity of its set, the SHA-256 of the set's manifest.
type Result struct {
	Commit     string               `json:"commit,omitempty"`
	Set        string               `json:"set,omitempty"`
	Reference  string               `json:"reference"`
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

// options are what a run holds the reference to, and how long it gives it.
type options struct {
	manifest, archive, installed string
	timeout                      time.Duration
	requests, decoding           string
	scenarios                    time.Duration
	progress                     io.Writer
}

// What a commit and a set's identity are written as: lower-case hex, whole.
var (
	fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	setDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pinned", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "the reference manifest")
	archive := flags.String("archive", "", "the directory the archived installers are in")
	installed := flags.String("installed", "", "the directory the reference build is installed in")
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
	if *manifestPath == "" || *archive == "" || *installed == "" || flags.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "pinned: --manifest, --archive and --installed are required, and nothing else")
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

	result, err := hold(ctx, options{manifest: *manifestPath, archive: *archive, installed: *installed, timeout: *timeout,
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
			result.Reference)
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

// hold checks the reference is what the manifest says, compares with it, and
// holds it to the fixtures of what a page does.
func hold(ctx context.Context, o options) (*Result, error) {
	data, err := os.ReadFile(o.manifest)
	if err != nil {
		return nil, err
	}
	// The fixtures first: nothing is measured that could not be held to them.
	requests, err := harness.LoadRequests(o.requests)
	if err != nil {
		return nil, err
	}
	decoding, err := harness.LoadDecoding(o.decoding)
	if err != nil {
		return nil, err
	}
	manifest, err := reference.Load(data)
	if err != nil {
		return nil, err
	}
	platform := map[string]string{"darwin": "macos"}[goos]
	if platform == "" {
		platform = goos
	}
	build, err := manifest.Build(platform, goarch)
	if err != nil {
		return nil, err
	}
	if err := reference.VerifyFile(filepath.Join(o.archive, build.Installer), build.InstallerSHA256); err != nil {
		return nil, err
	}
	binary := filepath.Join(o.installed, filepath.FromSlash(build.Binary))
	if err := reference.VerifyFile(binary, build.BinarySHA256); err != nil {
		return nil, err
	}
	if err := build.CheckMachine(binary); err != nil {
		return nil, err
	}
	said, err := versionOf(ctx, binary)
	if err != nil {
		return nil, err
	}
	if err := manifest.CheckIdentity(said); err != nil {
		return nil, err
	}
	comparison, err := compare(ctx, tlsforge.MeasureOptions{
		Browser: binary, Headless: manifest.Launch.Headless, BrowserArgs: manifest.Launch.Args, Timeout: o.timeout,
	}, tlsforge.WithProfile(manifest.Profile))
	if err != nil {
		return nil, fmt.Errorf("comparing: %w", err)
	}
	worn, err := profileOf(manifest.Profile)
	if err != nil {
		return nil, err
	}
	// On the bench as the fixtures were measured, headless whatever launch
	// says, given its arguments, which are for the machine (--no-sandbox on a
	// hosted runner): what the browser asks for in each scenario, how it
	// decodes each page.
	ctx, cancel := context.WithTimeout(ctx, o.scenarios)
	defer cancel()
	b := harness.Chrome{Path: binary, Args: manifest.Launch.Args}
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
	return &Result{
		Reference: manifest.Version, Platform: build.Platform, Arch: build.Arch,
		OK: comparison.OK() && len(differences) == 0, Comparison: comparison, Scenarios: differences,
	}, nil
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
