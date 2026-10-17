// Command pinned holds tls-forge to the reference Google Chrome, the build a
// release is measured against: it checks that the archived installer and the
// installed browser are the build the manifest names, that the browser says it
// is that build, and then compares the manifest's profile with it, launched as
// the manifest says. It exits 0 only when all of that holds. A reference it
// cannot find or check is a failure, never a reason to measure another
// browser: that would hold the release to whatever happened to be at hand.
//
//	go run ./internal/pinned --manifest reference/chrome.json \
//	    --archive DIR --installed DIR [--out result.json] \
//	    [--commit SHA] [--set DIGEST]
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
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/reference"
)

// exit is os.Exit, which a test of main replaces.
var exit = os.Exit

func main() { exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// Result is what a run writes to --out: what it held to what, and the
// comparison. Commit and Set are what the result is for: the commit a release
// is built from and the identity of its set, the SHA-256 of the set's manifest.
type Result struct {
	Commit     string               `json:"commit,omitempty"`
	Set        string               `json:"set,omitempty"`
	Reference  string               `json:"reference"`
	Platform   string               `json:"platform"`
	Arch       string               `json:"arch"`
	OK         bool                 `json:"ok"`
	Comparison *tlsforge.Comparison `json:"comparison"`
}

// The seams the tests reach through.
var (
	goos, goarch = runtime.GOOS, runtime.GOARCH
	versionOf    = func(ctx context.Context, binary string) ([]byte, error) {
		return exec.CommandContext(ctx, binary, "--version").Output()
	}
	compare = tlsforge.CompareToBrowser
)

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

	result, err := hold(ctx, *manifestPath, *archive, *installed, *timeout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pinned: %v\n", err)
		return 1
	}
	result.Commit, result.Set = *commit, *set
	_, _ = fmt.Fprint(stdout, result.Comparison.String())
	if *out != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "pinned: %v\n", err)
			return 1
		}
	}
	if !result.OK {
		_, _ = fmt.Fprintf(stderr, "pinned: %s does not match Google Chrome %s\n", result.Comparison.Client.Profile,
			result.Reference)
		return 1
	}
	return 0
}

// hold checks the reference is what the manifest says, and compares with it.
func hold(ctx context.Context, manifestPath, archive, installed string, timeout time.Duration) (*Result, error) {
	data, err := os.ReadFile(manifestPath)
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
	if err := reference.VerifyFile(filepath.Join(archive, build.Installer), build.InstallerSHA256); err != nil {
		return nil, err
	}
	binary := filepath.Join(installed, filepath.FromSlash(build.Binary))
	if err := reference.VerifyFile(binary, build.BinarySHA256); err != nil {
		return nil, err
	}
	if err := build.CheckMachine(binary); err != nil {
		return nil, err
	}
	said, err := versionOf(ctx, binary)
	if err != nil {
		return nil, fmt.Errorf("asking %s its version: %w", binary, err)
	}
	if err := manifest.CheckIdentity(string(said)); err != nil {
		return nil, err
	}
	comparison, err := compare(ctx, tlsforge.MeasureOptions{
		Browser: binary, Headless: manifest.Launch.Headless, BrowserArgs: manifest.Launch.Args, Timeout: timeout,
	}, tlsforge.WithProfile(manifest.Profile))
	if err != nil {
		return nil, fmt.Errorf("comparing: %w", err)
	}
	return &Result{
		Reference: manifest.Version, Platform: build.Platform, Arch: build.Arch, OK: comparison.OK(),
		Comparison: comparison,
	}, nil
}
