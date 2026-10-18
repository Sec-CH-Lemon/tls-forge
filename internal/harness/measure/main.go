// Command measure measures a browser on the bench in internal/harness: what it
// asks for in each scenario, which connection it asks on, how it decodes each
// page, how it writes the header blocks of each connection into HPACK, and the
// WINDOW_UPDATEs it sends while it reads an answer. It writes what it measured
// into the fixtures, or with --check holds the browser to them.
//
//	go run ./internal/harness/measure --browser PATH [--requests FILE] \
//	    [--connections FILE] [--decoding FILE] [--hpack FILE] [--flow FILE] \
//	    [--only ID,...] [--check]
//
// --requests, --connections, --decoding, --hpack and --flow name the fixtures,
// testdata/chrome155-requests.json, testdata/chrome155-connections.json,
// testdata/chrome155-decoding.json, testdata/chrome155-hpack.json and
// testdata/chrome155-flow.json unless said; an empty one is not measured.
// --only measures those scenarios alone, of requests, of connections, of
// header blocks and of window updates, and each fixture of them measured has
// to have every one. Writing replaces what the fixture says of
// each scenario measured, and of every page, and says which browser it was and
// when.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/browser"
	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
)

// exit is os.Exit, which a test of main replaces.
var exit = os.Exit

func main() { exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// The seams the tests reach through.
var (
	// open is the browser at path, and what it says it is.
	open = func(ctx context.Context, path string) (harness.Browser, string, error) {
		found, err := browser.Find(path)
		if err != nil {
			return nil, "", err
		}
		said, err := exec.CommandContext(ctx, found.Path, "--version").Output()
		if err != nil {
			return nil, "", fmt.Errorf("asking %s its version: %w", found.Path, err)
		}
		return harness.Chrome{Path: found.Path}, strings.TrimSpace(string(said)), nil
	}
	// machine says what this machine is, as the fixtures do.
	machine = func() string { return describe(runtime.GOOS, runtime.GOARCH, exec.Command, os.ReadFile) }
	today   = func() string { return time.Now().UTC().Format(time.DateOnly) }
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("measure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("browser", "", "the browser to measure: a path, or a name browser.Find knows")
	requests := flags.String("requests", "testdata/chrome155-requests.json", "the fixture of requests; empty, none")
	connections := flags.String("connections", "testdata/chrome155-connections.json",
		"the fixture of connections; empty, none")
	decoding := flags.String("decoding", "testdata/chrome155-decoding.json", "the fixture of decodings; empty, none")
	hpack := flags.String("hpack", "testdata/chrome155-hpack.json", "the fixture of header blocks; empty, none")
	flow := flags.String("flow", "testdata/chrome155-flow.json", "the fixture of window updates; empty, none")
	only := flags.String("only", "", "the scenarios to measure, by name, comma-separated; every one unless said")
	check := flags.Bool("check", false, "hold the browser to the fixtures rather than write them")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() > 0 || *requests == "" && *connections == "" && *decoding == "" && *hpack == "" &&
		*flow == "" {
		_, _ = fmt.Fprintln(stderr, "measure: --browser is needed, a fixture to measure for, and nothing else")
		return 2
	}
	var names []string
	if *only != "" {
		names = strings.Split(*only, ",")
	}
	b, said, err := open(ctx, *path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
		return 1
	}
	about := said + ", --headless=new --lang=en-US, " + machine()
	var diff []string
	for _, fixture := range []struct {
		path    string
		measure measurer
	}{{*requests, harness.Measure}, {*connections, harness.MeasureConnections}} {
		if fixture.path == "" {
			continue
		}
		found, err := measureRequests(ctx, b, fixture.measure, fixture.path, names, about, *check, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			return 1
		}
		diff = append(diff, found...)
	}
	if *decoding != "" {
		found, err := measureDecoding(ctx, b, *decoding, about, *check, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			return 1
		}
		diff = append(diff, found...)
	}
	if *hpack != "" {
		found, err := measureHeaderBlocks(ctx, b, *hpack, names, about, *check, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			return 1
		}
		diff = append(diff, found...)
	}
	if *flow != "" {
		found, err := measureWindowUpdates(ctx, b, *flow, names, about, *check, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			return 1
		}
		diff = append(diff, found...)
	}
	for _, d := range diff {
		_, _ = fmt.Fprintln(stdout, d)
	}
	if len(diff) > 0 {
		_, _ = fmt.Fprintf(stderr, "measure: %d differences from the fixtures\n", len(diff))
		return 1
	}
	if *check {
		_, _ = fmt.Fprintln(stdout, "the browser is what the fixtures say")
	}
	return 0
}

// measurer measures the scenarios of a fixture of requests: harness.Measure,
// or harness.MeasureConnections.
type measurer func(ctx context.Context, b harness.Browser, only []string,
	progress io.Writer) (map[string]harness.MeasuredScenario, error)

// measureRequests measures the scenarios named, or every one, with measure,
// and holds them to the fixture at path, or writes them into it.
func measureRequests(ctx context.Context, b harness.Browser, measure measurer, path string, names []string, about string,
	check bool, progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadRequests(path)
	if err != nil {
		return nil, err
	}
	got, err := measure(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.MeasuredScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		return harness.Compare(want, got, nil), nil
	}
	for name, scenario := range got {
		fixture.Scenarios[name] = scenario
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureWindowUpdates measures the WINDOW_UPDATE scenarios named, or every
// one, and holds them to the fixture at path, or writes them into it.
func measureWindowUpdates(ctx context.Context, b harness.Browser, path string, names []string, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadFlow(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureFlow(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.FlowScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		return harness.CompareFlow(want, got), nil
	}
	if fixture.Scenarios == nil {
		fixture.Scenarios = map[string]harness.FlowScenario{}
	}
	for name, scenario := range got {
		fixture.Scenarios[name] = scenario
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureHeaderBlocks measures the HPACK scenarios named, or every one, and
// holds them to the fixture at path, or writes them into it.
func measureHeaderBlocks(ctx context.Context, b harness.Browser, path string, names []string, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadHPACK(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureHPACK(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.HPACKScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		return harness.CompareHPACK(want, got), nil
	}
	if fixture.Scenarios == nil {
		fixture.Scenarios = map[string]harness.HPACKScenario{}
	}
	for name, scenario := range got {
		fixture.Scenarios[name] = scenario
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureDecoding measures every page of the fixture at path, and holds the
// browser to it, or writes what it made of them into it.
func measureDecoding(ctx context.Context, b harness.Browser, path, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadDecoding(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureDecoding(ctx, b, fixture.Cases, progress)
	if err != nil {
		return nil, err
	}
	if check {
		return harness.CompareDecoding(fixture.Cases, got), nil
	}
	fixture.Cases, fixture.Browser, fixture.Measured = got, about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// dated is the dates a fixture was measured on, day among them.
func dated(dates, day string) string {
	if dates == "" {
		return day
	}
	for _, d := range strings.Split(dates, ", ") {
		if d == day {
			return dates
		}
	}
	return dates + ", " + day
}

// describe says what a machine is as the fixtures say it: its system, its
// version where there is a way to ask, and its processor.
func describe(goos, goarch string, command func(string, ...string) *exec.Cmd,
	read func(string) ([]byte, error)) string {
	system := goos
	switch goos {
	case "darwin":
		system = "macOS"
		if version, err := command("sw_vers", "-productVersion").Output(); err == nil {
			system += " " + strings.TrimSpace(string(version))
		}
	case "linux":
		system = "Linux"
		if release, err := read("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(release), "\n") {
				if name, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
					system = strings.Trim(name, `"`)
				}
			}
		}
	case "windows":
		system = "Windows"
	}
	return system + " (" + goarch + ")"
}
