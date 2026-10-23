// Command measure measures a browser on the bench in internal/harness: what it
// asks for in each scenario, which connection it asks on, how it decodes each
// page, how it writes the header blocks of each connection into HPACK, how its
// TLS records carry its requests over HTTP/1.1, what it makes of a server that
// gives it ALPS, the WINDOW_UPDATEs it sends while it reads an answer, the
// order it draws for the extensions of each ClientHello, and whether it asks
// a TLS 1.2 server for a page before the server's Finished. It writes what it
// measured into the fixtures, or with --check holds the browser to them.
//
//	go run ./internal/harness/measure --browser PATH [--requests FILE] \
//	    [--connections FILE] [--decoding FILE] [--hpack FILE] [--records FILE] \
//	    [--alps FILE] [--flow FILE] [--urls FILE] [--hellos FILE] \
//	    [--false-start FILE] [--only ID,...] [--browser-arg ARG]... \
//	    [--check [--newer]]
//
// --requests, --connections, --decoding, --hpack, --records, --alps, --flow,
// --urls, --hellos and --false-start name the fixtures,
// testdata/chrome155-requests.json, testdata/chrome155-connections.json,
// testdata/chrome155-decoding.json, testdata/chrome155-hpack.json,
// testdata/chrome155-records.json, testdata/chrome155-alps.json,
// testdata/chrome155-flow.json, testdata/chrome155-urls.json,
// testdata/chrome155-hellos.json and testdata/chrome155-falsestart.json unless
// said; an empty one is not measured. The hellos are drawn afresh: --check
// holds each launch to every order being as likely as any other. --only
// measures those scenarios alone, of requests, of connections, of header
// blocks, of records, of ALPS, of window updates and of False Start, and each
// fixture of them measured has to have every one. --newer holds a newer build
// of the browser than the fixtures': what its version decides, the values of
// sec-ch-ua and its kind and the length they give an HTTP/1.1 head, is held
// to what it sends itself rather than to the fixtures'. --browser-arg gives
// the browser an argument after the bench's own, for the machine: a hosted
// runner's Linux and Windows need --no-sandbox, without which Chrome loads no
// page and says nothing. It exits 0 when the
// browser is what the fixtures say, 3 when it is not, 2 for what it is given
// that it cannot run with, and 1 when it could not measure. Writing replaces what the fixture says of
// each scenario measured, and of every page, and says which browser it was and
// when.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v7/browser"
	"github.com/Sec-CH-Lemon/tls-forge/v7/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
)

// exit is os.Exit, which a test of main replaces.
var exit = os.Exit

func main() { exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// The seams the tests reach through.
var (
	// open is the browser at path, given args after the bench's own, and what
	// it says it is.
	open = func(ctx context.Context, path string, args []string) (harness.Browser, string, error) {
		found, err := browser.Find(path)
		if err != nil {
			return nil, "", err
		}
		chrome := harness.Chrome{Path: found.Path, Args: args}
		said, err := chrome.Version(ctx)
		if err != nil {
			return nil, "", err
		}
		return chrome, said, nil
	}
	// machine says what this machine is, as the fixtures do.
	machine = func() string { return describe(runtime.GOOS, runtime.GOARCH, exec.Command, os.ReadFile) }
	today   = func() string { return time.Now().UTC().Format(time.DateOnly) }
	// urlCases measures URL cases, each of which is waited out for seconds
	// over each protocol.
	urlCases = harness.MeasureURLs
	// helloOrders measures the hellos, which launches the browser twice.
	helloOrders = harness.MeasureHellos
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
	records := flags.String("records", "testdata/chrome155-records.json",
		"the fixture of TLS records over HTTP/1.1; empty, none")
	alps := flags.String("alps", "testdata/chrome155-alps.json", "the fixture of ALPS; empty, none")
	flow := flags.String("flow", "testdata/chrome155-flow.json", "the fixture of window updates; empty, none")
	urls := flags.String("urls", "testdata/chrome155-urls.json", "the fixture of URLs; empty, none")
	hellos := flags.String("hellos", "testdata/chrome155-hellos.json", "the fixture of ClientHello orders; empty, none")
	falseStart := flags.String("false-start", "testdata/chrome155-falsestart.json",
		"the fixture of False Start over TLS 1.2; empty, none")
	only := flags.String("only", "", "the scenarios to measure, by name, comma-separated; every one unless said")
	check := flags.Bool("check", false, "hold the browser to the fixtures rather than write them")
	newer := flags.Bool("newer", false,
		"with --check, a newer build: what its version decides held to what it sends itself")
	var browserArgs arguments
	flags.Var(&browserArgs, "browser-arg",
		"an argument for the browser after the bench's own, again for more; for the machine, as --no-sandbox")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() > 0 || *requests == "" && *connections == "" && *decoding == "" && *hpack == "" &&
		*records == "" && *alps == "" && *flow == "" && *urls == "" && *hellos == "" && *falseStart == "" {
		_, _ = fmt.Fprintln(stderr, "measure: --browser is needed, a fixture to measure for, and nothing else")
		return 2
	}
	if *newer && !*check {
		_, _ = fmt.Fprintln(stderr, "measure: --newer holds a browser to the fixtures, with --check")
		return 2
	}
	var names []string
	if *only != "" {
		names = strings.Split(*only, ",")
	}
	b, said, err := open(ctx, *path, browserArgs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
		return 1
	}
	about := said + ", " + strings.Join(append([]string{"--headless=new", "--lang=en-US"}, browserArgs...), " ") +
		", " + machine()
	// A fixture that cannot be measured is, checked, a difference, and the
	// others are measured all the same: one scenario a browser does otherwise
	// on its platform loses no more than its own fixture. Nothing measured
	// at all is no check; writing, any is the end.
	var diff []string
	measuredAny, failed := false, false
	step := func(what string, found []string, err error) bool {
		switch {
		case err == nil:
			measuredAny = true
			diff = append(diff, found...)
		case *check:
			failed = true
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			diff = append(diff, fmt.Sprintf("%s could not be measured: %v", what, err))
		default:
			_, _ = fmt.Fprintf(stderr, "measure: %v\n", err)
			return false
		}
		return true
	}
	for _, fixture := range []struct {
		what    string
		path    string
		measure measurer
	}{{"the requests", *requests, harness.Measure}, {"the connections", *connections, harness.MeasureConnections}} {
		if fixture.path == "" {
			continue
		}
		found, err := measureRequests(ctx, b, fixture.measure, fixture.path, names, about, *check, *newer, stderr)
		if !step(fixture.what, found, err) {
			return 1
		}
	}
	for _, fixture := range []struct {
		what    string
		path    string
		measure func() ([]string, error)
	}{
		{"the decoding", *decoding, func() ([]string, error) { return measureDecoding(ctx, b, *decoding, about, *check, stderr) }},
		{"the header blocks", *hpack, func() ([]string, error) {
			return measureHeaderBlocks(ctx, b, *hpack, names, about, *check, stderr)
		}},
		{"the TLS records", *records, func() ([]string, error) {
			return measureTLSRecords(ctx, b, *records, names, about, *check, *newer, stderr)
		}},
		{"the ALPS", *alps, func() ([]string, error) { return measureALPSFixture(ctx, b, *alps, names, about, *check, stderr) }},
		{"the window updates", *flow, func() ([]string, error) {
			return measureWindowUpdates(ctx, b, *flow, names, about, *check, stderr)
		}},
		{"the URLs", *urls, func() ([]string, error) { return measureURLs(ctx, b, *urls, names, about, *check, stderr) }},
		{"False Start", *falseStart, func() ([]string, error) {
			return measureFalseStartFixture(ctx, b, *falseStart, names, about, *check, stderr)
		}},
		{"the hellos", *hellos, func() ([]string, error) { return measureHellos(ctx, b, *hellos, about, *check, stderr) }},
	} {
		if fixture.path == "" {
			continue
		}
		if found, err := fixture.measure(); !step(fixture.what, found, err) {
			return 1
		}
	}
	if failed && !measuredAny {
		_, _ = fmt.Fprintln(stderr, "measure: nothing could be measured")
		return 1
	}
	for _, d := range diff {
		_, _ = fmt.Fprintln(stdout, d)
	}
	if len(diff) > 0 {
		_, _ = fmt.Fprintf(stderr, "measure: %d differences from the fixtures\n", len(diff))
		return 3
	}
	if *check {
		_, _ = fmt.Fprintln(stdout, "the browser is what the fixtures say")
	}
	return 0
}

// arguments are what --browser-arg gives, each as it is, in order.
type arguments []string

func (a *arguments) String() string { return strings.Join(*a, " ") }

func (a *arguments) Set(arg string) error {
	*a = append(*a, arg)
	return nil
}

// measurer measures the scenarios of a fixture of requests: harness.Measure,
// or harness.MeasureConnections.
type measurer func(ctx context.Context, b harness.Browser, only []string,
	progress io.Writer) (map[string]harness.MeasuredScenario, error)

// platform is the name of this machine's platform, as profiles say it.
var platform = profile.HostPlatform

// measureRequests measures the scenarios named, or every one, with measure,
// and holds them to the fixture at path, or writes them into it. A check
// passes over a scenario Chrome sends otherwise on this platform than on
// macOS (harness.Apart), saying so; a fixture is not written of a scenario
// the browser did not finish.
func measureRequests(ctx context.Context, b harness.Browser, measure measurer, path string, names []string, about string,
	check, newer bool, progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadRequests(path)
	if err != nil {
		return nil, err
	}
	if apart := harness.Apart(platform()); check && len(apart) > 0 {
		if names == nil {
			names = slices.Sorted(maps.Keys(fixture.Scenarios))
		}
		names = slices.DeleteFunc(slices.Clone(names), func(name string) bool {
			why, ok := apart[name]
			if ok {
				_, _ = fmt.Fprintf(progress, "%s: passed over on %s: %s\n", name, platform(), why)
			}
			return ok
		})
		if len(names) == 0 {
			return nil, nil
		}
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
		var own map[string]string
		if newer {
			own = harness.OwnValues(got)
		}
		return harness.Compare(want, got, own), nil
	}
	for _, name := range slices.Sorted(maps.Keys(got)) {
		if unfinished := got[name].Unfinished; len(unfinished) > 0 {
			return nil, fmt.Errorf("harness: %s did not finish %s: nothing written", name, strings.Join(unfinished, ", "))
		}
	}
	for name, scenario := range got {
		fixture.Scenarios[name] = scenario
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureURLs measures the URL cases named, or every one, and holds them to the
// fixture at path, or writes them into it.
func measureURLs(ctx context.Context, b harness.Browser, path string, names []string, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadURLs(path)
	if err != nil {
		return nil, err
	}
	got, err := urlCases(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Cases
		if names != nil {
			want = map[string]harness.URLCase{}
			for _, name := range names {
				if c, ok := fixture.Cases[name]; ok {
					want[name] = c
				}
			}
		}
		return harness.CompareURLs(want, got), nil
	}
	if fixture.Cases == nil {
		fixture.Cases = map[string]harness.URLCase{}
	}
	for name, c := range got {
		fixture.Cases[name] = c
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureHellos measures the order of the extensions of the first ClientHello
// to each name, launch by launch, and writes them into the fixture at path;
// or holds each launch to every order being as likely as any other, against
// the fixture's first order, which no launch measured now holds.
func measureHellos(ctx context.Context, b harness.Browser, path string, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadHellos(path)
	if err != nil {
		return nil, err
	}
	var reference []uint16
	if check {
		if len(fixture.Launches) == 0 || len(fixture.Launches[0]) == 0 {
			return nil, fmt.Errorf("%s holds no ClientHello to hold the browser against", path)
		}
		if reference, err = harness.ParseOrder(fixture.Launches[0][0]); err != nil {
			return nil, err
		}
	}
	got, err := helloOrders(ctx, b, progress)
	if err != nil {
		return nil, err
	}
	if !check {
		fixture.Launches = got
		fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
		return nil, fixture.Write(path)
	}
	var diff []string
	for i, launch := range got {
		orders := make([][]uint16, len(launch))
		for j, order := range launch {
			if orders[j], err = harness.ParseOrder(order); err != nil {
				return nil, err
			}
		}
		stats, err := harness.OrderStatsOf(orders, reference)
		if err != nil {
			return nil, err
		}
		for _, problem := range stats.Problems() {
			diff = append(diff, fmt.Sprintf("hellos, launch %d: %s", i+1, problem))
		}
	}
	return diff, nil
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

// measureFalseStartFixture measures the False Start scenarios named, or every
// one, and holds them to the fixture at path, or writes them into it.
func measureFalseStartFixture(ctx context.Context, b harness.Browser, path string, names []string, about string,
	check bool, progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadFalseStart(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureFalseStart(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.FalseStartScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		return harness.CompareFalseStart(want, got), nil
	}
	if fixture.Scenarios == nil {
		fixture.Scenarios = map[string]harness.FalseStartScenario{}
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

// measureTLSRecords measures the scenarios of records named, or every one, and
// holds them to the fixture at path, or writes them into it.
func measureTLSRecords(ctx context.Context, b harness.Browser, path string, names []string, about string, check, newer bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadRecords(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureRecords(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.RecordsScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		if newer {
			return harness.CompareRecordsNewer(want, got), nil
		}
		return harness.CompareRecords(want, got), nil
	}
	if fixture.Scenarios == nil {
		fixture.Scenarios = map[string]harness.RecordsScenario{}
	}
	for name, scenario := range got {
		fixture.Scenarios[name] = scenario
	}
	fixture.Browser, fixture.Measured = about, dated(fixture.Measured, today())
	return nil, fixture.Write(path)
}

// measureALPSFixture measures the scenarios of ALPS named, or every one, and
// holds them to the fixture at path, or writes them into it.
func measureALPSFixture(ctx context.Context, b harness.Browser, path string, names []string, about string, check bool,
	progress io.Writer) ([]string, error) {
	fixture, err := harness.LoadALPS(path)
	if err != nil {
		return nil, err
	}
	got, err := harness.MeasureALPS(ctx, b, names, progress)
	if err != nil {
		return nil, err
	}
	if check {
		want := fixture.Scenarios
		if names != nil {
			want = map[string]harness.ALPSScenario{}
			for _, name := range names {
				if scenario, ok := fixture.Scenarios[name]; ok {
					want[name] = scenario
				}
			}
		}
		return harness.CompareALPS(want, got), nil
	}
	if fixture.Scenarios == nil {
		fixture.Scenarios = map[string]harness.ALPSScenario{}
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
