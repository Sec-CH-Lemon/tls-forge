//go:build ignore

// Command record-release-requests records an explicit request-fixture selection
// for release-oracle calibration. It never skips platform cases or writes an
// unfinished scenario. The native workflow keeps the raw output encrypted.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
)

var recordMeasure = harness.MeasureObserved

func main() {
	if err := recordRequests(context.Background(), os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func recordRequests(ctx context.Context, args []string, progress io.Writer) error {
	flags := flag.NewFlagSet("record-release-requests", flag.ContinueOnError)
	flags.SetOutput(progress)
	browser := flags.String("browser", "", "Google Chrome binary to measure")
	path := flags.String("fixture", "", "input plan and output fixture; every listed scenario is measured")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *browser == "" || *path == "" || flags.NArg() != 0 {
		return fmt.Errorf("--browser and --fixture are required, with no other arguments")
	}
	f, err := harness.LoadRequests(*path)
	if err != nil {
		return err
	}
	if len(f.Scenarios) == 0 {
		return fmt.Errorf("fixture must explicitly select at least one scenario")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	got, err := recordMeasure(ctx, harness.Chrome{Path: *browser, Args: []string{"--no-sandbox"}},
		slices.Sorted(maps.Keys(f.Scenarios)), f.ObservationMS, progress)
	if err != nil {
		return err
	}
	if len(got) != len(f.Scenarios) {
		return fmt.Errorf("measurement returned a different scenario inventory")
	}
	for id := range f.Scenarios {
		measured, ok := got[id]
		if !ok || len(measured.Unfinished) != 0 || len(measured.H1) == 0 || len(measured.H2) == 0 {
			return fmt.Errorf("%s missing, unfinished or has no requests: nothing written", id)
		}
	}
	f.Scenarios = got
	f.Measured = time.Now().UTC().Format(time.RFC3339)
	return f.Write(*path)
}
