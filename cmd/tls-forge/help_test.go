package main

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func TestGroupedFlags(t *testing.T) {
	fs := newFlagSet("x", newPrinter(io.Discard))
	fs.StringP("alpha", "a", "", "the first")
	fs.Bool("beta", false, "the second,\nwhich runs on")
	fs.String("gamma", "", "the third")
	fs.String("delta", "", "the fourth, in no group")
	got := groupedFlags(fs.FlagUsages(), []flagGroup{
		// In the order the groups give, which is not the order of the flags.
		{"first", []string{"gamma", "alpha"}},
		// A group of nothing there is not shown, and a flag shown is not shown
		// again.
		{"empty", []string{"nothing"}},
		{"second", []string{"beta", "alpha"}},
	})
	lines := strings.Split(got, "\n")
	var headings, names []string
	for _, line := range lines {
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			headings = append(headings, line)
		}
		if match := flagLine.FindStringSubmatch(line); match != nil {
			names = append(names, match[1])
		}
	}
	if want := []string{"first:", "second:", "other flags:"}; !slices.Equal(headings, want) {
		t.Errorf("headings %q, want %q\n%s", headings, want, got)
	}
	if want := []string{"gamma", "alpha", "beta", "delta"}; !slices.Equal(names, want) {
		t.Errorf("flags %q, want %q\n%s", names, want, got)
	}
	// A description that runs on stays with its flag.
	if !strings.Contains(got, "the second,\n") || !strings.Contains(got, "which runs on\n\nother flags:") {
		t.Errorf("the second flag's description was split from it:\n%s", got)
	}
	// One column for every group, as pflag lines them up.
	column := -1
	for _, line := range lines {
		if flagLine.MatchString(line) {
			at := strings.Index(line, "the ")
			if column >= 0 && at != column {
				t.Errorf("descriptions start at %d and at %d:\n%s", column, at, got)
			}
			column = at
		}
	}
}

func TestFetchHelpShowsEveryFlagUnderAGroup(t *testing.T) {
	code, stdout, _ := exec(t, "fetch", "--help")
	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}
	var shown []string
	for _, line := range strings.Split(stdout, "\n") {
		if match := flagLine.FindStringSubmatch(line); match != nil {
			shown = append(shown, match[1])
		}
	}
	// Every flag under a heading of its own group, once, and every flag a group
	// names one fetch has: a flag renamed in one place and not the other would
	// otherwise be shown under "other flags", or not at all.
	var grouped []string
	for _, group := range fetchFlagGroups {
		if !strings.Contains(stdout, "\n"+group.title+":\n") {
			t.Errorf("no heading %q", group.title)
		}
		grouped = append(grouped, group.names...)
	}
	if strings.Contains(stdout, "other flags:") || !slices.Equal(shown, grouped) {
		t.Errorf("fetch --help shows %q, the groups name %q\n%s", shown, grouped, stdout)
	}
}
