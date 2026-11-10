//go:build ignore

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/harness"
)

func TestRecordingRefusesPartialOrUnfinishedEvidence(t *testing.T) {
	old := recordMeasure
	t.Cleanup(func() { recordMeasure = old })
	path := filepath.Join(t.TempDir(), "fixture.json")
	fixture := &harness.RequestsFixture{ObservationMS: harness.ObservationWindows{"auth-digest-negotiate": 15000},
		Scenarios: map[string]harness.MeasuredScenario{"auth-digest-negotiate": {}}}
	if err := fixture.Write(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	complete := harness.MeasuredScenario{H1: []harness.Request{{Method: "GET"}}, H2: []harness.Request{{Method: "GET"}}}
	for _, got := range []map[string]harness.MeasuredScenario{
		{}, {"other": complete}, {"auth-digest-negotiate": {Unfinished: []string{"timeout"}}},
		{"auth-digest-negotiate": {H1: complete.H1}},
	} {
		recordMeasure = func(context.Context, harness.Browser, []string, harness.ObservationWindows, io.Writer) (map[string]harness.MeasuredScenario, error) {
			return got, nil
		}
		if err := recordRequests(context.Background(), []string{"--browser", "chrome", "--fixture", path}, io.Discard); err == nil {
			t.Fatal("wrote incomplete evidence")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("failed measurement replaced input")
		}
	}
	recordMeasure = func(_ context.Context, b harness.Browser, only []string, windows harness.ObservationWindows, _ io.Writer) (map[string]harness.MeasuredScenario, error) {
		if !reflect.DeepEqual(only, []string{"auth-digest-negotiate"}) || windows[only[0]] != 15000 || b.(harness.Chrome).Path != "chrome" {
			t.Fatal("wrong recording plan")
		}
		return map[string]harness.MeasuredScenario{only[0]: complete}, nil
	}
	if err := recordRequests(context.Background(), []string{"--browser", "chrome", "--fixture", path}, io.Discard); err != nil {
		t.Fatal(err)
	}
	loaded, err := harness.LoadRequests(path)
	if err != nil || len(loaded.Scenarios) != 1 || len(loaded.Scenarios["auth-digest-negotiate"].H2) != 1 || loaded.Measured == "" || loaded.ObservationMS["auth-digest-negotiate"] != 15000 {
		t.Fatalf("recording lost evidence: %+v %v", loaded, err)
	}
}
