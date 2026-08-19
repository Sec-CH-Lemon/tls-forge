package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

func headerCapture(names ...string) *capture.Capture {
	fields := make([]capture.HeaderField, len(names))
	for i, name := range names {
		fields[i] = capture.HeaderField{Name: name, Value: "v-" + name}
	}
	return &capture.Capture{HTTP2: &capture.HTTP2{Headers: fields}}
}

func TestPrintGoogleHeaders(t *testing.T) {
	ordinary := headerCapture("accept", "user-agent")
	google := headerCapture("accept", "x-browser-channel", "x-client-data", "user-agent")

	var buf bytes.Buffer
	printGoogleHeaders(newPrinter(&buf), ordinary, google)
	got := buf.String()
	for _, want := range []string{"x-browser-channel  v-x-browser-channel", "x-client-data"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not mention %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "accept  v-accept") {
		t.Errorf("the report repeats headers the ordinary capture already had:\n%s", got)
	}
	// Where the block goes is part of what was measured, so the report says it.
	if !strings.Contains(got, "(after accept)") {
		t.Errorf("the report does not say where the block sits:\n%s", got)
	}

	// A browser that is not Google Chrome sends no block, and saying so is the
	// difference between a profile that lacks the headers and one that lacks
	// them for a reason nobody wrote down.
	buf.Reset()
	printGoogleHeaders(newPrinter(&buf), ordinary, ordinary)
	if !strings.Contains(buf.String(), "nothing extra") {
		t.Errorf("stdout = %q", buf.String())
	}

	buf.Reset()
	printGoogleHeaders(newPrinter(&buf), ordinary, nil)
	if !strings.Contains(buf.String(), "nothing extra") {
		t.Errorf("a failed pass should read as nothing extra, got %q", buf.String())
	}
}

// browserStandInThatIsNotGoogleChrome answers the ordinary capture and refuses
// the Google pass, which is every browser that is not Chrome and every machine
// where the second launch goes wrong.
func browserStandInThatIsNotGoogleChrome(t *testing.T) string {
	t.Helper()
	return standIn(t, `case "$*" in *--host-resolver-rules=*) exit 5 ;; esac`)
}

func TestCaptureSurvivesAFailedGooglePass(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/p.json"
	code, stdout, stderr := exec(t, "capture",
		"--browser", browserStandInThatIsNotGoogleChrome(t), "--timeout", "5s", "--save", path)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "could not measure the Google headers") {
		t.Errorf("the failure was not reported:\n%s", stderr)
	}
	if !strings.Contains(stdout, "wrote profile") {
		t.Errorf("the profile was not written:\n%s", stdout)
	}
}

func TestSaveProfileRefusesAScatteredGoogleBlock(t *testing.T) {
	// The Google pass is meant to add one block and change nothing else. If it
	// comes back interleaved, the two captures disagree about more than Google,
	// and a profile built from them would replay an order nobody measured.
	raw, err := os.ReadFile("../../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	measured := &capture.Capture{RawClientHello: raw,
		HTTP2: &capture.HTTP2{Headers: []capture.HeaderField{
			{Name: "accept", Value: "*/*"},
			{Name: "user-agent", Value: "ua"},
		}}}
	google := &capture.Capture{RawClientHello: raw,
		HTTP2: &capture.HTTP2{Headers: []capture.HeaderField{
			{Name: "accept", Value: "*/*"},
			{Name: "x-one", Value: "1"},
			{Name: "user-agent", Value: "ua"},
			{Name: "x-two", Value: "2"},
		}}}

	_, _, err = saveProfile(filepath.Join(t.TempDir(), "p.json"), "chrome_151", measured, google)
	if err == nil {
		t.Error("a scattered block was written into a profile")
	}
}
