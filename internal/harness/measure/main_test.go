package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
)

// client asks the bench's server for a page: every name it serves is the
// loopback address, and its certificate is taken on trust.
var client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
	},
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the bench's own certificate
	ForceAttemptHTTP2: true,
}}

// fake is a browser that asks for the page it opens, and dumps each page as
// dump says; it fails what fail says.
type fake struct {
	dump      func(body []byte) string
	failOpen  bool
	failDumps bool
}

func (f *fake) Open(_ context.Context, page, _ string) (func(), error) {
	if f.failOpen {
		return nil, errors.New("the fake would not open " + page)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if res, err := client.Get(page); err == nil {
			_ = res.Body.Close()
		}
	}()
	return func() { <-done }, nil
}

func (f *fake) DumpDOM(_ context.Context, page string) ([]byte, error) {
	if f.failDumps {
		return nil, errors.New("the fake dumped nothing")
	}
	res, err := client.Get(page)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return []byte(f.dump(body)), nil
}

// opening has the command measure b, which says it is said.
func opening(t *testing.T, b harness.Browser, said string) {
	t.Helper()
	oldOpen, oldMachine, oldToday := open, machine, today
	open = func(context.Context, string) (harness.Browser, string, error) { return b, said, nil }
	machine = func() string { return "Testing 1 (arm64)" }
	today = func() string { return "2026-10-17" }
	t.Cleanup(func() { open, machine, today = oldOpen, oldMachine, oldToday })
}

// fixtures are a fixture of requests holding scenarios, and one of decodings
// holding cases, in a directory of their own.
func fixtures(t *testing.T, scenarios map[string]harness.MeasuredScenario, cases []harness.DecodingCase) (string, string) {
	t.Helper()
	dir := t.TempDir()
	requests, decoding := filepath.Join(dir, "requests.json"), filepath.Join(dir, "decoding.json")
	if err := (&harness.RequestsFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(requests); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := (&harness.DecodingFixture{Browser: "old", Measured: "2026-10-16", How: "how", Cases: cases}).Write(decoding); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return requests, decoding
}

func measured(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestTheCommandWritesWhatItMeasuredAndThenHoldsTheBrowserToIt(t *testing.T) {
	text := "x"
	cases := []harness.DecodingCase{{Name: "a", ContentType: &text, Body: []byte("<p>a</p>"), Word: []byte("a")}}
	requests, decoding := fixtures(t, map[string]harness.MeasuredScenario{"kept": {Note: "kept"}}, cases)
	b := &fake{dump: func(body []byte) string { return "<title>UTF-8|" + string(body[3:4]) + "</title>" }}
	opening(t, b, "Fake Chrome 1.2.3.4")
	code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--decoding", decoding, "--only", "nav-direct")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "h2 nav-direct: 1 requests") || !strings.Contains(stderr, "decoding a") {
		t.Errorf("progress %q", stderr)
	}
	wrote, err := harness.LoadRequests(requests)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Scenarios) != 2 || len(wrote.Scenarios["nav-direct"].H2) != 1 || wrote.Scenarios["kept"].Note != "kept" {
		t.Errorf("wrote %+v", wrote)
	}
	wroteDecoding, err := harness.LoadDecoding(decoding)
	if err != nil {
		t.Fatalf("LoadDecoding: %v", err)
	}
	if c := wroteDecoding.Cases[0]; c.Encoding != "UTF-8" || *c.Text != "a" || wroteDecoding.Measured != "2026-10-16, 2026-10-17" {
		t.Errorf("wrote %+v", wroteDecoding)
	}
	// Measured again, the browser is what they say.
	code, stdout, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--decoding", decoding, "--only", "nav-direct", "--check")
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A browser that decodes otherwise, and asks for what the fixture does
	// not have, is not.
	b.dump = func([]byte) string { return "<title>windows-1252|b</title>" }
	code, stdout, stderr = measured(t, "--browser", "chrome", "--requests", requests, "--decoding", decoding,
		"--only", "nav-direct,redir-nav-direct-301", "--check")
	if code != 1 || !strings.Contains(stdout, "redir-nav-direct-301 was measured, and the fixture has no such scenario\n") ||
		!strings.Contains(stdout, `a: the browser read "b" as "windows-1252"`) || !strings.HasSuffix(stderr, "measure: 2 differences from the fixtures\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// And without --only, every scenario is measured: here, one the fake
	// will not open.
	b.failOpen = true
	if code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--decoding", ""); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestTheCommandSaysWhyItMeasuredNothing(t *testing.T) {
	requests, decoding := fixtures(t, map[string]harness.MeasuredScenario{}, nil)
	missing := filepath.Join(t.TempDir(), "none.json")
	for _, tc := range []struct {
		name string
		b    *fake
		args []string
		says string
	}{
		{"no fixture of requests", &fake{}, []string{"--requests", missing, "--decoding", ""}, "none.json"},
		{"no fixture of decodings", &fake{}, []string{"--requests", "", "--decoding", missing}, "none.json"},
		{"a page it cannot dump", &fake{failDumps: true}, []string{"--requests", "", "--decoding", decoding}, ""},
		{"a scenario that is none", &fake{}, []string{"--requests", requests, "--decoding", "", "--only", "nothing"},
			"there is no scenario nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opening(t, tc.b, "Fake")
			if tc.name == "a page it cannot dump" {
				text := "x"
				_, decoding = fixtures(t, nil, []harness.DecodingCase{{Name: "a", ContentType: &text}})
				tc.args[3] = decoding
				tc.says = "the fake dumped nothing"
			}
			code, _, stderr := measured(t, append([]string{"--browser", "chrome"}, tc.args...)...)
			if code != 1 || !strings.Contains(stderr, tc.says) {
				t.Errorf("exit %d: %s, want %q", code, stderr, tc.says)
			}
		})
	}
	oldOpen := open
	open = func(context.Context, string) (harness.Browser, string, error) {
		return nil, "", errors.New("no browser here")
	}
	t.Cleanup(func() { open = oldOpen })
	if code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests); code != 1 || stderr != "measure: no browser here\n" {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestTheCommandSaysWhyItCouldNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a file it may not")
	}
	text := "x"
	requests, decoding := fixtures(t, map[string]harness.MeasuredScenario{}, []harness.DecodingCase{{Name: "a", ContentType: &text}})
	opening(t, &fake{dump: func([]byte) string { return "<p>a</p>" }}, "Fake")
	for _, args := range [][]string{
		{"--requests", requests, "--decoding", "", "--only", "nav-direct"},
		{"--requests", "", "--decoding", decoding},
	} {
		path := args[1]
		if path == "" {
			path = args[3]
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append([]string{"--browser", "chrome"}, args...)...); code != 1 ||
			!strings.Contains(stderr, "permission denied") {
			t.Errorf("%v: exit %d, %s", args, code, stderr)
		}
	}
}

func TestTheCommandNeedsABrowserAndAFixture(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--requests", "a.json"},
		{"--browser", "chrome", "extra"},
		{"--browser", "chrome", "--requests", "", "--decoding", ""},
		{"--no-such-flag"},
	} {
		if code, _, _ := measured(t, args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestADayIsAddedToTheDatesMeasuredOnce(t *testing.T) {
	for _, tc := range [][3]string{
		{"", "2026-10-17", "2026-10-17"},
		{"2026-10-16", "2026-10-17", "2026-10-16, 2026-10-17"},
		{"2026-10-16, 2026-10-17", "2026-10-17", "2026-10-16, 2026-10-17"},
		{"2026-10-17, 2026-10-16", "2026-10-17", "2026-10-17, 2026-10-16"},
	} {
		if got := dated(tc[0], tc[1]); got != tc[2] {
			t.Errorf("dated(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestAMachineIsSaidAsTheFixturesSayIt(t *testing.T) {
	saying := func(out string) func(string, ...string) *exec.Cmd {
		return func(string, ...string) *exec.Cmd {
			if out == "" {
				return exec.Command(filepath.Join(t.TempDir(), "none"))
			}
			return exec.Command("/bin/echo", out)
		}
	}
	reading := func(text string, err error) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(text), err }
	}
	if runtime.GOOS == "windows" {
		t.Skip("the stand-ins are Unix commands")
	}
	for _, tc := range []struct {
		goos    string
		command func(string, ...string) *exec.Cmd
		read    func(string) ([]byte, error)
		want    string
	}{
		{"darwin", saying("27.0.1"), nil, "macOS 27.0.1 (arm64)"},
		{"darwin", saying(""), nil, "macOS (arm64)"},
		{"linux", nil, reading("NAME=x\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n", nil), "Ubuntu 24.04.3 LTS (arm64)"},
		{"linux", nil, reading("NAME=x\n", nil), "Linux (arm64)"},
		{"linux", nil, reading("", errors.New("none")), "Linux (arm64)"},
		{"windows", nil, nil, "Windows (arm64)"},
		{"freebsd", nil, nil, "freebsd (arm64)"},
	} {
		if got := describe(tc.goos, "arm64", tc.command, tc.read); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestTheDefaultsSayThisMachineAndToday(t *testing.T) {
	if got := machine(); !strings.HasSuffix(got, "("+runtime.GOARCH+")") {
		t.Errorf("machine() = %q", got)
	}
	if got := today(); got != time.Now().UTC().Format(time.DateOnly) {
		t.Errorf("today() = %q", got)
	}
}

func TestTheBrowserIsFoundAndAskedWhatItIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-ins are shell scripts")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}
	path := write("chrome", "echo 'Google Chrome 155.0.8059.80 '\n")
	b, said, err := open(context.Background(), path)
	if err != nil || said != "Google Chrome 155.0.8059.80" || b.(harness.Chrome).Path != path {
		t.Errorf("open: %v, %q, %v", b, said, err)
	}
	failing := write("failing", "exit 3\n")
	if _, _, err := open(context.Background(), failing); err == nil || !strings.Contains(err.Error(), "asking "+failing+" its version") {
		t.Errorf("open of a browser that will not say: %v", err)
	}
	if _, _, err := open(context.Background(), filepath.Join(dir, "none")); err == nil {
		t.Error("open of no browser")
	}
}

func TestMainEntryPoint(t *testing.T) {
	originalExit, originalArgs := exit, os.Args
	t.Cleanup(func() { exit, os.Args = originalExit, originalArgs })
	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"measure"}
	main()
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
}
