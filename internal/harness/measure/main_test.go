package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
// dump says; it fails what fail says. A page that goes on to a run page, as a
// scenario of connections starts at one, it follows there, and a run page,
// followed or opened, says it is done, on the connection it was asked on.
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
		asked := []string{page}
		if u, err := url.Parse(page); err == nil {
			origin := u.Scheme + "://" + u.Host
			switch run := u.Query().Get("next"); {
			case strings.HasPrefix(run, "/run/"):
				asked = append(asked, origin+run, origin+"/done/"+strings.TrimPrefix(run, "/run/"))
			case strings.HasPrefix(u.Path, "/run/"):
				asked = append(asked, origin+"/done/"+strings.TrimPrefix(u.Path, "/run/"))
			}
		}
		for _, page := range asked {
			if res, err := client.Get(page); err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}
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
	code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", decoding,
		"--hpack", "", "--flow", "", "--urls", "", "--only", "nav-direct")
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
	code, stdout, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", decoding,
		"--hpack", "", "--flow", "", "--urls", "", "--only", "nav-direct", "--check")
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A browser that decodes otherwise, and asks for what the fixture does
	// not have, is not.
	b.dump = func([]byte) string { return "<title>windows-1252|b</title>" }
	code, stdout, stderr = measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", decoding,
		"--hpack", "", "--flow", "", "--urls", "", "--only", "nav-direct,redir-nav-direct-301", "--check")
	if code != 1 || !strings.Contains(stdout, "redir-nav-direct-301 was measured, and the fixture has no such scenario\n") ||
		!strings.Contains(stdout, `a: the browser read "b" as "windows-1252"`) || !strings.HasSuffix(stderr, "measure: 2 differences from the fixtures\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// And without --only, every scenario is measured: here, one the fake
	// will not open.
	b.failOpen = true
	if code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", ""); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestTheCommandMeasuresWhichConnectionEachRequestCameOn(t *testing.T) {
	requests, _ := fixtures(t, map[string]harness.MeasuredScenario{"kept": {Note: "kept"}}, nil)
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	code, _, stderr := measured(t, "--browser", "chrome", "--requests", "", "--connections", requests, "--decoding", "",
		"--hpack", "", "--flow", "", "--urls", "", "--only", "conn-fetch")
	if code != 0 || !strings.Contains(stderr, "h1 conn-fetch: 1 requests") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadRequests(requests)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	// The run page alone: the fake asked for nothing more.
	if got := wrote.Scenarios["conn-fetch"].H2; len(got) != 1 || got[0].URL != "https://www.example.com/run/conn-fetch" ||
		got[0].Conn != 1 || wrote.Scenarios["kept"].Note != "kept" || wrote.Measured != "2026-10-16, 2026-10-17" {
		t.Errorf("wrote %+v", wrote)
	}
	code, stdout, stderr := measured(t, "--browser", "chrome", "--requests", "", "--connections", requests, "--decoding", "",
		"--hpack", "", "--flow", "", "--urls", "", "--only", "conn-fetch", "--check")
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
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
		{"no fixture of requests", &fake{}, []string{"--requests", missing, "--decoding", "", "--connections", ""}, "none.json"},
		{"no fixture of decodings", &fake{}, []string{"--requests", "", "--decoding", missing, "--connections", ""}, "none.json"},
		{"no fixture of connections", &fake{}, []string{"--requests", "", "--decoding", "", "--connections", missing}, "none.json"},
		{"a page it cannot dump", &fake{failDumps: true}, []string{"--requests", "", "--decoding", decoding, "--connections", ""}, ""},
		{"a scenario that is none", &fake{}, []string{"--requests", requests, "--decoding", "", "--connections", "", "--only", "nothing"},
			"there is no scenario nothing"},
		{"a scenario of connections, with the fixture of requests", &fake{},
			[]string{"--requests", requests, "--decoding", "", "--connections", requests, "--only", "conn-fetch"},
			"there is no scenario conn-fetch"},
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
		{"--requests", requests, "--decoding", "", "--connections", "", "--only", "nav-direct"},
		{"--requests", "", "--decoding", decoding, "--connections", ""},
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
		{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "", "--urls", ""},
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

// blocks is a fixture of header blocks holding scenarios, in a directory of its
// own.
func blocks(t *testing.T, scenarios map[string]harness.HPACKScenario) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hpack.json")
	if err := (&harness.HPACKFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheHeaderBlocksAndThenHoldsTheBrowserToThem(t *testing.T) {
	hpack := blocks(t, map[string]harness.HPACKScenario{"kept": {Note: "kept"}})
	b := &fake{}
	opening(t, b, "Fake Chrome 1.2.3.4")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--flow", "", "--urls", ""}
	code, _, stderr := measured(t, append(none, "--hpack", hpack, "--only", "hpack-fetch")...)
	if code != 0 || !strings.Contains(stderr, "h2 hpack-fetch: 1 connections") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadHPACK(hpack)
	if err != nil {
		t.Fatalf("LoadHPACK: %v", err)
	}
	fetch := wrote.Scenarios["hpack-fetch"]
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Scenarios) != 2 || wrote.Scenarios["kept"].Note != "kept" ||
		len(fetch.Connections) != 1 || len(fetch.Connections[0]) != 2 || fetch.Connections[0][1].URL != "https://www.example.com/done/hpack-fetch" {
		t.Errorf("wrote %+v", wrote)
	}
	// Measured again, the browser is what it says.
	code, stdout, stderr := measured(t, append(none, "--hpack", hpack, "--only", "hpack-fetch", "--check")...)
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that says otherwise is not, nor one without the scenario.
	fetch.Connections[0] = fetch.Connections[0][:1]
	hpack = blocks(t, map[string]harness.HPACKScenario{"hpack-fetch": fetch})
	code, stdout, stderr = measured(t, append(none, "--hpack", hpack, "--only", "hpack-fetch,hpack-table-1k", "--check")...)
	if code != 1 || stdout != "hpack-fetch: connection 1: 2 requests, want 1\n"+
		"hpack-table-1k was measured, and the fixture has no such scenario\n" ||
		!strings.HasSuffix(stderr, "measure: 2 differences from the fixtures\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that is not one's scenarios are made.
	empty := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(empty, []byte("{}"), 0o644)
	if code, _, stderr := measured(t, append(none, "--hpack", empty, "--only", "hpack-fetch")...); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if wrote, err := harness.LoadHPACK(empty); err != nil || len(wrote.Scenarios) != 1 {
		t.Errorf("made %+v, %v", wrote, err)
	}
	// Every fixture measured has to have every scenario named.
	requests, _ := fixtures(t, map[string]harness.MeasuredScenario{}, nil)
	if code, _, stderr := measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", "",
		"--hpack", empty, "--only", "hpack-fetch"); code != 1 || !strings.Contains(stderr, "there is no scenario hpack-fetch") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestTheCommandSaysWhyItMeasuredNoHeaderBlocks(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--flow", "", "--urls", ""}
	missing := filepath.Join(t.TempDir(), "none.json")
	opening(t, &fake{}, "Fake")
	if code, _, stderr := measured(t, append(none, "--hpack", missing)...); code != 1 || !strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	opening(t, &fake{failOpen: true}, "Fake")
	hpack := blocks(t, map[string]harness.HPACKScenario{})
	if code, _, stderr := measured(t, append(none, "--hpack", hpack, "--only", "hpack-fetch")...); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("a browser that does not open: exit %d, %s", code, stderr)
	}
	if os.Geteuid() != 0 {
		opening(t, &fake{}, "Fake")
		if err := os.Chmod(hpack, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append(none, "--hpack", hpack, "--only", "hpack-fetch")...); code != 1 ||
			!strings.Contains(stderr, "permission denied") {
			t.Errorf("a fixture it may not write: exit %d, %s", code, stderr)
		}
	}
}

func flows(t *testing.T, scenarios map[string]harness.FlowScenario) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flow.json")
	if err := (&harness.FlowFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheWindowUpdatesAndThenHoldsTheBrowserToThem(t *testing.T) {
	flow := flows(t, map[string]harness.FlowScenario{"kept": {FlowShape: harness.FlowShape{Note: "kept"}}})
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--urls", ""}
	code, _, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small")...)
	if code != 0 || !strings.Contains(stderr, "h2 flow-small: ") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadFlow(flow)
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	small := wrote.Scenarios["flow-small"]
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Scenarios) != 2 || wrote.Scenarios["kept"].Note != "kept" || small.Size != 300<<10 {
		t.Errorf("wrote %+v", wrote)
	}
	// A fixture that says otherwise is not the browser, nor one without the
	// scenario.
	small.Updates = append(small.Updates, harness.FlowUpdate{Window: "first", Increment: 1, Part: 9})
	flow = flows(t, map[string]harness.FlowScenario{"flow-small": small})
	code, stdout, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small,flow-half", "--check")...)
	if code != 1 || !strings.Contains(stdout, "flow-small: ") ||
		!strings.Contains(stdout, "flow-half was measured, and the fixture has no such scenario\n") ||
		!strings.Contains(stderr, "differences from the fixtures") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// Held to the whole fixture, every scenario is measured.
	flow = flows(t, map[string]harness.FlowScenario{})
	if code, stdout, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small", "--check")...); code != 1 ||
		stdout != "flow-small was measured, and the fixture has no such scenario\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that is not one's scenarios are made.
	empty := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(empty, []byte("{}"), 0o644)
	if code, _, stderr := measured(t, append(none, "--flow", empty, "--only", "flow-small")...); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if wrote, err := harness.LoadFlow(empty); err != nil || len(wrote.Scenarios) != 1 {
		t.Errorf("made %+v, %v", wrote, err)
	}
}

func TestTheCommandSaysWhyItMeasuredNoWindowUpdates(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--urls", ""}
	opening(t, &fake{}, "Fake")
	if code, _, stderr := measured(t, append(none, "--flow", filepath.Join(t.TempDir(), "none.json"))...); code != 1 ||
		!strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	flow := flows(t, map[string]harness.FlowScenario{})
	if code, _, stderr := measured(t, append(none, "--flow", flow, "--only", "nothing")...); code != 1 ||
		!strings.Contains(stderr, "there is no scenario nothing") {
		t.Errorf("a scenario that is none: exit %d, %s", code, stderr)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(flow, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small")...); code != 1 ||
			!strings.Contains(stderr, "permission denied") {
			t.Errorf("a fixture it may not write: exit %d, %s", code, stderr)
		}
	}
}

// urlsMeasured has the command's URL cases measured as got and err say, with
// no browser and no waiting, and is the names it was asked to measure.
func urlsMeasured(t *testing.T, got map[string]harness.URLCase, err error) *[]string {
	t.Helper()
	var asked []string
	old := urlCases
	urlCases = func(_ context.Context, _ harness.Browser, only []string, progress io.Writer) (map[string]harness.URLCase, error) {
		asked = append(asked, only...)
		_, _ = io.WriteString(progress, "h2 measured\n")
		return got, err
	}
	t.Cleanup(func() { urlCases = old })
	return &asked
}

func urlFixture(t *testing.T, cases map[string]harness.URLCase) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "urls.json")
	if err := (&harness.URLsFixture{Browser: "old", Measured: "2026-10-16", How: "how", Cases: cases}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheURLsAndThenHoldsTheBrowserToThem(t *testing.T) {
	sent := harness.SentURL{Scheme: "https", Authority: "www.example.com", Target: "/p/x"}
	upper := harness.URLCase{Note: "upper", Input: "https://WWW.EXAMPLE.COM/p/x", H2: sent, H1: sent}
	asked := urlsMeasured(t, map[string]harness.URLCase{"url-host-upper": upper}, nil)
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", ""}
	urls := urlFixture(t, map[string]harness.URLCase{"kept": {Note: "kept"}})
	code, _, stderr := measured(t, append(none, "--urls", urls, "--only", "url-host-upper")...)
	if code != 0 || !strings.Contains(stderr, "h2 measured") || strings.Join(*asked, ",") != "url-host-upper" {
		t.Fatalf("exit %d, asked %v: %s", code, *asked, stderr)
	}
	wrote, err := harness.LoadURLs(urls)
	if err != nil {
		t.Fatalf("LoadURLs: %v", err)
	}
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Cases) != 2 || wrote.Cases["kept"].Note != "kept" || wrote.Cases["url-host-upper"] != upper {
		t.Errorf("wrote %+v", wrote)
	}
	// A fixture that says otherwise is not the browser; one without the case
	// named does not have it.
	other := upper
	other.H1 = harness.SentURL{Refused: "blocked"}
	urls = urlFixture(t, map[string]harness.URLCase{"url-host-upper": other, "url-host-idn": upper})
	code, stdout, stderr := measured(t, append(none, "--urls", urls, "--only", "url-host-upper,url-scheme-upper", "--check")...)
	if code != 1 || stdout != "url-host-upper over h1: https www.example.com/p/x (sni \"\"), want blocked\n" ||
		!strings.Contains(stderr, "1 differences from the fixtures") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// Held to the whole fixture, every case of it is measured.
	if code, stdout, stderr := measured(t, append(none, "--urls", urls, "--check")...); code != 1 ||
		!strings.Contains(stdout, "url-host-idn was not measured\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	urls = urlFixture(t, map[string]harness.URLCase{"url-host-upper": upper})
	if code, stdout, stderr := measured(t, append(none, "--urls", urls, "--check")...); code != 0 ||
		stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that is not one's cases are made.
	empty := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(empty, []byte("{}"), 0o644)
	if code, _, stderr := measured(t, append(none, "--urls", empty, "--only", "url-host-upper")...); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if wrote, err := harness.LoadURLs(empty); err != nil || len(wrote.Cases) != 1 {
		t.Errorf("made %+v, %v", wrote, err)
	}
}

func TestTheCommandSaysWhyItMeasuredNoURLs(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", ""}
	opening(t, &fake{}, "Fake")
	urlsMeasured(t, map[string]harness.URLCase{}, nil)
	if code, _, stderr := measured(t, append(none, "--urls", filepath.Join(t.TempDir(), "none.json"))...); code != 1 ||
		!strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	urls := urlFixture(t, map[string]harness.URLCase{})
	urlsMeasured(t, nil, errors.New("harness: there is no scenario nothing"))
	if code, _, stderr := measured(t, append(none, "--urls", urls, "--only", "nothing")...); code != 1 ||
		!strings.Contains(stderr, "measure: harness: there is no scenario nothing") {
		t.Errorf("a case that is none: exit %d, %s", code, stderr)
	}
	urlsMeasured(t, map[string]harness.URLCase{}, nil)
	if os.Geteuid() != 0 {
		if err := os.Chmod(urls, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append(none, "--urls", urls, "--only", "url-host-upper")...); code != 1 ||
			!strings.Contains(stderr, "permission denied") {
			t.Errorf("a fixture it may not write: exit %d, %s", code, stderr)
		}
	}
}

func TestTheCommandMeasuresTheURLCasesItIsNotToldOtherwise(t *testing.T) {
	// The seam is the harness's own measurement until a test says otherwise.
	if reflect.ValueOf(urlCases).Pointer() != reflect.ValueOf(harness.MeasureURLs).Pointer() {
		t.Error("URL cases are measured otherwise")
	}
}
