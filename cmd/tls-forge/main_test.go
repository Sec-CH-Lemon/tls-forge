package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// The CLI is driven the way a user drives it — argv in, bytes out — rather than
// by calling the functions underneath. That is the only way to catch a flag
// that was renamed, a command that was never wired up, or an exit code that
// stopped meaning what a CI job assumes it means.

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	// Bounded, because `proxy` and `serve` run until their context is cancelled
	// and a background context is never cancelled. A test that starts one by
	// accident used to wedge the whole package for the five minutes `go test`
	// allows, and the panic that ended it named the test but not the reason.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code = run(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func startEcho(t *testing.T) *echo.Server {
	t.Helper()
	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// TestBrowserHelper stands in for a browser, as in the library's own tests.
func TestBrowserHelper(t *testing.T) {
	url := os.Getenv("TLSFORGE_BROWSER_HELPER")
	if url == "" {
		t.Skip("not running as the browser stand-in")
	}
	client, err := tlsforge.New(tlsforge.WithInsecureSkipVerify(), tlsforge.WithoutRedirects())
	if err != nil {
		os.Exit(1)
	}
	defer client.Close()
	page, err := client.Do(&tlsforge.Request{URL: url, Header: tlsforge.NewHeader(
		"sec-fetch-site", "none",
		"sec-fetch-mode", "navigate",
		"sec-fetch-user", "?1",
		"sec-fetch-dest", "document",
	)})
	if err != nil {
		os.Exit(1)
	}
	if strings.Contains(url, "http1=cold") {
		os.Exit(0)
	}
	const marker = "fetch('"
	start := strings.Index(page.Text(), marker)
	if start < 0 {
		os.Exit(1)
	}
	start += len(marker)
	end := strings.IndexByte(page.Text()[start:], '\'')
	if end < 0 {
		os.Exit(1)
	}
	final, err := neturl.Parse(page.URL)
	if err != nil {
		os.Exit(1)
	}
	collect := final.Scheme + "://" + final.Host + page.Text()[start:start+end]
	if _, err := client.Do(&tlsforge.Request{
		Method: "POST",
		URL:    collect,
		Body:   []byte(`{"user_agent":"Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36"}`),
		Header: tlsforge.NewHeader("content-type", "application/json"),
	}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func browserStandIn(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
for last; do :; done
TLSFORGE_BROWSER_HELPER="$last" exec %q -test.run='^TestBrowserHelper$'
`, self)
	path := filepath.Join(t.TempDir(), "stand-in-browser")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the stand-in: %v", err)
	}
	return path
}

func TestUsage(t *testing.T) {
	code, _, stderr := exec(t)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "usage: tls-forge") {
		t.Errorf("stderr = %q", stderr)
	}
	// Every command must appear, or a user cannot discover it.
	for _, c := range commands() {
		if !strings.Contains(stderr, c.name) {
			t.Errorf("usage does not mention %q", c.name)
		}
	}
}

func TestHelpGoesToStdoutAndSucceeds(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		code, stdout, _ := exec(t, arg)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0", arg, code)
		}
		if !strings.Contains(stdout, "usage: tls-forge") {
			t.Errorf("%s: stdout = %q", arg, stdout)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := exec(t, "frobnicate")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := exec(t, "version")
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "tls-forge") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestBadFlagExitsTwo(t *testing.T) {
	// A mistyped flag should print the usage and exit 2, the way every other
	// Unix tool does, rather than crash or carry on.
	//
	// Spelled with two dashes, because with one it is not a mistyped flag: a
	// single dash introduces short flags, so `-nonsense` is `-n onsense`, and
	// every tool that follows this convention reads it that way.
	//
	// 2, not 1: compare uses 3 for "the fingerprints differ", and a typo must
	// not look like that to the job watching for it.
	for _, args := range [][]string{
		{"fetch", "--nonsense"},
		{"capture", "--nonsense"},
		{"compare", "--nonsense"},
		{"profiles", "--nonsense"},
		{"serve", "--nonsense"},
		{"daemon", "--nonsense"},
		{"capture", "-Z"},
	} {
		code, _, _ := exec(t, args...)
		if code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}
}

func TestFetch(t *testing.T) {
	server := startEcho(t)
	code, stdout, stderr := exec(t, "fetch", "--insecure", server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}

	var measured map[string]any
	if err := json.Unmarshal([]byte(stdout), &measured); err != nil {
		t.Fatalf("output was not the echo server's JSON: %v", err)
	}
	if measured["tls"] == nil {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestFetchWithHeadersAndStatusLine(t *testing.T) {
	server := startEcho(t)
	code, stdout, _ := exec(t, "fetch", "--insecure", "-i",
		"-H", "X-One: 1", "-H", "Referer: https://example.com",
		server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(stdout, "200 ") {
		t.Errorf("stdout does not start with the status line: %q", stdout[:40])
	}
	if !strings.Contains(stdout, "content-type: application/json") {
		t.Errorf("stdout does not show the response headers")
	}
	// The extra headers must have reached the server in the order given.
	body := stdout[strings.Index(stdout, "{"):]
	if !strings.Contains(body, `"x-one"`) || !strings.Contains(body, `"referer"`) {
		t.Errorf("the -H headers did not reach the server")
	}
}

func TestFetchWritesToAFile(t *testing.T) {
	server := startEcho(t)
	path := filepath.Join(t.TempDir(), "body.json")
	code, stdout, _ := exec(t, "fetch", "--insecure", "-o", path, server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "wrote") {
		t.Errorf("stdout = %q", stdout)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the output: %v", err)
	}
	if len(written) == 0 {
		t.Error("the file is empty")
	}
}

func TestFetchPost(t *testing.T) {
	server := startEcho(t)
	code, stdout, _ := exec(t, "fetch", "--insecure", "--method", "POST",
		"-H", "content-type: application/json",
		"--data", `{"user_agent":"from the CLI"}`, server.URL()+"/collect")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "from the CLI") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestFetchArgumentErrors(t *testing.T) {
	// The two exit codes mean different things and a caller can act on the
	// difference: 2 is "you typed it wrong, nothing was attempted", 1 is "it ran
	// and failed". compare also uses 1 for "the fingerprints differ", so a typo
	// must never come out as 1.
	for _, args := range [][]string{
		{"fetch"},               // no URL
		{"fetch", "one", "two"}, // two URLs
		{"fetch", "-H", "no-colon", "https://x/"}, // malformed header
		{"fetch", "--nonsense", "https://x/"},     // unknown flag
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
	}

	for _, args := range [][]string{
		{"fetch", "--profile", "netscape_4", "https://x/"}, // unknown profile
		{"fetch", "https://127.0.0.1:1/"},                  // nothing listening
	} {
		if code, _, _ := exec(t, args...); code != 1 {
			t.Errorf("%v: exit code = %d, want 1", args, code)
		}
	}
}

func TestFetchCannotWriteTheOutputFile(t *testing.T) {
	server := startEcho(t)
	code, _, stderr := exec(t, "fetch", "--insecure",
		"-o", filepath.Join(t.TempDir(), "no-such-directory", "body"), server.URL()+"/api/all")
	if code == 0 {
		t.Errorf("exit code = 0, want non-zero; stderr = %q", stderr)
	}
}

func TestProfiles(t *testing.T) {
	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	shipped, err := profile.Get(tlsforge.DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if !strings.Contains(stdout, shipped.Name) {
		t.Errorf("the measured profile is not listed:\n%s", stdout)
	}
	if !strings.Contains(stdout, "chrome_133") {
		t.Errorf("the catalogue is not listed:\n%s", stdout)
	}
	if !strings.Contains(stdout, "tls-forge capture") {
		t.Errorf("the listing does not say how to measure your own")
	}
}

func TestDaemon(t *testing.T) {
	server := startEcho(t)
	original := daemonInput
	t.Cleanup(func() { daemonInput = original })
	daemonInput = strings.NewReader(
		`{"id":42,"url":"` + server.URL() + `/api/all"}` + "\n")

	code, stdout, stderr := exec(t, "daemon", "--insecure")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}

	var response struct {
		ID     uint64 `json:"id"`
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &response); err != nil {
		t.Fatalf("decoding: %v (output %q)", err, stdout)
	}
	if response.ID != 42 {
		t.Errorf("id = %d, want the one that was asked for", response.ID)
	}
	if response.Status != 200 || !strings.Contains(response.Body, "ja4") {
		t.Errorf("response = %+v", response)
	}
}

func TestDaemonRejectsAnUnknownProfile(t *testing.T) {
	code, _, _ := exec(t, "daemon", "--profile", "netscape_4")
	if code == 0 {
		t.Error("exit code = 0, want non-zero")
	}
}

// syncBuffer is a bytes.Buffer that can be read while it is being written.
//
// serve runs until its context ends, so the test has to watch its output from
// another goroutine — and bytes.Buffer is not safe for that.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServeStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve"}, out, out) }()

	// Wait for it to announce its URL, then stop it the way Ctrl-C would.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if strings.Contains(out.String(), "https://localhost:") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop when its context was cancelled")
	}
	if !strings.Contains(out.String(), "/api/all") {
		t.Errorf("serve did not describe its endpoints:\n%s", out.String())
	}
}

func TestServeRejectsAnUnusableAddress(t *testing.T) {
	code, _, _ := exec(t, "serve", "--addr", "256.256.256.256:0")
	if code == 0 {
		t.Error("exit code = 0, want non-zero")
	}
}

func TestPublicListenerWarning(t *testing.T) {
	for _, tc := range []struct {
		addr     string
		loopback bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"missing-port", false},
	} {
		if got := listenerIsLoopback(tc.addr); got != tc.loopback {
			t.Errorf("listenerIsLoopback(%q) = %v, want %v", tc.addr, got, tc.loopback)
		}
	}
	var buf bytes.Buffer
	out := newPrinter(&buf)
	warnPublicListener("serve", "127.0.0.1:8080", out)
	if buf.Len() != 0 {
		t.Errorf("loopback warning = %q", buf.String())
	}
	warnPublicListener("serve", "0.0.0.0:8080", out)
	if got := buf.String(); !strings.Contains(got, "WARNING") || !strings.Contains(got, "without authentication") {
		t.Errorf("public warning = %q", got)
	}
}

func TestCapture(t *testing.T) {
	code, stdout, stderr := exec(t, "capture", "--browser", browserStandIn(t), "--timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "JA4") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "--save") {
		t.Error("the summary does not say how to save a profile")
	}
}

func TestCaptureJSON(t *testing.T) {
	code, stdout, _ := exec(t, "capture", "--json", "--browser", browserStandIn(t), "--timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	// The banner line comes first, then the JSON.
	body := stdout[strings.Index(stdout, "{"):]
	var measured map[string]any
	if err := json.Unmarshal([]byte(body), &measured); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if measured["raw_client_hello"] == nil {
		t.Error("the capture carries no ClientHello")
	}
}

func TestCaptureSavesAProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "my-chrome.json")
	code, stdout, stderr := exec(t, "capture", "--browser", browserStandIn(t), "--timeout", "30s", "--save", path)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "wrote profile") {
		t.Errorf("stdout = %q", stdout)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the profile: %v", err)
	}
	saved, err := profile.Load(data)
	if err != nil {
		t.Fatalf("loading the profile: %v", err)
	}
	// The stand-in reports a Chrome 151 user-agent, so the name must follow it.
	if saved.Name != "chrome_151" {
		t.Errorf("name = %q, want chrome_151", saved.Name)
	}
	if len(saved.ClientHello) == 0 {
		t.Error("the profile carries no ClientHello")
	}
	if !strings.Contains(saved.Notes, "captured") {
		t.Errorf("notes = %q", saved.Notes)
	}
	// A saved profile must be usable, or the command produced a file that only
	// looks right.
	if _, err := saved.ClientProfile(); err != nil {
		t.Errorf("the saved profile cannot be used: %v", err)
	}
}

func TestCaptureSavesUnderAGivenName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named.json")
	code, _, _ := exec(t, "capture", "--browser", browserStandIn(t), "--timeout", "30s",
		"--save", path, "--name", "my_browser")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	data, _ := os.ReadFile(path)
	saved, err := profile.Load(data)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if saved.Name != "my_browser" {
		t.Errorf("name = %q", saved.Name)
	}
}

func TestCaptureErrors(t *testing.T) {
	if code, _, _ := exec(t, "capture", "--browser", "netscape"); code == 0 {
		t.Error("an unknown browser should fail")
	}
	// A save path that cannot be written.
	code, _, _ := exec(t, "capture", "--browser", browserStandIn(t), "--timeout", "30s",
		"--save", filepath.Join(t.TempDir(), "no-such-directory", "p.json"))
	if code == 0 {
		t.Error("an unwritable save path should fail")
	}
}

func TestCompareMatches(t *testing.T) {
	// The stand-in browser IS this library, so a comparison against it has to
	// come out clean and exit 0.
	code, stdout, stderr := exec(t, "compare", "--browser", browserStandIn(t), "--timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "indistinguishable") {
		t.Errorf("stdout = %q", stdout)
	}
	// The diff shows both sides, field by field, and every line agrees.
	for _, want := range []string{"--- browser", "+++ client", "  ja4", "  http2_akamai"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout has no %q line:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "\n- ") || strings.Contains(stdout, "\n+ ") {
		t.Errorf("a clean comparison printed a difference:\n%s", stdout)
	}
	// --color auto, and the test writes to a buffer rather than a terminal.
	if strings.Contains(stdout, "\x1b[") {
		t.Errorf("colour was written to something that is not a terminal:\n%q", stdout)
	}
}

func TestCompareDiffersExitsThree(t *testing.T) {
	// The exit code is the contract a CI job depends on: a browser update is
	// exactly when an impersonation stops being true, and it does so quietly.
	//
	// Three rather than one, because "it ran and disagreed" and "it could not
	// run" are different answers and something automating this has to tell them
	// apart. A scheduled check that read a browser which would not start as a
	// profile that had drifted would file an issue every week for a broken
	// runner.
	code, stdout, _ := exec(t, "compare", "--browser", browserStandIn(t),
		"--timeout", "30s", "--profile", "chrome_120")
	if code != 3 {
		t.Fatalf("exit code = %d, want 3\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "field(s) differ") {
		t.Errorf("stdout does not show the differences:\n%s", stdout)
	}
	// Both sides of a differing field, so the reader can see what changed
	// without running anything else.
	if !strings.Contains(stdout, "- header_order") || !strings.Contains(stdout, "+ header_order") {
		t.Errorf("a differing field is not shown as a pair:\n%s", stdout)
	}
	if !strings.Contains(stdout, "tls-forge capture") {
		t.Error("the report does not say how to fix it")
	}
}

func TestCompareColours(t *testing.T) {
	// --color always, so the assertion does not depend on what the test's stdout
	// happens to be attached to.
	code, stdout, _ := exec(t, "compare", "--browser", browserStandIn(t), "--timeout", "30s",
		"--color", "always", "--full")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, ansiGreen+"  ja4") {
		t.Errorf("a matching field is not green:\n%q", stdout)
	}
	// --full turns off the trimming, so no value is cut short. Measured from the
	// diff itself: the banner above it ends in an ellipsis of its own.
	if diff := stdout[strings.Index(stdout, "+++ client"):]; strings.Contains(diff, "…") {
		t.Errorf("--full still trimmed a value:\n%s", diff)
	}
}

func TestCompareRejectsAnUnknownColourMode(t *testing.T) {
	// Rejected before the browser starts: a typo should not cost two minutes of
	// waiting to report itself.
	code, _, stderr := exec(t, "compare", "--color", "sometimes")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "--color") || !strings.Contains(stderr, "sometimes") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestPaletteFor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")

	if p, err := paletteFor("always", io.Discard); err != nil || p.match != ansiGreen {
		t.Errorf("always: %+v, %v", p, err)
	}
	if p, err := paletteFor("never", io.Discard); err != nil || p.match != "" {
		t.Errorf("never: %+v, %v", p, err)
	}
	// Not a terminal, so auto stays quiet.
	if p, err := paletteFor("auto", io.Discard); err != nil || p.match != "" {
		t.Errorf("auto on a buffer: %+v, %v", p, err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	// A character device is what "someone is looking at this" is detected by,
	// and the writer is reached through the printer the commands write to.
	if p, err := paletteFor("auto", newPrinter(devNull)); err != nil || p.match != ansiGreen {
		t.Errorf("auto on a character device: %+v, %v", p, err)
	}
	// The one convention every tool that colourises agrees on.
	t.Setenv("NO_COLOR", "1")
	if p, err := paletteFor("auto", newPrinter(devNull)); err != nil || p.match != "" {
		t.Errorf("NO_COLOR was ignored: %+v, %v", p, err)
	}
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(io.Discard) {
		t.Error("a writer that is not a file is not a terminal")
	}

	regular, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if isTerminal(regular) {
		t.Error("a regular file is not a terminal")
	}

	// Stat on a closed descriptor fails, and a writer that cannot be asked is
	// not one to colourise.
	_ = regular.Close()
	if isTerminal(regular) {
		t.Error("a closed file is not a terminal")
	}
}

func TestCompareWithoutHTTP2(t *testing.T) {
	// A connection that came out as HTTP/1.1 has no HTTP/2 fingerprint on
	// either side. The TLS half still has to print.
	raw, err := os.ReadFile("../../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var buf bytes.Buffer
	result := &tlsforge.Comparison{
		Browser: &capture.Capture{RawClientHello: raw},
		Client:  &capture.Capture{RawClientHello: raw},
	}
	printComparison(newPrinter(&buf), result, palette{}, false)

	if !strings.Contains(buf.String(), "  ja4") {
		t.Errorf("no TLS section:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "HTTP/2") {
		t.Errorf("an HTTP/2 section was printed for a connection that had none:\n%s", buf.String())
	}
}

func TestComparePrintsHTTP1(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	http1 := &capture.HTTP1{
		HeaderNames: []string{"Host", "sec-ch-ua"},
		Headers: []capture.HeaderField{
			{Name: "host", Value: "localhost"}, {Name: "sec-ch-ua", Value: "browser"},
		},
	}
	var buf bytes.Buffer
	result := &tlsforge.Comparison{
		Browser: &capture.Capture{RawClientHello: raw, HTTP1: http1},
		Client:  &capture.Capture{RawClientHello: raw, HTTP1: http1},
	}
	printComparison(newPrinter(&buf), result, palette{}, true)
	if !strings.Contains(buf.String(), "HTTP/1.1") ||
		!strings.Contains(buf.String(), "http1_header_order") {
		t.Errorf("HTTP/1.1 section was not printed:\n%s", buf.String())
	}
}

func TestCompareCannotReReadItsCaptures(t *testing.T) {
	// printComparison parses the two hellos again to lay them out. Compare has
	// already parsed both, so this is unreachable in a real run, and it must not
	// print an empty diff that reads as agreement.
	var buf bytes.Buffer
	out := newPrinter(&buf)
	result := &tlsforge.Comparison{
		Browser: &capture.Capture{RawClientHello: []byte{0xff, 0xff}},
		Client:  &capture.Capture{RawClientHello: []byte{0xff, 0xff}},
	}
	printComparison(out, result, palette{}, false)
	if !strings.Contains(buf.String(), "could not be re-read") {
		t.Errorf("stdout = %q", buf.String())
	}
}

func TestCompareJSON(t *testing.T) {
	code, stdout, _ := exec(t, "compare", "--json", "--browser", browserStandIn(t), "--timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	body := stdout[strings.Index(stdout, "{"):]
	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if result["browser"] == nil || result["client"] == nil {
		t.Errorf("the JSON is missing a side: %v", result)
	}
}

func TestCompareErrors(t *testing.T) {
	if code, _, _ := exec(t, "compare", "--browser", "netscape"); code == 0 {
		t.Error("an unknown browser should fail")
	}
}

func TestProfileNameFor(t *testing.T) {
	for _, tc := range []struct{ userAgent, want string }{
		{"Mozilla/5.0 (Macintosh) Chrome/151.0.0.0 Safari/537.36", "chrome_151"},
		// Every Chromium browser says "Chrome/", so the ones with their own
		// token have to win or they all come out named chrome.
		{"Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0", "edge_151"},
		{"Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0", "opera_106"},
		{"Mozilla/5.0 (X11) Gecko/20100101 Firefox/135.0", "firefox_135"},
		{"Mozilla/5.0 (Macintosh) Version/18.3 Safari/605.1.15", "safari_18"},
		{"Chrome/", "chrome"},
		{"some unknown agent", "captured"},
		{"", "captured"},
	} {
		if got := profileNameFor(tc.userAgent); got != tc.want {
			t.Errorf("profileNameFor(%q) = %q, want %q", tc.userAgent, got, tc.want)
		}
	}
}

func TestHeaderFlag(t *testing.T) {
	var h headerFlag
	if err := h.Set("Referer: https://example.com"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := h.Set("X-Empty:"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := h.Set("no colon here"); err == nil {
		t.Error("a header without a colon should be rejected")
	}
	if got := tlsforge.Header(h).Get("referer"); got != "https://example.com" {
		t.Errorf("referer = %q", got)
	}
	if h.String() != "" {
		t.Errorf("String() = %q", h.String())
	}
}

// limitedWriter accepts a fixed number of bytes and then fails, so a command's
// "could not write the output" path can be reached.
type limitedWriter struct{ remaining int }

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("no space left on device")
	}
	if len(p) > w.remaining {
		w.remaining = 0
		return 0, errors.New("no space left on device")
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestMainEntryPoint(t *testing.T) {
	// The wiring between argv, the signal context and the exit code is the one
	// part of the program that run() does not cover.
	originalExit, originalArgs := exit, os.Args
	t.Cleanup(func() { exit, os.Args = originalExit, originalArgs })

	var code int
	exit = func(c int) { code = c }
	os.Args = []string{"tls-forge", "version"}
	main()

	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestHelpFlagOnACommandExitsTwo(t *testing.T) {
	// -h is not an error, but it is not a successful run either: nothing was
	// fetched. Every command has to agree about that.
	// Every command, so that a shorthand two flags both want is caught here
	// rather than by a panic in front of whoever ran it. batch was missing from
	// this list when --cookies and --concurrency both asked for -c.
	for _, name := range []string{"fetch", "batch", "capture", "compare", "profiles",
		"proxy", "serve", "daemon", "version"} {
		code, _, _ := exec(t, name, "-h")
		if code != 2 {
			t.Errorf("%s -h: exit code = %d, want 2", name, code)
		}
	}
}

func TestCommandsWithoutPositionalsRejectThem(t *testing.T) {
	for _, name := range []string{"capture", "compare", "profiles", "proxy", "serve", "daemon", "version"} {
		code, stdout, stderr := exec(t, name, "unexpected")
		if code != exitUsage {
			t.Errorf("%s: exit code = %d, want %d", name, code, exitUsage)
		}
		if !strings.Contains(stdout, "usage: tls-forge "+name) {
			t.Errorf("%s: stdout has no usage: %q", name, stdout)
		}
		if !strings.Contains(stderr, "takes no arguments") {
			t.Errorf("%s: stderr = %q", name, stderr)
		}
	}
}

func TestCommandsOnlyAdvertiseEffectiveCookieFlags(t *testing.T) {
	flags := []string{"--cookie name=value", "--cookies string", "--cookie-set string", "--save-cookies string"}
	tests := []struct {
		command string
		want    []bool
	}{
		{"fetch", []bool{true, true, true, true}},
		{"batch", []bool{true, true, true, true}},
		// Daemon can start from a warmed jar, but cannot save one because the
		// stream protocol does not retain the list of hosts it visited.
		{"daemon", []bool{true, true, true, false}},
		// Proxy forwards its caller's Cookie header and deliberately has no jar.
		{"proxy", []bool{false, false, false, false}},
	}

	for _, tc := range tests {
		code, stdout, stderr := exec(t, tc.command, "--help")
		if code != 2 {
			t.Fatalf("%s --help: exit code = %d, stderr = %q", tc.command, code, stderr)
		}
		for i, flag := range flags {
			if got := strings.Contains(stdout, flag); got != tc.want[i] {
				t.Errorf("%s help contains %q = %v, want %v", tc.command, flag, got, tc.want[i])
			}
		}
	}

	if code, _, _ := exec(t, "proxy", "--cookie", "session=abc"); code != 2 {
		t.Errorf("proxy accepted an ineffective cookie flag: exit code = %d, want 2", code)
	}
	if code, _, _ := exec(t, "daemon", "--save-cookies", "session.json"); code != 2 {
		t.Errorf("daemon accepted an unsupported save flag: exit code = %d, want 2", code)
	}
}

func TestFetchThroughAProxy(t *testing.T) {
	// Nothing is listening on the proxy port; what is being checked is that the
	// flag reaches the client rather than being silently ignored.
	code, _, stderr := exec(t, "fetch", "--insecure",
		"--proxy", "http://127.0.0.1:1", "https://example.com/")
	if code == 0 {
		t.Error("exit code = 0, want non-zero")
	}
	if stderr == "" {
		t.Error("no error was reported")
	}
}

func TestCompareCannotWriteItsJSON(t *testing.T) {
	// The banner goes out, then the disk fills.
	out := &limitedWriter{remaining: 64}
	code := run(context.Background(),
		[]string{"compare", "--json", "--browser", browserStandIn(t), "--timeout", "30s"},
		out, io.Discard)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestSaveProfileRejectsAResumedCapture(t *testing.T) {
	// A resumed hello carries pre_shared_key, so its JA4 is not the one a server
	// sees on first contact. Saving it would produce a profile that matches the
	// browser about half the time.
	raw, err := os.ReadFile("../../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	measured := &capture.Capture{RawClientHello: raw}
	measured.TLS.Resumed = true

	if _, _, err := saveProfile(filepath.Join(t.TempDir(), "p.json"), "chrome_151", measured); err == nil {
		t.Error("expected a resumed capture to be refused")
	}
}

func TestPrintCaptureShowsResumption(t *testing.T) {
	var out bytes.Buffer
	measured := &capture.Capture{}
	measured.TLS.JA4 = "t13d1517h2_x_y"
	measured.TLS.Resumed = true
	printCapture(newPrinter(&out), measured)

	if !strings.Contains(out.String(), "resumed") {
		t.Errorf("the summary hides that the capture was resumed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "first contact") {
		t.Error("the summary does not explain why resumption matters")
	}
}

func TestProfilesListsAnUnloadableNameWithTheCatalogue(t *testing.T) {
	// A registered profile that cannot produce a handshake still has a name, and
	// dropping it silently would hide exactly the thing worth reporting.
	if err := profile.Register(&profile.Profile{Name: "zz_unloadable"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "zz_unloadable") {
		t.Errorf("the profile was dropped from the listing:\n%s", stdout)
	}
}

// countingWriter fails on demand and records how many times it was asked to
// write, which is how the short-circuit below is proved rather than assumed.
type countingWriter struct {
	writes int
	fail   error
}

func (w *countingWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.fail != nil {
		return 0, w.fail
	}
	return len(b), nil
}

func TestPrinterRemembersTheFirstFailure(t *testing.T) {
	w := &countingWriter{}
	p := newPrinter(w)

	p.println("first")
	p.printf("%s\n", "second")
	if p.err != nil {
		t.Fatalf("err = %v on a healthy writer", p.err)
	}

	// The pipe closes — `tls-forge fetch … | head -1` is the everyday version of
	// this.
	w.fail = errors.New("broken pipe")
	p.println("third")
	if p.err == nil {
		t.Fatal("the failure was not remembered")
	}

	// Everything after it must short-circuit: a command that kept writing into a
	// dead pipe would burn through its output and still exit 0.
	before := w.writes
	p.println("fourth")
	p.printf("fifth\n")
	if w.writes != before {
		t.Errorf("wrote %d more times after the failure, want 0", w.writes-before)
	}
	if _, err := p.Write([]byte("sixth")); err == nil {
		t.Error("Write returned no error after the stream had failed")
	}
}

func TestAFailedStdoutFailsTheCommand(t *testing.T) {
	// The exit code has to reflect it: a command whose output never arrived did
	// not do what it was asked, whatever it returned.
	code := run(context.Background(), []string{"version"}, &countingWriter{fail: errors.New("no space")}, io.Discard)
	if code == 0 {
		t.Error("exit code = 0 for a command that could not write its output")
	}
}

func TestReleaseSignalHandsInterruptsBack(t *testing.T) {
	// The first interrupt asks for an orderly stop; any after it should kill
	// the process the way they would have if nothing were listening. That means
	// giving the signal back to the runtime once the first one has arrived.
	ctx, cancel := context.WithCancel(context.Background())
	released := make(chan struct{})
	releaseSignal(ctx, func() { close(released) })

	select {
	case <-released:
		t.Fatal("the signal was handed back before one arrived")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the signal was never handed back, so a second Ctrl-C would do nothing")
	}
}

func TestIsTerminalReader(t *testing.T) {
	if isTerminalReader(strings.NewReader("")) {
		t.Error("a string is not a terminal")
	}
	regular, err := os.Create(filepath.Join(t.TempDir(), "in"))
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	t.Cleanup(func() { _ = regular.Close() })
	if isTerminalReader(regular) {
		t.Error("a regular file is not a terminal")
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	if !isTerminalReader(devNull) {
		t.Error("a character device was not recognised")
	}
}

// keepProfilesIn points this machine's profile directory at a temporary one, so
// a test never reads or writes the real one.
func keepProfilesIn(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles")
	// The previous directory rather than DefaultDir(): cleanups run last-in
	// first-out, so this one runs before t.Setenv puts the environment back and
	// would otherwise pin the registry to a temporary directory that is about
	// to be deleted — which every later test in the package would then read.
	previous := profile.Default.Dir()
	t.Setenv("TLSFORGE_PROFILES", dir)
	profile.Default.SetDir(dir)
	t.Cleanup(func() { profile.Default.SetDir(previous) })
	return dir
}

func TestCaptureInstallsIntoThisMachinesDirectory(t *testing.T) {
	dir := keepProfilesIn(t)

	code, stdout, stderr := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--install")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	// Filed under `local`, not under the browser's version: there is one browser
	// on a machine, and measuring it again after an update should replace what
	// is there rather than leave two. Version names are for profiles that ship.
	written := filepath.Join(dir, localName, profile.HostPlatform()+".json")
	if _, err := os.Stat(written); err != nil {
		t.Fatalf("nothing was kept: %v", err)
	}
	if !strings.Contains(stdout, written) {
		t.Errorf("stdout does not say where it went:\n%s", stdout)
	}
	// And says how to use it, since the whole point is that a name now works.
	if !strings.Contains(stdout, "--profile "+localName+"_"+profile.HostPlatform()) {
		t.Errorf("stdout does not say how to use it:\n%s", stdout)
	}

	// The name resolves, and to what was kept rather than to what shipped.
	p, err := profile.Get(localName + "_" + profile.HostPlatform())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(p.Notes, "captured") {
		t.Errorf("the shipped profile answered instead: %q", p.Notes)
	}
}

func TestCaptureSaveIntoADirectory(t *testing.T) {
	// A directory gets a version/platform layout, unlike --install, which files
	// under `local`. This is the shape the capture workflow relies on to produce
	// chrome_152/macos.json for committing.
	dir := t.TempDir()
	code, stdout, _ := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--save", dir)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "chrome_151", profile.HostPlatform()+".json")); err != nil {
		t.Errorf("nothing was written: %v", err)
	}
}

func TestCaptureWithNowhereToKeepProfiles(t *testing.T) {
	// A container with no home and no override has nowhere to install to, and
	// should say so rather than write somewhere surprising.
	t.Setenv("TLSFORGE_PROFILES", "")
	if runtime.GOOS == "windows" {
		t.Skip("HOME is not the mechanism on Windows")
	}
	// XDG_CONFIG_HOME as well as HOME: on Linux it is the first thing
	// os.UserConfigDir reads, and GitHub's runners set it, so clearing HOME
	// alone leaves a home to install into and this test asserting nothing.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	code, _, stderr := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--install")
	if code == 0 {
		t.Fatal("exit code = 0")
	}
	if !strings.Contains(stderr, "TLSFORGE_PROFILES") {
		t.Errorf("stderr does not say what to set: %q", stderr)
	}
}

func TestCaptureSaysHowToKeepAProfile(t *testing.T) {
	code, stdout, _ := exec(t, "capture", "--browser", browserStandIn(t), "--timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "--install") {
		t.Errorf("a capture that kept nothing does not say how to keep one:\n%s", stdout)
	}
}

func TestProfilesMarksTheOnesKeptHere(t *testing.T) {
	dir := keepProfilesIn(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shipped, err := profile.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	shipped.Name = "my_browser"
	data, err := shipped.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "my_browser.json"), data, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "* my_browser") {
		t.Errorf("the profile kept here is not marked:\n%s", stdout)
	}
	// And the listing says where that is, or nobody can find it.
	if !strings.Contains(stdout, dir) {
		t.Errorf("the listing does not name the directory:\n%s", stdout)
	}
}

func TestCaptureCannotMakeTheProfileDirectory(t *testing.T) {
	// A file where the directory should be. Reported rather than left to fail
	// later with a stranger message about a path.
	blocked := filepath.Join(t.TempDir(), "profiles")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	t.Setenv("TLSFORGE_PROFILES", blocked)

	code, _, stderr := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--install")
	if code == 0 {
		t.Fatal("exit code = 0")
	}
	if !strings.Contains(stderr, "capture:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCaptureCannotMakeTheVersionDirectory(t *testing.T) {
	// A file where the version's directory should be. Reported rather than left
	// to fail later with a stranger message about a path.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "chrome_151"), nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	code, _, stderr := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--save", dir)
	if code == 0 {
		t.Fatal("exit code = 0")
	}
	if stderr == "" {
		t.Error("nothing was reported")
	}
}

func TestProfilesMarksAPlatformKeptHere(t *testing.T) {
	// A machine that measured one platform still resolves the shipped profile
	// for the others, and the listing has to show both with only one starred.
	dir := keepProfilesIn(t)
	version := filepath.Join(dir, "chrome_151")
	if err := os.MkdirAll(version, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shipped, err := profile.Get("chrome_151_linux")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	shipped.Name = "chrome_151_" + profile.HostPlatform()
	data, err := shipped.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(filepath.Join(version, profile.HostPlatform()+".json"), data, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	// Every line is a name that can be copied into --profile.
	for _, want := range []string{"chrome_151", "chrome_151_linux", "chrome_151_macos"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the listing has no %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stdout, "*   chrome_151_"+profile.HostPlatform()) {
		t.Errorf("the platform kept here is not marked:\n%s", stdout)
	}
}

func TestProfilesListsAProfileThatWillNotLoadWithTheCatalogue(t *testing.T) {
	// A profile that exists but will not load is exactly the thing a user needs
	// to be told about, so it is listed rather than silently dropped.
	dir := keepProfilesIn(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "broken") {
		t.Errorf("a profile that will not load vanished from the listing:\n%s", stdout)
	}
}

func TestProfilesIsANameListRatherThanUserAgents(t *testing.T) {
	keepProfilesIn(t)
	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	// Names, not the user-agents behind them: the listing answers "what is
	// there and which one do I get", and a browser's full user-agent on every
	// row buries both.
	if strings.Contains(stdout, "Mozilla/5.0") {
		t.Errorf("the listing carries user-agents:\n%s", stdout)
	}

	// The one a run lands on when nobody says, marked once rather than on every
	// name that reaches it.
	fallback, err := profile.Get(tlsforge.DefaultProfile)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	var marked []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasSuffix(line, "<") {
			marked = append(marked, strings.TrimSpace(strings.TrimSuffix(line, "<")))
		}
	}
	if len(marked) != 1 {
		t.Fatalf("%d rows are marked as the default: %v", len(marked), marked)
	}
	if strings.TrimPrefix(marked[0], "* ") != fallback.Name {
		t.Errorf("the default is marked on %q, want %q", marked[0], fallback.Name)
	}

	// And no row trails a space, which is what an arrow column does when it is
	// padded onto every line.
	for _, line := range strings.Split(stdout, "\n") {
		if line != strings.TrimRight(line, " ") && !strings.Contains(line, "  ") {
			t.Errorf("a row trails whitespace: %q", line)
		}
	}
}

func TestProfilesMarksAFlatProfileAsTheDefault(t *testing.T) {
	// A profile with no platforms of its own carries the mark on its own line,
	// since there is no more specific name to put it on.
	dir := keepProfilesIn(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shipped, err := profile.Get("chrome_151_linux")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Named so that "chrome" resolves to it: a higher version than anything
	// shipped, laid out flat.
	shipped.Name = "chrome_999"
	data, err := shipped.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chrome_999.json"), data, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	code, stdout, _ := exec(t, "profiles")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "* chrome_999") {
		t.Errorf("the flat profile is not marked as kept here:\n%s", stdout)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "chrome_999") && strings.HasSuffix(line, "<") {
			return
		}
	}
	t.Errorf("the flat profile is not marked as the default:\n%s", stdout)
}

func TestCaptureAndComparePassBrowserFlagsThrough(t *testing.T) {
	// The CLI end of the same plumbing: a flag that stops at the flag set is a
	// flag that does nothing, and the failure it was added to prevent — Chrome
	// starting on a runner and never loading the page — looks identical either
	// way.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	for _, command := range []string{"capture", "compare"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			recorded := filepath.Join(dir, "args")
			recorder := filepath.Join(dir, "recorder")
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + recorded + "\n"
			if err := os.WriteFile(recorder, []byte(script), 0o755); err != nil {
				t.Fatalf("writing the recorder: %v", err)
			}

			// It records and exits, so the command ends at its deadline. What is
			// asserted is the launch, not what came back from it.
			exec(t, command, "--browser", recorder, "--timeout", "2s",
				"--browser-arg", "--no-sandbox")

			data, err := os.ReadFile(recorded)
			if err != nil {
				t.Fatalf("the browser was never launched: %v", err)
			}
			if !strings.Contains(string(data), "--no-sandbox") {
				t.Errorf("the flag did not reach the browser:\n%s", data)
			}
		})
	}
}

func TestCompareTellsTroubleFromDisagreement(t *testing.T) {
	// The distinction the scheduled check is built on: only one of these means
	// "capture a new profile".
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"a browser that is not there", []string{"compare", "--browser", "/no/such/browser"}, 1},
		{"a flag that is not a flag", []string{"compare", "--nonsense"}, 2},
		{"a profile that disagrees", []string{"compare", "--browser", browserStandIn(t),
			"--timeout", "30s", "--profile", "chrome_120"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := exec(t, tc.args...); code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}
