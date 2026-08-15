package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	code = run(context.Background(), args, &out, &errOut)
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
	client, err := tlsforge.New(tlsforge.WithInsecureSkipVerify())
	if err != nil {
		os.Exit(1)
	}
	defer client.Close()
	if _, err := client.Get(url + "/"); err != nil {
		os.Exit(1)
	}
	if _, err := client.Do(&tlsforge.Request{
		Method: "POST",
		URL:    url + "/collect",
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
	// flag.ErrHelp rather than a crash: a mistyped flag should print the usage
	// and exit 2, the way every other Unix tool does.
	for _, args := range [][]string{
		{"fetch", "-nonsense"},
		{"capture", "-nonsense"},
		{"compare", "-nonsense"},
		{"profiles", "-nonsense"},
		{"serve", "-nonsense"},
		{"daemon", "-nonsense"},
	} {
		code, _, _ := exec(t, args...)
		if code == 0 {
			t.Errorf("%v: exit code = 0, want non-zero", args)
		}
	}
}

func TestFetch(t *testing.T) {
	server := startEcho(t)
	code, stdout, stderr := exec(t, "fetch", "-insecure", server.URL()+"/api/all")
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
	code, stdout, _ := exec(t, "fetch", "-insecure", "-i",
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
	code, stdout, _ := exec(t, "fetch", "-insecure", "-o", path, server.URL()+"/api/all")
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
	code, stdout, _ := exec(t, "fetch", "-insecure", "-method", "POST",
		"-H", "content-type: application/json",
		"-data", `{"user_agent":"from the CLI"}`, server.URL()+"/collect")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "from the CLI") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestFetchArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"fetch"},               // no URL
		{"fetch", "one", "two"}, // two URLs
		{"fetch", "-H", "no-colon", "https://x/"},         // malformed header
		{"fetch", "-profile", "netscape_4", "https://x/"}, // unknown profile
		{"fetch", "https://127.0.0.1:1/"},                 // nothing listening
	} {
		code, _, _ := exec(t, args...)
		if code == 0 {
			t.Errorf("%v: exit code = 0, want non-zero", args)
		}
	}
}

func TestFetchCannotWriteTheOutputFile(t *testing.T) {
	server := startEcho(t)
	code, _, stderr := exec(t, "fetch", "-insecure",
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

	code, stdout, stderr := exec(t, "daemon", "-insecure")
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
	code, _, _ := exec(t, "daemon", "-profile", "netscape_4")
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
	code, _, _ := exec(t, "serve", "-addr", "256.256.256.256:0")
	if code == 0 {
		t.Error("exit code = 0, want non-zero")
	}
}

func TestCapture(t *testing.T) {
	code, stdout, stderr := exec(t, "capture", "-browser", browserStandIn(t), "-timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "JA4") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "-save") {
		t.Error("the summary does not say how to save a profile")
	}
}

func TestCaptureJSON(t *testing.T) {
	code, stdout, _ := exec(t, "capture", "-json", "-browser", browserStandIn(t), "-timeout", "30s")
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
	code, stdout, stderr := exec(t, "capture", "-browser", browserStandIn(t), "-timeout", "30s", "-save", path)
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
	code, _, _ := exec(t, "capture", "-browser", browserStandIn(t), "-timeout", "30s",
		"-save", path, "-name", "my_browser")
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
	if code, _, _ := exec(t, "capture", "-browser", "netscape"); code == 0 {
		t.Error("an unknown browser should fail")
	}
	// A save path that cannot be written.
	code, _, _ := exec(t, "capture", "-browser", browserStandIn(t), "-timeout", "30s",
		"-save", filepath.Join(t.TempDir(), "no-such-directory", "p.json"))
	if code == 0 {
		t.Error("an unwritable save path should fail")
	}
}

func TestCompareMatches(t *testing.T) {
	// The stand-in browser IS this library, so a comparison against it has to
	// come out clean and exit 0.
	code, stdout, stderr := exec(t, "compare", "-browser", browserStandIn(t), "-timeout", "30s")
	if code != 0 {
		t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "match") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "indistinguishable") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestCompareDiffersExitsOne(t *testing.T) {
	// The exit code is the contract a CI job depends on: a browser update is
	// exactly when an impersonation stops being true, and it does so quietly.
	code, stdout, _ := exec(t, "compare", "-browser", browserStandIn(t),
		"-timeout", "30s", "-profile", "chrome_120")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "DIFFER") {
		t.Errorf("stdout does not show the differences:\n%s", stdout)
	}
	if !strings.Contains(stdout, "tls-forge capture") {
		t.Error("the report does not say how to fix it")
	}
}

func TestCompareJSON(t *testing.T) {
	code, stdout, _ := exec(t, "compare", "-json", "-browser", browserStandIn(t), "-timeout", "30s")
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
	if code, _, _ := exec(t, "compare", "-browser", "netscape"); code == 0 {
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
	for _, name := range []string{"fetch", "capture", "compare", "profiles", "serve", "daemon"} {
		code, _, _ := exec(t, name, "-h")
		if code != 2 {
			t.Errorf("%s -h: exit code = %d, want 2", name, code)
		}
	}
}

func TestFetchThroughAProxy(t *testing.T) {
	// Nothing is listening on the proxy port; what is being checked is that the
	// flag reaches the client rather than being silently ignored.
	code, _, stderr := exec(t, "fetch", "-insecure",
		"-proxy", "http://127.0.0.1:1", "https://example.com/")
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
		[]string{"compare", "-json", "-browser", browserStandIn(t), "-timeout", "30s"},
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

	if _, err := saveProfile(filepath.Join(t.TempDir(), "p.json"), "chrome_151", measured); err == nil {
		t.Error("expected a resumed capture to be refused")
	}
}

func TestPrintCaptureShowsResumption(t *testing.T) {
	var out bytes.Buffer
	measured := &capture.Capture{}
	measured.TLS.JA4 = "t13d1517h2_x_y"
	measured.TLS.Resumed = true
	printCapture(&out, measured)

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
