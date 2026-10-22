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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v5/internal/harness"
)

// client asks the bench's server for a page: every name it serves is the
// loopback address, and its certificate is taken on trust.
var client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
	DialContext:       dial,
	DialTLSContext:    dialTLS,
	ForceAttemptHTTP2: true,
}}

// readsLate is how long each read of a connection the fake makes waits
// first: none, unless a test makes what the server sends come late.
var readsLate time.Duration

// dial reaches what the bench serves at addr on the loopback address, its
// reads late by readsLate.
func dial(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, _ := net.SplitHostPort(addr)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
	if err != nil || readsLate == 0 {
		return conn, err
	}
	return lateReads{conn, readsLate}, nil
}

// lateReads is a connection whose every read waits late first.
type lateReads struct {
	net.Conn
	late time.Duration
}

func (c lateReads) Read(p []byte) (int, error) {
	time.Sleep(c.late)
	return c.Conn.Read(p)
}

// dialTLS reaches what the bench serves at addr over TLS, its certificate
// taken on trust, and holds what an HTTP/2 server sends until the fake has
// written its first request (heldReads).
func dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	held := &heldReads{Conn: raw}
	host, _, _ := net.SplitHostPort(addr)
	conn := tls.Client(held, &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"},
		InsecureSkipVerify: true}) //nolint:gosec // the bench's own certificate
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		held.hold()
	}
	return conn, nil
}

// heldReads is a connection under the fake's TLS that, once held, reads
// nothing until the client has written twice more: an HTTP/2 client's
// preface and SETTINGS, then its first request's HEADERS. What the server
// sent, its SETTINGS among it, is then read after the client wrote its first
// header block, however soon it came. Go's HTTP/2 client starts a header
// block with a size update once it has read the server's SETTINGS, which on
// loopback come about as it writes its first request: asked at once, the
// update went in the first block or the second, and a fixture the fake wrote
// was not always what it wrote the next time (2026-10-20, under load). A
// server that holds what it sends until a client's first header block, as
// the bench's table servers do, sends it after, as before; waiting for the
// SETTINGS instead, a PING answered after them, would wait for such a server
// forever.
type heldReads struct {
	net.Conn
	mu     sync.Mutex
	held   chan struct{}
	writes int
}

// holds counts the connections held, for a test to see that they are.
var holds atomic.Int64

// hold makes reads wait for the next two writes.
func (c *heldReads) hold() {
	holds.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.held, c.writes = make(chan struct{}), 0
}

// letGo lets the reads held go, c.mu held.
func (c *heldReads) letGo() {
	if c.held != nil {
		close(c.held)
		c.held = nil
	}
}

func (c *heldReads) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writes++; c.writes == 2 {
		c.letGo()
	}
	return n, err
}

func (c *heldReads) Read(p []byte) (int, error) {
	c.mu.Lock()
	held := c.held
	c.mu.Unlock()
	if held != nil {
		<-held
	}
	return c.Conn.Read(p)
}

// Close lets a read held for a request never written end with it.
func (c *heldReads) Close() error {
	c.mu.Lock()
	c.letGo()
	c.mu.Unlock()
	return c.Conn.Close()
}

// fake is a browser that asks for the page it opens, and dumps each page as
// dump says; it fails what fail says. A page that goes on to a run page, as a
// scenario of connections starts at one, it follows there, and a run page,
// followed or opened, says it is done, on the connection it was asked on.
type fake struct {
	dump      func(body []byte) string
	failOpen  bool
	failDumps bool
	// version, when there is one, is said in a sec-ch-ua of every page it
	// opens, as a build of a browser says its own.
	version string
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
			req, _ := http.NewRequest(http.MethodGet, page, nil)
			if f.version != "" {
				req.Header.Set("Sec-Ch-Ua", `"Fake";v="`+f.version+`"`)
			}
			if res, err := client.Do(req); err == nil {
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

// opening has the command measure b, which says it is said, and keeps the
// arguments the command gave it.
func opening(t *testing.T, b harness.Browser, said string) *[]string {
	t.Helper()
	oldOpen, oldMachine, oldToday := open, machine, today
	given := new([]string)
	open = func(_ context.Context, _ string, args []string) (harness.Browser, string, error) {
		*given = args
		return b, said, nil
	}
	machine = func() string { return "Testing 1 (arm64)" }
	today = func() string { return "2026-10-17" }
	t.Cleanup(func() { open, machine, today = oldOpen, oldMachine, oldToday })
	return given
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
		"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", "", "--only", "nav-direct")
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
		"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", "", "--only", "nav-direct", "--check")
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A browser that decodes otherwise, and asks for what the fixture does
	// not have, is not.
	b.dump = func([]byte) string { return "<title>windows-1252|b</title>" }
	code, stdout, stderr = measured(t, "--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", decoding,
		"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", "", "--only", "nav-direct,redir-nav-direct-301", "--check")
	if code != 3 || !strings.Contains(stdout, "redir-nav-direct-301 was measured, and the fixture has no such scenario\n") ||
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
		"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", "", "--only", "conn-fetch")
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
		"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", "", "--only", "conn-fetch", "--check")
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
	open = func(context.Context, string, []string) (harness.Browser, string, error) {
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
		{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""},
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
	b, said, err := open(context.Background(), path, []string{"--no-sandbox"})
	if err != nil || said != "Google Chrome 155.0.8059.80" ||
		!reflect.DeepEqual(b, harness.Chrome{Path: path, Args: []string{"--no-sandbox"}}) {
		t.Errorf("open: %v, %q, %v", b, said, err)
	}
	failing := write("failing", "exit 3\n")
	if _, _, err := open(context.Background(), failing, nil); err == nil || !strings.Contains(err.Error(), "asking "+failing+" its version") {
		t.Errorf("open of a browser that will not say: %v", err)
	}
	if _, _, err := open(context.Background(), filepath.Join(dir, "none"), nil); err == nil {
		t.Error("open of no browser")
	}
}

func TestTheBrowserIsGivenTheArgumentsForTheMachine(t *testing.T) {
	// Each --browser-arg, in order, after the bench's own, and the fixture
	// says how the browser was run; none, none.
	text := "x"
	for _, tc := range []struct {
		args  []string
		given []string
		how   string
	}{
		{nil, nil, "--headless=new --lang=en-US"},
		{[]string{"--browser-arg=--no-sandbox", "--browser-arg", "--x=a b"}, []string{"--no-sandbox", "--x=a b"},
			"--headless=new --lang=en-US --no-sandbox --x=a b"},
	} {
		requests, _ := fixtures(t, map[string]harness.MeasuredScenario{}, []harness.DecodingCase{{Name: "a", ContentType: &text}})
		given := opening(t, &fake{}, "Fake Chrome 1.2.3.4")
		args := append([]string{"--browser", "chrome", "--requests", requests, "--connections", "", "--decoding", "",
			"--hpack", "", "--records", "", "--alps", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "",
			"--only", "nav-direct"}, tc.args...)
		if code, _, stderr := measured(t, args...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		wrote, err := harness.LoadRequests(requests)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(*given, tc.given) || wrote.Browser != "Fake Chrome 1.2.3.4, "+tc.how+", Testing 1 (arm64)" {
			t.Errorf("%q: given %q, the fixture says %q", tc.args, *given, wrote.Browser)
		}
	}
	var some arguments
	if some.String() != "" || some.Set("--a") != nil || some.Set("--b") != nil || some.String() != "--a --b" {
		t.Errorf("arguments: %q", some)
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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
	if code != 3 || stdout != "hpack-fetch: connection 1: 2 requests, want 1\n"+
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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

// recordsFile is a fixture of records holding scenarios, in a directory of
// its own.
func recordsFile(t *testing.T, scenarios map[string]harness.RecordsScenario) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.json")
	if err := (&harness.RecordsFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheRecordsAndThenHoldsTheBrowserToThem(t *testing.T) {
	records := recordsFile(t, map[string]harness.RecordsScenario{"kept": {Note: "kept"}})
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--false-start", "", "--alps", ""}
	code, _, stderr := measured(t, append(none, "--records", records, "--only", "h1-records-header")...)
	if code != 0 || !strings.Contains(stderr, "h1 h1-records-header: 2 requests") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadRecords(records)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	header := wrote.Scenarios["h1-records-header"]
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Scenarios) != 2 || wrote.Scenarios["kept"].Note != "kept" || len(header.Requests) != 2 ||
		header.Requests[1].URL != "https://www.example.com/done/h1-records-header" {
		t.Errorf("wrote %+v", wrote)
	}
	// Measured again, the browser is what it says.
	code, stdout, stderr := measured(t, append(none, "--records", records, "--only", "h1-records-header", "--check")...)
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that says otherwise is not, nor one without the scenario.
	header.Requests = header.Requests[:1]
	records = recordsFile(t, map[string]harness.RecordsScenario{"h1-records-header": header})
	code, stdout, stderr = measured(t, append(none, "--records", records, "--only", "h1-records-header,h1-records-post-100", "--check")...)
	if code != 3 || stdout != "h1-records-header: 2 requests, want 1\n"+
		"h1-records-post-100 was measured, and the fixture has no such scenario\n" ||
		!strings.HasSuffix(stderr, "measure: 2 differences from the fixtures\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that is not one's scenarios are made.
	empty := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(empty, []byte("{}"), 0o644)
	if code, _, stderr := measured(t, append(none, "--records", empty, "--only", "h1-records-header")...); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if wrote, err := harness.LoadRecords(empty); err != nil || len(wrote.Scenarios) != 1 {
		t.Errorf("made %+v, %v", wrote, err)
	}
}

func TestTheCommandSaysWhyItMeasuredNoRecords(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--false-start", "", "--alps", ""}
	missing := filepath.Join(t.TempDir(), "none.json")
	opening(t, &fake{}, "Fake")
	if code, _, stderr := measured(t, append(none, "--records", missing)...); code != 1 || !strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	opening(t, &fake{failOpen: true}, "Fake")
	records := recordsFile(t, map[string]harness.RecordsScenario{})
	if code, _, stderr := measured(t, append(none, "--records", records, "--only", "h1-records-header")...); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("a browser that does not open: exit %d, %s", code, stderr)
	}
	if os.Geteuid() != 0 {
		opening(t, &fake{}, "Fake")
		if err := os.Chmod(records, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append(none, "--records", records, "--only", "h1-records-header")...); code != 1 ||
			!strings.Contains(stderr, "permission denied") {
			t.Errorf("a fixture it may not write: exit %d, %s", code, stderr)
		}
	}
}

// alpsFile is a fixture of ALPS holding scenarios, in a directory of its own.
func alpsFile(t *testing.T, scenarios map[string]harness.ALPSScenario) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alps.json")
	if err := (&harness.ALPSFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheALPSAndThenHoldsTheBrowserToIt(t *testing.T) {
	alps := alpsFile(t, map[string]harness.ALPSScenario{"kept": {Note: "kept"}})
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--false-start", "", "--records", ""}
	code, _, stderr := measured(t, append(none, "--alps", alps, "--only", "alps-none")...)
	if code != 0 || !strings.Contains(stderr, "alps alps-none: 1 connections") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadALPS(alps)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	got := wrote.Scenarios["alps-none"]
	if wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" ||
		wrote.How != "how" || len(wrote.Scenarios) != 2 || wrote.Scenarios["kept"].Note != "kept" || len(got.Handshakes) != 1 ||
		len(got.Connections) != 1 || got.Connections[0][1].URL != "https://www.example.com/done/alps-none" {
		t.Errorf("wrote %+v", wrote)
	}
	// Measured again, the browser is what it says.
	code, stdout, stderr := measured(t, append(none, "--alps", alps, "--only", "alps-none", "--check")...)
	if code != 0 || stdout != "the browser is what the fixtures say\n" {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that says otherwise is not, nor one without the scenario.
	got.Handshakes = nil
	alps = alpsFile(t, map[string]harness.ALPSScenario{"alps-none": got})
	code, stdout, stderr = measured(t, append(none, "--alps", alps, "--only", "alps-none,alps-empty", "--check")...)
	if code != 3 || stdout != "alps-none: 1 handshakes, want 0\n"+
		"alps-empty was measured, and the fixture has no such scenario\n" ||
		!strings.HasSuffix(stderr, "measure: 2 differences from the fixtures\n") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// A fixture that is not one's scenarios are made.
	empty := filepath.Join(t.TempDir(), "empty.json")
	_ = os.WriteFile(empty, []byte("{}"), 0o644)
	if code, _, stderr := measured(t, append(none, "--alps", empty, "--only", "alps-none")...); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if wrote, err := harness.LoadALPS(empty); err != nil || len(wrote.Scenarios) != 1 {
		t.Errorf("made %+v, %v", wrote, err)
	}
}

func TestTheCommandSaysWhyItMeasuredNoALPS(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--false-start", "", "--records", ""}
	missing := filepath.Join(t.TempDir(), "none.json")
	opening(t, &fake{}, "Fake")
	if code, _, stderr := measured(t, append(none, "--alps", missing)...); code != 1 || !strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	opening(t, &fake{failOpen: true}, "Fake")
	alps := alpsFile(t, map[string]harness.ALPSScenario{})
	if code, _, stderr := measured(t, append(none, "--alps", alps, "--only", "alps-none")...); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("a browser that does not open: exit %d, %s", code, stderr)
	}
	if os.Geteuid() != 0 {
		opening(t, &fake{}, "Fake")
		if err := os.Chmod(alps, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if code, _, stderr := measured(t, append(none, "--alps", alps, "--only", "alps-none")...); code != 1 ||
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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
	// scenario: one more of the connection's (a stream's last missing is a
	// slow reader's, and no difference).
	small.Updates = append(small.Updates, harness.FlowUpdate{Window: "connection", Increment: 1, Part: 9})
	flow = flows(t, map[string]harness.FlowScenario{"flow-small": small})
	code, stdout, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small,flow-half", "--check")...)
	if code != 3 || !strings.Contains(stdout, "flow-small: ") ||
		!strings.Contains(stdout, "flow-half was measured, and the fixture has no such scenario\n") ||
		!strings.Contains(stderr, "differences from the fixtures") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// Held to the whole fixture, every scenario is measured.
	flow = flows(t, map[string]harness.FlowScenario{})
	if code, stdout, stderr := measured(t, append(none, "--flow", flow, "--only", "flow-small", "--check")...); code != 3 ||
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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
	if code != 3 || stdout != "url-host-upper over h1: https www.example.com/p/x (sni \"\"), want blocked\n" ||
		!strings.Contains(stderr, "1 differences from the fixtures") {
		t.Errorf("exit %d: %s%s", code, stdout, stderr)
	}
	// Held to the whole fixture, every case of it is measured.
	if code, stdout, stderr := measured(t, append(none, "--urls", urls, "--check")...); code != 3 ||
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
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
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

// hellosMeasured has the command's hellos measured as got and err say, with no
// browser.
func hellosMeasured(t *testing.T, got [][]string, err error) {
	t.Helper()
	old := helloOrders
	helloOrders = func(_ context.Context, _ harness.Browser, progress io.Writer) ([][]string, error) {
		_, _ = io.WriteString(progress, "hellos measured\n")
		return got, err
	}
	t.Cleanup(func() { helloOrders = old })
}

func helloFixture(t *testing.T, launches [][]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hellos.json")
	if err := (&harness.HellosFixture{Browser: "old", How: "how", Launches: launches}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesTheHellosAndThenHoldsTheBrowserToThem(t *testing.T) {
	// Every order of three extensions between two GREASE as often: as
	// uniform as can be; the same order every time: as far from it.
	var every []string
	for _, order := range []string{"1,2,3", "1,3,2", "2,1,3", "2,3,1", "3,1,2", "3,2,1"} {
		every = append(every, "2570,"+order+",6682")
	}
	same := slices.Repeat([]string{"2570,1,2,3,6682"}, 100)
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--records", "", "--alps", "", "--false-start", ""}
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	hellosMeasured(t, [][]string{every, every}, nil)
	hellos := helloFixture(t, nil)
	if code, _, stderr := measured(t, append(none, "--hellos", hellos)...); code != 0 || !strings.Contains(stderr, "hellos measured") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wrote, err := harness.LoadHellos(hellos)
	if err != nil || wrote.Browser != "Fake Chrome 1.2.3.4, --headless=new --lang=en-US, Testing 1 (arm64)" ||
		wrote.Measured != "2026-10-17" || wrote.How != "how" || len(wrote.Launches) != 2 || !slices.Equal(wrote.Launches[1], every) {
		t.Errorf("wrote %+v, %v", wrote, err)
	}
	// Held to the rule against the fixture's first order.
	if code, stdout, stderr := measured(t, append(none, "--hellos", hellos, "--check")...); code != 0 ||
		stdout != "the browser is what the fixtures say\n" {
		t.Errorf("uniform: exit %d: %s%s", code, stdout, stderr)
	}
	hellosMeasured(t, [][]string{every, same}, nil)
	code, stdout, stderr := measured(t, append(none, "--hellos", hellos, "--check")...)
	if code != 3 || !strings.HasPrefix(stdout, "hellos, launch 2: 100 orders keep 3.000 extensions where the reference has them") ||
		strings.Count(stdout, "hellos, launch 2: ") != 3 || strings.Contains(stdout, "launch 1") ||
		!strings.Contains(stderr, "3 differences from the fixtures") {
		t.Errorf("the same order: exit %d: %s%s", code, stdout, stderr)
	}
}

func TestTheCommandSaysWhyItMeasuredNoHellos(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--records", "", "--alps", "", "--false-start", ""}
	opening(t, &fake{}, "Fake")
	good := [][]string{{"2570,1,2,6682"}}
	for _, tc := range []struct {
		name     string
		fixture  [][]string
		measured [][]string
		err      error
		says     string
	}{
		{"a fixture with no hello", nil, good, nil, "holds no ClientHello to hold the browser against"},
		{"a fixture with an empty launch", [][]string{{}}, good, nil, "holds no ClientHello to hold the browser against"},
		{"a fixture's order unread", [][]string{{"x"}}, good, nil, `harness: an order of extensions: "x"`},
		{"a measured order unread", good, [][]string{{"y"}}, nil, `harness: an order of extensions: "y"`},
		{"a measured order of other extensions", good, [][]string{{"2570,1,4,6682"}}, nil,
			"harness: order 1 has 4, which the reference has not, or twice"},
		{"a measurement that failed", good, nil, errors.New("harness: hellos, launch 1: gone"), "harness: hellos, launch 1: gone"},
	} {
		hellosMeasured(t, tc.measured, tc.err)
		if code, _, stderr := measured(t, append(none, "--hellos", helloFixture(t, tc.fixture), "--check")...); code != 1 ||
			!strings.Contains(stderr, tc.says) {
			t.Errorf("%s: exit %d, %s", tc.name, code, stderr)
		}
	}
	hellosMeasured(t, good, nil)
	if code, _, stderr := measured(t, append(none, "--hellos", filepath.Join(t.TempDir(), "none.json"))...); code != 1 ||
		!strings.Contains(stderr, "none.json") {
		t.Errorf("no fixture: exit %d, %s", code, stderr)
	}
	hellosMeasured(t, nil, errors.New("harness: hellos, launch 1: gone"))
	if code, _, stderr := measured(t, append(none, "--hellos", helloFixture(t, nil))...); code != 1 ||
		!strings.Contains(stderr, "harness: hellos, launch 1: gone") {
		t.Errorf("a measurement that failed, written: exit %d, %s", code, stderr)
	}
}

func TestTheCommandMeasuresTheHellosItIsNotToldOtherwise(t *testing.T) {
	// The seam is the harness's own measurement until a test says otherwise.
	if reflect.ValueOf(helloOrders).Pointer() != reflect.ValueOf(harness.MeasureHellos).Pointer() {
		t.Error("the hellos are measured otherwise")
	}
}

func falseStarts(t *testing.T, scenarios map[string]harness.FalseStartScenario) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "falsestart.json")
	if err := (&harness.FalseStartFixture{Browser: "old", Measured: "2026-10-16", How: "how", Scenarios: scenarios}).Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestTheCommandWritesFalseStartAndThenHoldsTheBrowserToIt(t *testing.T) {
	opening(t, &fake{}, "Fake 1")
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--records", "", "--alps", ""}
	const id = "fs-h1-ecdhe-ecdsa-aes128gcm"
	path := falseStarts(t, map[string]harness.FalseStartScenario{"kept": {Proto: "kept"}})
	code, _, stderr := measured(t, append(none, "--false-start", path, "--only", id)...)
	if code != 0 || !strings.Contains(stderr, "tls1.2 "+id+": HTTP/1.1, early false") {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	wrote, err := harness.LoadFalseStart(path)
	if err != nil {
		t.Fatalf("LoadFalseStart: %v", err)
	}
	// The fake is Go's client, which waits for the server's Finished.
	if got := wrote.Scenarios[id]; got.Proto != "HTTP/1.1" || got.Early || wrote.Scenarios["kept"].Proto != "kept" ||
		wrote.Browser != "Fake 1, --headless=new --lang=en-US, Testing 1 (arm64)" || wrote.Measured != "2026-10-16, 2026-10-17" {
		t.Errorf("wrote %+v", wrote)
	}
	if code, stdout, stderr := measured(t, append(none, "--false-start", path, "--only", id, "--check")...); code != 0 ||
		stdout != "the browser is what the fixtures say\n" {
		t.Errorf("held to what it wrote: %d\n%s%s", code, stdout, stderr)
	}
	early := wrote.Scenarios[id]
	early.Early = true
	path = falseStarts(t, map[string]harness.FalseStartScenario{id: early})
	if code, stdout, _ := measured(t, append(none, "--false-start", path, "--only", id+",fs-h1-ecdhe-rsa-aes128cbc", "--check")...); code != 3 ||
		!strings.Contains(stdout, id+": asked before the server's Finished false, want true") ||
		!strings.Contains(stdout, "fs-h1-ecdhe-rsa-aes128cbc was measured, and the fixture has no such scenario") {
		t.Errorf("held to another: %d\n%s", code, stdout)
	}
	// Every scenario held, none named.
	if code, stdout, _ := measured(t, append(none, "--false-start", falseStarts(t, nil), "--only", id, "--check")...); code != 3 ||
		stdout != id+" was measured, and the fixture has no such scenario\n" {
		t.Errorf("held to an empty fixture: %d\n%s", code, stdout)
	}
	if code, _, stderr := measured(t, append(none, "--false-start", falseStarts(t, nil), "--only", id)...); code != 0 {
		t.Errorf("written into an empty fixture: %d\n%s", code, stderr)
	}
}

func TestTheCommandSaysWhyItMeasuredNoFalseStart(t *testing.T) {
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--records", "", "--alps", ""}
	opening(t, &fake{}, "Fake 1")
	if code, _, stderr := measured(t, append(none, "--false-start", filepath.Join(t.TempDir(), "none.json"))...); code != 1 ||
		!strings.Contains(stderr, "measure: open ") {
		t.Errorf("no fixture: %d\n%s", code, stderr)
	}
	if code, _, stderr := measured(t, append(none, "--false-start", falseStarts(t, nil), "--only", "none")...); code != 1 ||
		!strings.Contains(stderr, "measure: harness: there is no scenario none") {
		t.Errorf("an unknown scenario: %d\n%s", code, stderr)
	}
	opening(t, &fake{failOpen: true}, "Fake 1")
	if code, _, stderr := measured(t, append(none, "--false-start", falseStarts(t, nil), "--only", "fs-h1-ecdhe-ecdsa-aes128gcm")...); code != 1 ||
		!strings.Contains(stderr, "the fake would not open") {
		t.Errorf("a browser that does not open: %d\n%s", code, stderr)
	}
}

func TestTheCommandHoldsANewerBuildToTheFixtures(t *testing.T) {
	// A build that says another version in sec-ch-ua, and so writes heads a
	// byte longer, is what the fixtures say with --newer, and not without.
	none := []string{"--browser", "chrome", "--connections", "", "--decoding", "", "--hpack", "", "--flow", "",
		"--urls", "", "--hellos", "", "--false-start", "", "--alps", ""}
	requests, _ := fixtures(t, map[string]harness.MeasuredScenario{}, nil)
	records := recordsFile(t, nil)
	for _, only := range []struct{ fixture, scenario, path, other string }{
		{"--requests", "nav-direct", requests, "--records"},
		{"--records", "h1-records-header", records, "--requests"},
	} {
		args := append(slices.Clone(none), only.fixture, only.path, only.other, "", "--only", only.scenario)
		opening(t, &fake{version: "1"}, "Fake 1")
		if code, _, stderr := measured(t, args...); code != 0 {
			t.Fatalf("%s written: %d\n%s", only.fixture, code, stderr)
		}
		opening(t, &fake{version: "22"}, "Fake 22")
		code, stdout, _ := measured(t, append(args, "--check")...)
		if code != 3 || !strings.Contains(stdout, only.scenario) {
			t.Errorf("%s held as it is: %d\n%s", only.fixture, code, stdout)
		}
		code, stdout, stderr := measured(t, append(args, "--check", "--newer")...)
		if code != 0 || stdout != "the browser is what the fixtures say\n" {
			t.Errorf("%s held as a newer build: %d\n%s%s", only.fixture, code, stdout, stderr)
		}
	}
	// --newer says how to hold a browser, which writing does not.
	if code, _, stderr := measured(t, append(none, "--requests", requests, "--records", "", "--newer")...); code != 2 ||
		stderr != "measure: --newer holds a browser to the fixtures, with --check\n" {
		t.Errorf("--newer without --check: %d\n%s", code, stderr)
	}
}

// stuckMeasurer is a measurer whose browser began the scenarios it is asked
// for and finished only those of finished, and which keeps the names it was
// asked for.
type stuckMeasurer struct {
	finished []string
	asked    [][]string
}

func (s *stuckMeasurer) measure(_ context.Context, _ harness.Browser, only []string, _ io.Writer) (map[string]harness.MeasuredScenario, error) {
	s.asked = append(s.asked, only)
	out := map[string]harness.MeasuredScenario{}
	for _, id := range only {
		scenario := harness.MeasuredScenario{Note: id, H2: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/" + id}},
			H1: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/" + id}}}
		if !slices.Contains(s.finished, id) {
			scenario.Unfinished = []string{"over h2: /p/end was not asked for within 15s"}
		}
		out[id] = scenario
	}
	return out, nil
}

func TestAScenarioTheBrowserDidNotFinishIsSaidAndNeverWritten(t *testing.T) {
	kept := harness.MeasuredScenario{Note: "a", H2: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/a"}},
		H1: []harness.Request{{Method: "GET", URL: "https://www.example.com/p/a"}}}
	requests, _ := fixtures(t, map[string]harness.MeasuredScenario{"a": kept, "b": kept}, nil)
	before, err := os.ReadFile(requests)
	if err != nil {
		t.Fatal(err)
	}
	stuck := &stuckMeasurer{finished: []string{"a"}}
	var progress bytes.Buffer
	// Written, nothing is, the fixture as it was.
	_, err = measureRequests(context.Background(), nil, stuck.measure, requests, []string{"a", "b"}, "about", false, false, &progress)
	if err == nil || err.Error() != "harness: b did not finish over h2: /p/end was not asked for within 15s: nothing written" {
		t.Errorf("measureRequests: %v", err)
	}
	if after, err := os.ReadFile(requests); err != nil || !bytes.Equal(after, before) {
		t.Errorf("the fixture was written: %v", err)
	}
	// Checked, it is a difference.
	diff, err := measureRequests(context.Background(), nil, stuck.measure, requests, []string{"a", "b"}, "about", true, false, &progress)
	if err != nil || !slices.Contains(diff, "b did not finish over h2: /p/end was not asked for within 15s") {
		t.Errorf("measureRequests: %q, %v", diff, err)
	}
}

func TestACheckPassesOverWhatChromeSendsOtherwiseOnThisPlatform(t *testing.T) {
	// On Windows, Chrome answers Negotiate: the scenario that offers it is
	// passed over, said, and the rest measured; asked for alone, nothing is.
	old := platform
	t.Cleanup(func() { platform = old })
	scenario := harness.MeasuredScenario{Note: "x"}
	requests, _ := fixtures(t, map[string]harness.MeasuredScenario{"auth-digest-negotiate": scenario, "nav-direct": scenario}, nil)
	for _, tc := range []struct {
		platform string
		names    []string
		asked    [][]string
		says     string
	}{
		{"windows", nil, [][]string{{"nav-direct"}}, "auth-digest-negotiate: passed over on windows: Chrome on Windows answers Negotiate"},
		{"windows", []string{"auth-digest-negotiate"}, nil, "auth-digest-negotiate: passed over on windows"},
		{"macos", nil, [][]string{nil}, ""},
	} {
		platform = func() string { return tc.platform }
		stuck := &stuckMeasurer{}
		var progress bytes.Buffer
		if _, err := measureRequests(context.Background(), nil, stuck.measure, requests, tc.names, "about", true, false, &progress); err != nil {
			t.Errorf("%s %v: %v", tc.platform, tc.names, err)
		}
		if !reflect.DeepEqual(stuck.asked, tc.asked) || !strings.Contains(progress.String(), tc.says) ||
			tc.says == "" && progress.Len() > 0 {
			t.Errorf("%s %v: asked %q, said %q", tc.platform, tc.names, stuck.asked, progress.String())
		}
	}
	// Written, a fixture is measured whole whatever the platform.
	platform = func() string { return "windows" }
	stuck := &stuckMeasurer{finished: []string{"auth-digest-negotiate", "nav-direct"}}
	if _, err := measureRequests(context.Background(), nil, stuck.measure, requests, nil, "about", false, false, io.Discard); err != nil ||
		!reflect.DeepEqual(stuck.asked, [][]string{nil}) {
		t.Errorf("written: asked %q, %v", stuck.asked, err)
	}
}

func TestACheckGoesOnPastAFixtureItCannotMeasure(t *testing.T) {
	// The decodings cannot be measured here and the requests can: a
	// difference of its own, said, and the rest held to the fixtures. Only
	// what cannot be measured is no check.
	text := "x"
	requests, decoding := fixtures(t, map[string]harness.MeasuredScenario{"nav-direct": {Note: "x"}},
		[]harness.DecodingCase{{Name: "a", ContentType: &text}})
	opening(t, &fake{failDumps: true}, "Fake")
	none := []string{"--hpack", "", "--flow", "", "--urls", "", "--hellos", "", "--false-start", "", "--records", "", "--alps", ""}
	code, stdout, stderr := measured(t, append([]string{"--browser", "chrome", "--requests", requests, "--connections", "",
		"--decoding", decoding, "--only", "nav-direct", "--check"}, none...)...)
	if code != 3 || !strings.Contains(stdout, "the decoding could not be measured: ") ||
		!strings.Contains(stdout, "the fake dumped nothing") || !strings.Contains(stdout, "nav-direct over h2: 1 requests, the fixture 0") ||
		!strings.Contains(stderr, "measure: ") {
		t.Errorf("exit %d:\n%s%s", code, stdout, stderr)
	}
	code, stdout, stderr = measured(t, append([]string{"--browser", "chrome", "--requests", "", "--connections", "",
		"--decoding", decoding, "--check"}, none...)...)
	if code != 1 || !strings.HasSuffix(stderr, "measure: nothing could be measured\n") || stdout != "" {
		t.Errorf("exit %d:\n%s%s", code, stdout, stderr)
	}
}

func TestTheFakesHeaderBlocksDoNotHangOnWhenTheServersSettingsCome(t *testing.T) {
	// Go's HTTP/2 client starts a header block with a size update once it
	// has read the server's SETTINGS, which on loopback come about as it
	// writes its first: a fixture the fake wrote did not always hold it to
	// itself (2026-10-20, under load). The fake reads nothing before it has
	// written its first request, so the update is in its second block,
	// whenever they come: at once, or read late.
	none := []string{"--browser", "chrome", "--requests", "", "--connections", "", "--decoding", "", "--flow", "", "--urls", "",
		"--hellos", "", "--false-start", "", "--records", ""}
	opening(t, &fake{}, "Fake Chrome 1.2.3.4")
	for _, tc := range []struct{ fixture, scenario string }{{"--hpack", "hpack-fetch"}, {"--alps", "alps-none"}} {
		t.Run(tc.scenario, func(t *testing.T) {
			var wrote [2]string
			before := holds.Load()
			for i, late := range []time.Duration{0, 20 * time.Millisecond} {
				readsLate = late
				path := filepath.Join(t.TempDir(), "fixture.json")
				_ = os.WriteFile(path, []byte("{}"), 0o644)
				args := append(slices.Clone(none), "--hpack", "", "--alps", "", tc.fixture, path, "--only", tc.scenario)
				code, _, stderr := measured(t, args...)
				readsLate = 0
				if code != 0 {
					t.Fatalf("exit %d: %s", code, stderr)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				wrote[i] = strings.Join(strings.Fields(string(data)), " ")
			}
			if wrote[0] != wrote[1] {
				t.Errorf("read at once:\n%s\nread late:\n%s", wrote[0], wrote[1])
			}
			// Held, an HTTP/2 connection cannot have read the SETTINGS
			// before its first block, whatever the machine is doing.
			if held := holds.Load() - before; held < 2 {
				t.Errorf("%d connections held", held)
			}
			// The second block, of the run page saying it is done, begins
			// with the update.
			if at := strings.Index(wrote[0], `"size update 4096"`); at < strings.Index(wrote[0], "/done/") {
				t.Errorf("the size update not in the second block: %s", wrote[0])
			}
		})
	}
}

func TestTheFakeReadsNothingBeforeItHasWrittenItsFirstRequest(t *testing.T) {
	// Once held, what the server sent first waits for the client's second
	// write, and a read held for a request never written ends when the
	// connection does; before, a read goes, as TLS's handshake reads.
	client, server := net.Pipe()
	held := &heldReads{Conn: client}
	go func() { _, _ = server.Write([]byte("hello")) }()
	if n, err := held.Read(make([]byte, 5)); err != nil || n != 5 {
		t.Fatalf("Read before held: %d, %v", n, err)
	}
	held.hold()
	go func() { _, _ = server.Write([]byte("settings")) }()
	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 8)
		n, _ := held.Read(buf)
		read <- string(buf[:n])
	}()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	for i, write := range []string{"preface", "headers"} {
		select {
		case got := <-read:
			t.Fatalf("read %q after %d writes", got, i)
		case <-time.After(50 * time.Millisecond):
		}
		if _, err := held.Write([]byte(write)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	select {
	case got := <-read:
		if got != "settings" {
			t.Errorf("read %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no read after two writes")
	}
	_ = held.Close()
	_ = server.Close()

	client, server = net.Pipe()
	held = &heldReads{Conn: client}
	held.hold()
	ended := make(chan error, 1)
	go func() {
		_, err := held.Read(make([]byte, 1))
		ended <- err
	}()
	_ = held.Close()
	select {
	case err := <-ended:
		if err == nil {
			t.Error("a read on a closed connection read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a held read outlived its connection")
	}
	_ = server.Close()
}
