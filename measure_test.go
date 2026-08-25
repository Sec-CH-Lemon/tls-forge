package tlsforge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// TestBrowserHelper is this test binary standing in for a browser.
//
// Re-executing the test binary is the standard way to get a real subprocess
// without shipping a second program, and a real subprocess is the point: the
// measurement path launches something, waits for it to arrive over TLS, and
// merges what it reports. A fake that skipped the process boundary would test
// none of that.
func TestBrowserHelper(t *testing.T) {
	url := os.Getenv("TLSFORGE_BROWSER_HELPER")
	if url == "" {
		t.Skip("not running as the browser stand-in")
	}

	client, err := New(WithInsecureSkipVerify())
	if err != nil {
		os.Exit(1)
	}
	defer client.Close()

	if _, err := client.Get(url + "/"); err != nil {
		os.Exit(1)
	}
	if _, err := client.Do(&Request{
		Method: "POST",
		URL:    url + "/collect",
		Body:   []byte(`{"user_agent":"stand-in browser","platform":"testOS"}`),
		Header: NewHeader("content-type", "application/json"),
	}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// browserStandIn writes a launcher that behaves the way browser.Open expects:
// it takes flags it ignores and a URL as its last argument.
func browserStandIn(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}

	// The URL is passed through the environment rather than as an argument,
	// because a test binary parses its own argv and would reject the browser
	// flags it is handed.
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

func TestMeasureBrowser(t *testing.T) {
	measured, err := MeasureBrowser(context.Background(), MeasureOptions{
		Browser: browserStandIn(t),
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("MeasureBrowser: %v", err)
	}

	if measured.Source != capture.SourceBrowser {
		t.Errorf("source = %q", measured.Source)
	}
	if len(measured.RawClientHello) == 0 {
		t.Error("no ClientHello was captured")
	}
	if measured.Navigator == nil || measured.Navigator.Platform != "testOS" {
		t.Errorf("navigator = %+v", measured.Navigator)
	}
	// The navigation's headers, not the report's.
	if measured.HTTP2 == nil {
		t.Fatal("no HTTP/2 data")
	}
	for _, name := range measured.HTTP2.HeaderOrder {
		if name == "content-type" {
			t.Errorf("captured the report's headers, not the navigation's: %v", measured.HTTP2.HeaderOrder)
		}
	}
}

func TestMeasureBrowserErrors(t *testing.T) {
	if _, err := MeasureBrowser(context.Background(), MeasureOptions{Browser: "netscape"}); err == nil {
		t.Error("expected an error for an unknown browser")
	}

	// A launcher that starts and never reports a capture: the measurement must
	// end at its deadline rather than waiting forever for a page that will never
	// load.
	//
	// The test binary itself, rather than a shell script — a script with a
	// shebang is not executable on Windows, and the failure it produced there
	// ("executable file not found in %PATH%") was the launcher never starting,
	// which is a different path through the code. Handed browser flags it does
	// not know, the binary exits at once; that is fine, because what is being
	// tested is what happens when no capture arrives.
	silent, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	_, err = MeasureBrowser(context.Background(), MeasureOptions{
		Browser: silent, Timeout: 300 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected a timeout")
	}
	if !strings.Contains(err.Error(), "no capture") {
		t.Errorf("error = %v, want it to say no capture arrived", err)
	}
}

func TestMeasureBrowserReportsALaunchFailure(t *testing.T) {
	notExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(notExecutable, []byte("not a program"), 0o644); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	if _, err := MeasureBrowser(context.Background(), MeasureOptions{Browser: notExecutable}); err == nil {
		t.Error("expected a launch failure")
	}
}

func TestMeasureSelf(t *testing.T) {
	measured, err := MeasureSelf(context.Background())
	if err != nil {
		t.Fatalf("MeasureSelf: %v", err)
	}
	if measured.Source != capture.SourceTLSFetch {
		t.Errorf("source = %q", measured.Source)
	}
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if measured.Profile != shipped.Name {
		t.Errorf("profile = %q, want %q", measured.Profile, shipped.Name)
	}
	if measured.TLS.JA4 == "" {
		t.Error("no JA4 was measured")
	}
}

func TestMeasureSelfErrors(t *testing.T) {
	if _, err := MeasureSelf(context.Background(), WithProfile("netscape_4")); err == nil {
		t.Error("expected an error for an unknown profile")
	}

	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	server.Close()
	if _, err := MeasureSelfAt(context.Background(), server); err == nil {
		t.Error("expected an error against a closed server")
	}
}

func TestReadMeasurement(t *testing.T) {
	if _, err := readMeasurement(&Response{Status: 404, Body: []byte("not found\n")}, "x"); err == nil {
		t.Error("expected an error for a non-200 answer")
	}
	if _, err := readMeasurement(&Response{Status: 200, Body: []byte("not json")}, "x"); err == nil {
		t.Error("expected an error for an unreadable answer")
	}
	measured, err := readMeasurement(&Response{Status: 200, Body: []byte(`{"tls":{"ja4":"x"}}`)}, "chrome_151")
	if err != nil {
		t.Fatalf("readMeasurement: %v", err)
	}
	if measured.Source != capture.SourceTLSFetch {
		t.Errorf("source = %q", measured.Source)
	}
	if measured.Profile != "chrome_151" {
		t.Errorf("profile = %q", measured.Profile)
	}
}

func TestMeasurementsReportAServerThatCannotStart(t *testing.T) {
	// Binding a port is the first thing every measurement does, and a machine
	// with no loopback to bind is a real, if rare, way for all of this to fail.
	original := startEchoServer
	t.Cleanup(func() { startEchoServer = original })
	startEchoServer = func(...echo.Option) (*echo.Server, error) {
		return nil, errors.New("no port to bind")
	}

	if _, err := MeasureSelf(context.Background()); err == nil {
		t.Error("MeasureSelf did not report the failure")
	}
	if _, err := MeasureBrowser(context.Background(), MeasureOptions{}); err == nil {
		t.Error("MeasureBrowser did not report the failure")
	}
	if _, err := CompareToBrowser(context.Background(), MeasureOptions{}); err == nil {
		t.Error("CompareToBrowser did not report the failure")
	}
}

func TestCompareToBrowser(t *testing.T) {
	// The stand-in browser IS this library, so the two measurements must agree
	// on every field — which is exactly what a real Chrome and the shipped
	// profile do, and what this asserts the comparison can recognise.
	result, err := CompareToBrowser(context.Background(), MeasureOptions{
		Browser: browserStandIn(t),
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CompareToBrowser: %v", err)
	}
	if !result.OK() {
		t.Errorf("expected no differences:\n%s", result)
	}
	rendered := result.String()
	if !strings.Contains(rendered, "identical") {
		t.Errorf("report = %s", rendered)
	}
	if !strings.Contains(rendered, result.Browser.TLS.JA4) {
		t.Errorf("report does not show the JA4:\n%s", rendered)
	}
}

func TestCompareToBrowserReportsErrors(t *testing.T) {
	if _, err := CompareToBrowser(context.Background(), MeasureOptions{Browser: "netscape"}); err == nil {
		t.Error("expected an error for an unknown browser")
	}
	if _, err := CompareToBrowser(context.Background(),
		MeasureOptions{Browser: browserStandIn(t), Timeout: 30 * time.Second},
		WithProfile("netscape_4")); err == nil {
		t.Error("expected an error for an unknown profile")
	}
}

func TestCompareFindsDifferences(t *testing.T) {
	// Two genuinely different clients: the shipped Chrome and a catalogue
	// profile from an older one.
	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	defer server.Close()

	chrome, err := MeasureSelfAt(context.Background(), server)
	if err != nil {
		t.Fatalf("MeasureSelfAt: %v", err)
	}
	older, err := MeasureSelfAt(context.Background(), server, WithProfile("chrome_120"))
	if err != nil {
		t.Fatalf("MeasureSelfAt: %v", err)
	}

	result, err := Compare(chrome, older)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if result.OK() {
		t.Fatal("expected differences between two different Chrome versions")
	}
	rendered := result.String()
	if !strings.Contains(rendered, "TLS") {
		t.Errorf("report does not show the TLS differences:\n%s", rendered)
	}
	if strings.Contains(rendered, "identical") {
		t.Errorf("a differing pair was reported as identical:\n%s", rendered)
	}
}

func TestCompareReportsHTTP2Differences(t *testing.T) {
	server, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	defer server.Close()

	reference, err := MeasureSelfAt(context.Background(), server)
	if err != nil {
		t.Fatalf("MeasureSelfAt: %v", err)
	}
	candidate, err := MeasureSelfAt(context.Background(), server)
	if err != nil {
		t.Fatalf("MeasureSelfAt: %v", err)
	}
	// Move one header, leaving the handshake untouched: a client can copy a
	// ClientHello byte for byte and still give itself away one layer up.
	headers := candidate.HTTP2.Headers
	headers[0], headers[len(headers)-1] = headers[len(headers)-1], headers[0]

	result, err := Compare(reference, candidate)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if result.TLS.OK() != true {
		t.Errorf("the handshakes should still match:\n%s", result.TLS)
	}
	if result.HTTP2.OK() {
		t.Error("expected the header order difference to be reported")
	}
	if !strings.Contains(result.String(), "HTTP/2") {
		t.Errorf("report does not show the HTTP/2 differences:\n%s", result)
	}
}

func TestCompareWithUnusableCaptures(t *testing.T) {
	good := &capture.Capture{RawClientHello: mustReadFixture(t)}
	bad := &capture.Capture{}

	if _, err := Compare(bad, good); err == nil {
		t.Error("expected an error for an unusable browser capture")
	}
	if _, err := Compare(good, bad); err == nil {
		t.Error("expected an error for an unusable client capture")
	}
}

func TestCompareWithoutHTTP2(t *testing.T) {
	// An HTTP/1.1 measurement has no HTTP/2 half. The comparison must still work
	// on the handshake rather than refusing to run.
	raw := mustReadFixture(t)
	result, err := Compare(&capture.Capture{RawClientHello: raw}, &capture.Capture{RawClientHello: raw})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !result.OK() {
		t.Errorf("identical captures differed:\n%s", result)
	}
}

func TestCompareReportsAProtocolMismatch(t *testing.T) {
	raw := mustReadFixture(t)
	browser := &capture.Capture{RawClientHello: raw, Negotiated: "h2", HTTP2: &capture.HTTP2{}}
	client := &capture.Capture{RawClientHello: raw, Negotiated: "http/1.1", HTTP1: &capture.HTTP1{Proto: "HTTP/1.1"}}
	result, err := Compare(browser, client)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if result.OK() || !strings.Contains(result.HTTP2.String(), "http_protocol") {
		t.Fatalf("protocol mismatch was not reported: %+v", result)
	}
}

func TestNegotiatedProtocolFallbacks(t *testing.T) {
	tests := []struct {
		capture *capture.Capture
		want    string
	}{
		{&capture.Capture{Negotiated: "h3"}, "h3"},
		{&capture.Capture{HTTP2: &capture.HTTP2{}}, "h2"},
		{&capture.Capture{HTTP1: &capture.HTTP1{Proto: "HTTP/1.0"}}, "HTTP/1.0"},
		{&capture.Capture{}, "(not recorded)"},
	}
	for _, test := range tests {
		if got := negotiatedProtocol(test.capture); got != test.want {
			t.Errorf("negotiatedProtocol(%+v) = %q, want %q", test.capture, got, test.want)
		}
	}
}

func mustReadFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

func TestMeasureBrowserPassesExtraFlagsToTheBrowser(t *testing.T) {
	// The reason this plumbing exists: without --no-sandbox Chrome starts on a
	// CI runner and never loads the page, and a flag that quietly fails to
	// arrive is a capture that times out for a reason nobody can see from the
	// message.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	recorded := filepath.Join(dir, "args")
	recorder := filepath.Join(dir, "recorder")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + recorded + "\n"
	if err := os.WriteFile(recorder, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the recorder: %v", err)
	}

	// It records and exits without reporting anything, so the measurement ends
	// at its deadline. What is being tested is the launch, not the capture.
	_, err := MeasureBrowser(context.Background(), MeasureOptions{
		Browser:     recorder,
		Timeout:     2 * time.Second,
		BrowserArgs: []string{"--no-sandbox", "--disable-dev-shm-usage"},
	})
	if err == nil {
		t.Fatal("the recorder answers nothing, so this should have timed out")
	}

	data, readErr := os.ReadFile(recorded)
	if readErr != nil {
		t.Fatalf("the browser was never launched: %v", readErr)
	}
	for _, want := range []string{"--no-sandbox", "--disable-dev-shm-usage"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("%s did not reach the browser:\n%s", want, data)
		}
	}
}
