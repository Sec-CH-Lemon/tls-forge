package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// visitAsAPerson does at the address what a person is told to: opens it,
// which only says what to do next; opens it again, as if in a new tab; and lets
// the page report back.
func visitAsAPerson(address, profileName string) error {
	client, err := tlsforge.New(tlsforge.WithProfile(profileName), tlsforge.WithInsecureSkipVerify(),
		tlsforge.WithoutRedirects())
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	opened := tlsforge.NewHeader("sec-fetch-site", "none", "sec-fetch-mode", "navigate",
		"sec-fetch-dest", "document", "sec-fetch-user", "?1")
	if _, err := client.Do(&tlsforge.Request{URL: address, Header: opened}); err != nil {
		return err
	}
	page, err := client.Do(&tlsforge.Request{URL: address, Header: opened})
	if err != nil {
		return err
	}
	const marker = "fetch('"
	start := strings.Index(page.Text(), marker)
	if start < 0 {
		return fmt.Errorf("the second visit was not measured:\n%s", page.Text())
	}
	start += len(marker)
	end := strings.IndexByte(page.Text()[start:], '\'')
	_, err = client.Do(&tlsforge.Request{
		Method: "POST", URL: strings.TrimSuffix(address, "/") + page.Text()[start:start+end],
		Body:   []byte(`{}`),
		Header: tlsforge.NewHeader("content-type", "application/json"),
	})
	return err
}

// aPersonVisits is a person at the browser the next manual measurement waits
// for, wearing a profile; what came of the visit arrives on the channel.
func aPersonVisits(t *testing.T, profileName string) <-chan error {
	t.Helper()
	visited := make(chan error, 1)
	previous := visitorReady
	visitorReady = func(address string) {
		go func() { visited <- visitAsAPerson(address, profileName) }()
	}
	t.Cleanup(func() { visitorReady = previous })
	return visited
}

// theVisitorsPlatform is the platform the stand-in person's browser says it
// runs on: the default profile's, which is this machine's.
func theVisitorsPlatform(t *testing.T) (version, platform string) {
	t.Helper()
	p, err := profile.Get("chrome")
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	version, _ = profile.Split(p.Name)
	return version, platformFrom(p.UserAgent)
}

func TestCaptureManualSavesTheBrowserAPersonOpens(t *testing.T) {
	visited := aPersonVisits(t, "chrome")
	dir := t.TempDir()
	code, stdout, stderr := exec(t, "capture", "--manual", "--save", dir)
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"waiting for a browser at https://localhost:", "1. Open that address",
		"2. It warns about the certificate", "3. Open the address again in a new tab",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
	// Named for the browser, and filed under the platform its user agent says.
	version, platform := theVisitorsPlatform(t)
	written := filepath.Join(dir, version, platform+".json")
	data, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("nothing was written to %s:\n%s", written, stdout)
	}
	saved, err := profile.Load(data)
	if err != nil || saved.Name != version+"_"+platform || saved.HTTP1 != nil || len(saved.ClientHello) == 0 {
		t.Fatalf("saved %+v, %v", saved, err)
	}
	if _, err := saved.ClientProfile(); err != nil {
		t.Errorf("the saved profile cannot be used: %v", err)
	}
}

func TestCaptureManualInstallsUnderTheBrowsersName(t *testing.T) {
	// Not as "local": that is this machine's own browser, and a browser a person
	// opened is another one, which its own name then finds.
	dir := keepProfilesIn(t)
	visited := aPersonVisits(t, "chrome")
	code, stdout, stderr := exec(t, "capture", "--manual", "--install", "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	version, platform := theVisitorsPlatform(t)
	if code != 0 || !strings.Contains(stdout, "--profile "+version+"_"+platform) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, version, platform+".json")); err != nil {
		t.Errorf("nothing was kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, localName)); err == nil {
		t.Error("it was kept as this machine's own browser")
	}
}

func TestCompareManual(t *testing.T) {
	for _, tc := range []struct {
		profile string
		code    int
	}{{"chrome", 0}, {"firefox_148", 3}} {
		visited := aPersonVisits(t, "chrome")
		code, stdout, stderr := exec(t, "compare", "--manual", "--color", "never", "--profile", tc.profile)
		if err := <-visited; err != nil {
			t.Fatalf("visiting: %v", err)
		}
		if code != tc.code || !strings.Contains(stdout, "HTTP/1.1 is not measured from a browser you open") ||
			!strings.Contains(stderr, "waiting for a browser at") {
			t.Errorf("%s: exit code = %d\n%s\n%s", tc.profile, code, stdout, stderr)
		}
	}
	// As JSON, without a word in front of the document.
	visited := aPersonVisits(t, "chrome")
	code, stdout, _ := exec(t, "compare", "--manual", "--json")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.HasPrefix(stdout, "{") {
		t.Errorf("exit code = %d\n%s", code, stdout)
	}
}

func TestManualFlagsThatDoNotGoTogether(t *testing.T) {
	for _, command := range []string{"capture", "compare"} {
		for _, tc := range []struct {
			args []string
			says string
		}{
			{[]string{"--manual", "--browser", "chrome"}, "--browser is for a browser tls-forge starts"},
			{[]string{"--manual", "--headless"}, "--headless is for a browser tls-forge starts"},
			{[]string{"--manual", "--browser-arg", "--no-sandbox"}, "--browser-arg is for a browser tls-forge starts"},
			{[]string{"--addr", "127.0.0.1:0"}, "--addr is for --manual"},
			{[]string{"--host", "example.test"}, "--host is for --manual"},
		} {
			code, _, stderr := exec(t, append([]string{command}, tc.args...)...)
			if code != 2 || !strings.Contains(stderr, tc.says) {
				t.Errorf("%s %q: exit code = %d\n%s", command, tc.args, code, stderr)
			}
		}
	}
}

func TestManualWaitsAsLongAsItIsTold(t *testing.T) {
	// Nobody comes: it gives up when --timeout says, and says what it waited for.
	for _, command := range []string{"capture", "compare"} {
		code, _, stderr := exec(t, command, "--manual", "--timeout", "50ms")
		if code != 1 || !strings.Contains(stderr, "no browser came to https://localhost:") {
			t.Errorf("%s: exit code = %d\n%s", command, code, stderr)
		}
		// Nor where it cannot listen.
		code, _, stderr = exec(t, command, "--manual", "--addr", "nowhere")
		if code != 1 || !strings.Contains(stderr, "listen") {
			t.Errorf("%s at nowhere: exit code = %d\n%s", command, code, stderr)
		}
	}
	if got := (visitFlags{manual: new(bool)}).waitFor(newFlagSet("x", nil), 7); got != 7 {
		t.Errorf("waitFor without --manual = %v", got)
	}
}

func TestManualOnEveryInterface(t *testing.T) {
	// Open to a phone, and so to anybody on the network: said, and so is what a
	// phone needs to find this machine, until it is given.
	code, _, stderr := exec(t, "capture", "--manual", "--addr", "0.0.0.0:0", "--timeout", "50ms")
	if code != 1 || !strings.Contains(stderr, "WARNING: capture is listening beyond loopback") ||
		!strings.Contains(stderr, "A phone cannot open localhost: give --host") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	_, _, stderr = exec(t, "capture", "--manual", "--addr", "0.0.0.0:0", "--host", "192.0.2.10", "--timeout", "50ms")
	if strings.Contains(stderr, "A phone cannot open localhost") || !strings.Contains(stderr, "https://192.0.2.10:") {
		t.Errorf("with --host:\n%s", stderr)
	}
}

func TestPlatformFrom(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/155.0.0.0 Safari/537.36", "macos"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/155.0.0.0", "windows"},
		{"Mozilla/5.0 (X11; Linux x86_64) Chrome/155.0.0.0", "linux"},
		// The phones before what they say they are like.
		{"Mozilla/5.0 (Linux; Android 15; Pixel 9) Chrome/138.0.0.0 Mobile Safari/537.36", "android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) Version/18.5 Mobile/15E148 Safari/604.1", "ios"},
		{"Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) CriOS/138.0 Mobile/15E148 Safari/604.1", "ios"},
		{"Mozilla/5.0 (iPod touch; CPU iPhone OS 16_0 like Mac OS X)", "ios"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/155.0.0.0", ""},
		{"", ""},
	} {
		if got := platformFrom(tc.ua); got != tc.want {
			t.Errorf("platformFrom(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestAProfileIsFiledUnderTheBrowsersPlatform(t *testing.T) {
	// The platform the browser's user agent says, which for a phone is not this
	// machine's; and this machine's for one that says none a profile is filed
	// under, such as ChromeOS, as it always was.
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome"))
	if err != nil {
		t.Fatalf("MeasureSelf: %v", err)
	}
	for _, tc := range []struct{ ua, platform string }{
		{"Mozilla/5.0 (Linux; Android 15; Pixel 9) Chrome/155.0.0.0 Mobile Safari/537.36", "android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) Version/18.5 Mobile/15E148 Safari/604.1", "ios"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/155.0.0.0", profile.HostPlatform()},
	} {
		measured.Navigator = &capture.Navigator{UserAgent: tc.ua}
		dir := t.TempDir()
		name, path, err := saveProfile(dir, "chrome_155", measured)
		if err != nil || name != "chrome_155_"+tc.platform ||
			path != filepath.Join(dir, "chrome_155", tc.platform+".json") {
			t.Errorf("%s: saved %q at %s: %v", tc.platform, name, path, err)
		}
	}
}
