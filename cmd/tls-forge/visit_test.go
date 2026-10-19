package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// visitAsAPersonSaying does at the address what a person is told to: opens
// it, which only says what to do next; opens it again, as if in a new tab; and
// lets the page report back navigator, the JSON /collect takes: what a
// browser's script says of it.
func visitAsAPersonSaying(address, profileName, navigator string) error {
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
		Body:   []byte(navigator),
		Header: tlsforge.NewHeader("content-type", "application/json"),
	})
	return err
}

// aPersonVisits is a person at the browser the next manual measurement waits
// for, wearing a profile; what came of the visit arrives on the channel.
func aPersonVisits(t *testing.T, profileName string) <-chan error {
	t.Helper()
	return aPersonVisitsSaying(t, profileName, `{}`)
}

// aPersonVisitsSaying is aPersonVisits whose page reports navigator.
func aPersonVisitsSaying(t *testing.T, profileName, navigator string) <-chan error {
	t.Helper()
	visited := make(chan error, 1)
	previous := visitorReady
	visitorReady = func(address string) {
		go func() { visited <- visitAsAPersonSaying(address, profileName, navigator) }()
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
	// opened is another one, which its own name then finds. A Chromium browser
	// is named by its brands: Brave's user agent is Chrome's.
	dir := keepProfilesIn(t)
	visited := aPersonVisitsSaying(t, "chrome",
		`{"brands": [{"brand": "Brave", "version": "155"}, {"brand": "Chromium", "version": "155"}]}`)
	code, stdout, stderr := exec(t, "capture", "--manual", "--install", "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	_, platform := theVisitorsPlatform(t)
	if code != 0 || !strings.Contains(stdout, "--profile brave_155_"+platform) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "brave_155", platform+".json")); err != nil {
		t.Errorf("nothing was kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, localName)); err == nil {
		t.Error("it was kept as this machine's own browser")
	}
}

func TestCaptureManualKeepsNoProfileUnderAShippedName(t *testing.T) {
	// A profile kept under the name of one tls-forge ships would answer for it
	// from then on, --profile chrome too, the directory being read first: not
	// unless asked by name. The browser is measured and shown all the same.
	dir := keepProfilesIn(t)
	version, platform := theVisitorsPlatform(t)
	visited := aPersonVisits(t, "chrome")
	code, stdout, stderr := exec(t, "capture", "--manual", "--install", "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 1 || !strings.Contains(stdout, "JA4") || !strings.Contains(stderr,
		version+"_"+platform+" is a profile tls-forge ships, and one kept under its name would answer for it") {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("kept %v, %v", entries, err)
	}
	// Asked by name, it is kept under that name.
	visited = aPersonVisits(t, "chrome")
	code, stdout, stderr = exec(t, "capture", "--manual", "--install", "--name", version, "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.Contains(stdout, "--profile "+version+"_"+platform) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, version, platform+".json")); err != nil {
		t.Errorf("nothing was kept: %v", err)
	}
	// Of a phone, whose platform tls-forge ships nothing for, it is kept.
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome"))
	if err != nil {
		t.Fatalf("MeasureSelf: %v", err)
	}
	measured.Navigator = &capture.Navigator{UserAgent: "Mozilla/5.0 (Linux; Android 15; Pixel 9) Chrome/155.0.0.0 Mobile Safari/537.36"}
	if name, _, err := saveProfile(t.TempDir(), "chrome_155", measured, false); err != nil || name != "chrome_155_android" {
		t.Errorf("a phone's: %q, %v", name, err)
	}
	if !profile.Ships(version+"_"+platform) || profile.Ships("chrome_155_android") || profile.Ships("brave_155_"+platform) {
		t.Error("Ships says otherwise")
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
	// phone needs to find this machine, a name, until it is given.
	hostnameIs(t, "Ihars-MacBook-Pro.local", nil)
	code, _, stderr := exec(t, "capture", "--manual", "--addr", "0.0.0.0:0", "--timeout", "50ms")
	if code != 1 || !strings.Contains(stderr, "WARNING: capture is listening beyond loopback") ||
		!strings.Contains(stderr, "A phone cannot open localhost: give --host a name it reaches this machine by, "+
			"such as ihars-macbook-pro.local (an iPhone finds a .local name by Bonjour).") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	_, _, stderr = exec(t, "capture", "--manual", "--addr", "0.0.0.0:0", "--host", "192.0.2.10", "--timeout", "50ms")
	if strings.Contains(stderr, "A phone cannot open localhost") || !strings.Contains(stderr, "https://192.0.2.10:") {
		t.Errorf("with --host:\n%s", stderr)
	}
}

// hostnameIs has this machine called name, or not say, for the test.
func hostnameIs(t *testing.T, name string, err error) {
	t.Helper()
	previous := hostname
	hostname = func() (string, error) { return name, err }
	t.Cleanup(func() { hostname = previous })
}

func TestCaptureManualKeepsNoProfileAtAnAddress(t *testing.T) {
	// A browser names no server to an address, so a profile of what it sends
	// there would name none to any site: refused before anything listens, with
	// a name this machine may be reached by, and nothing kept.
	hostnameIs(t, "Ihars-MacBook-Pro.local", nil)
	dir, kept := t.TempDir(), keepProfilesIn(t)
	for _, args := range [][]string{
		{"--host", "127.0.0.1", "--save", dir},
		{"--host", "192.0.2.10", "--save", dir},
		{"--host", "::1", "--save", dir},
		{"--host", "[2001:db8::1]", "--install"},
	} {
		code, _, stderr := exec(t, append([]string{"capture", "--manual"}, args...)...)
		if code != 2 || !strings.Contains(stderr, "--host "+args[1]+" is an address, and a browser names no server") ||
			!strings.Contains(stderr, "such as ihars-macbook-pro.local (an iPhone finds a .local name by Bonjour)") ||
			strings.Contains(stderr, "waiting for a browser") {
			t.Errorf("%q: exit code = %d\n%s", args, code, stderr)
		}
	}
	// Not even the directory --install keeps profiles in was made.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("%s holds %v, %v", dir, entries, err)
	}
	if _, err := os.Stat(kept); !os.IsNotExist(err) {
		t.Errorf("%s: %v", kept, err)
	}
	// A name is waited for as before, and so is an address with nothing to keep.
	for _, args := range [][]string{{"--host", "example.test", "--save", dir}, {"--host", "127.0.0.1"}} {
		code, _, stderr := exec(t, append([]string{"capture", "--manual", "--timeout", "50ms"}, args...)...)
		if code != 1 || !strings.Contains(stderr, "no browser came to https://"+args[1]+":") {
			t.Errorf("%q: exit code = %d\n%s", args, code, stderr)
		}
	}
}

func TestACaptureAtAnAddressSaysItIsNoProfile(t *testing.T) {
	// Measured and shown, as a browser at an address sends it, and said not to
	// be one to keep, rather than told how to keep it.
	visited := aPersonVisits(t, "chrome")
	code, stdout, stderr := exec(t, "capture", "--manual", "--host", "127.0.0.1", "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.Contains(stdout, "JA4              t13i") ||
		!strings.Contains(stdout, "The browser named no server, as at an address: capture at a name to keep a profile.") ||
		strings.Contains(stdout, "Re-run with --install") {
		t.Errorf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if namesNoServer(&capture.Capture{RawClientHello: []byte{1, 2, 3}}) {
		t.Error("a hello that does not parse says no server")
	}
}

func TestTheNameAPhoneReachesThisMachineBy(t *testing.T) {
	const bonjour = " (an iPhone finds a .local name by Bonjour)"
	for _, tc := range []struct {
		host       string
		err        error
		name, like string
	}{
		{"Ihars-MacBook-Pro.local", nil, "ihars-macbook-pro.local", ", such as ihars-macbook-pro.local" + bonjour},
		{"mbp", nil, "mbp.local", ", such as mbp.local" + bonjour},
		{"build.corp.example.com.", nil, "build.corp.example.com", ", such as build.corp.example.com"},
		{"192.168.1.20", nil, "", ""},
		{"", nil, "", ""},
		{"mbp", errors.New("no name"), "", ""},
	} {
		hostnameIs(t, tc.host, tc.err)
		if name, like := networkName(), aNameLike(); name != tc.name || like != tc.like {
			t.Errorf("%q, %v: %q, %q", tc.host, tc.err, name, like)
		}
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
		name, path, err := saveProfile(dir, "chrome_155", measured, true)
		if err != nil || name != "chrome_155_"+tc.platform ||
			path != filepath.Join(dir, "chrome_155", tc.platform+".json") {
			t.Errorf("%s: saved %q at %s: %v", tc.platform, name, path, err)
		}
	}
}
