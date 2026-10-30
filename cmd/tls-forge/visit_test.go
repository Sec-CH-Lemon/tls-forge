package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// aPerson is what the stand-in person at a browser does at its page: what
// its script reports back (navigator, the JSON /collect takes: what a
// browser's script says of it) and the client hints its report comes with
// (hints, names and values in turn, the page having asked for every one),
// whether it first opens the connections the page asks for, and whether it
// then makes the HTTP/1.1 visit or finishes without it.
type aPerson struct {
	navigator string
	hints     []string
	connects  bool
	http1     bool
}

// visitAsAPerson does at the address what a person is told to: opens it,
// which only says what to do next; opens it again, as if in a new tab; and
// lets the page report back. When connects says so, the page first opens the
// connections it asks for, as a browser's does: each once the server has ended
// the one before, then one given a ticket and one that resumes it. Then it
// opens the HTTP/1.1 address the page gives, twice, the first visit there only
// saying what to do next; or, without http1, finishes without it.
func visitAsAPerson(address, profileName string, p aPerson) error {
	// Its requests without a browser context go as given: the report it
	// posts carries client hints, which no page's script may set.
	worn, err := profile.Get(profileName)
	if err != nil {
		return err
	}
	worn.Behavior["http.instance_scope"] = json.RawMessage(`"client"`)
	worn.Behavior["headers.without_context"] = json.RawMessage(`"as-given"`)
	client, err := tlsforge.New(tlsforge.WithProfileValue(worn), tlsforge.WithInsecureSkipVerify(),
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
	said := func(marker, end string) string {
		at := strings.Index(page.Text(), marker) + len(marker)
		return page.Text()[at : at+strings.Index(page.Text()[at:], end)]
	}
	origin := strings.TrimSuffix(address, "/")
	if p.connects {
		hellos, err := strconv.Atoi(said("const hellos = ", ";"))
		if err != nil {
			return err
		}
		hello := origin + said("const hello = '", "'")
		say := func(what string) error {
			client.CloseIdleConnections()
			_, err := client.Do(&tlsforge.Request{URL: hello + what})
			return err
		}
		for i := range hellos {
			if err := say("&i=" + strconv.Itoa(i)); err != nil {
				return err
			}
		}
		for _, what := range []string{"&step=tickets", "&i=" + strconv.Itoa(hellos), "&step=resumed"} {
			if err := say(what); err != nil {
				return err
			}
		}
		client.CloseIdleConnections()
	}
	collect := said(marker, "'")
	if _, err := client.Do(&tlsforge.Request{
		Method: "POST", URL: origin + collect, Body: []byte(p.navigator),
		Header: tlsforge.NewHeader(append([]string{"content-type", "application/json"}, p.hints...)...),
	}); err != nil {
		return err
	}
	if !p.http1 {
		_, err := client.Do(&tlsforge.Request{URL: origin + "/skip?navigation=" + strings.TrimPrefix(collect, "/collect?navigation=")})
		return err
	}
	http1 := said("const http1Address = '", "'")
	for range 2 {
		if _, err := client.Do(&tlsforge.Request{URL: http1, Header: opened}); err != nil {
			return err
		}
	}
	return nil
}

// aPersonVisits is a person at the browser the next manual measurement waits
// for, wearing a profile, reporting nothing of note and finishing without
// HTTP/1.1; what came of the visit arrives on the channel.
func aPersonVisits(t *testing.T, profileName string) <-chan error {
	t.Helper()
	return aPersonVisitsAs(t, profileName, aPerson{navigator: `{}`})
}

// aPersonVisitsAs is aPersonVisits doing what p says.
func aPersonVisitsAs(t *testing.T, profileName string, p aPerson) <-chan error {
	t.Helper()
	visited := make(chan error, 1)
	previous := visitorReady
	visitorReady = func(address string) {
		go func() { visited <- visitAsAPerson(address, profileName, p) }()
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
	version = "manual_" + version
	written := filepath.Join(dir, version, platform+".json")
	data, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("nothing was written to %s:\n%s", written, stdout)
	}
	saved, err := profile.Load(data)
	if err != nil || saved.Name != version+"_"+platform || saved.HTTP1 == nil || len(saved.ClientHello) == 0 {
		t.Fatalf("saved %+v, %v", saved, err)
	}
	if _, err := saved.ClientProfile(); err != nil {
		t.Errorf("the saved profile cannot be used: %v", err)
	}
}

func TestCaptureManualKeepsTheClientHintsTheBrowserSent(t *testing.T) {
	// Its page asked for every one, and what its report came with is what
	// the profile says, over what the browser told its script; the summary
	// says how many.
	visited := aPersonVisitsAs(t, "chrome", aPerson{
		navigator: `{"full_version_list":[{"brand":"Chromium","version":"1"}],"architecture":"told"}`,
		hints:     []string{"sec-ch-ua-arch", `"x86"`, "device-memory", "8", "sec-ch-ua-platform-version", `"19.0.0"`},
	})
	dir := t.TempDir()
	code, stdout, stderr := exec(t, "capture", "--manual", "--save", dir)
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	version, platform := theVisitorsPlatform(t)
	data, err := os.ReadFile(filepath.Join(dir, "manual_"+version, platform+".json"))
	if err != nil {
		t.Fatalf("nothing was written:\n%s", stdout)
	}
	saved, err := profile.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := map[string]string{}
	for _, hint := range saved.ClientHints {
		got[hint.Name] = hint.Value
	}
	if got["sec-ch-ua-arch"] != `"x86"` || got["sec-ch-ua-platform-version"] != `"19.0.0"` || got["device-memory"] == "8" {
		t.Fatalf("persona not measured, or request context frozen: %v", got)
	}
	if !strings.Contains(stdout, "client hints     3 of the 21 a server asks for, sent when asked") {
		t.Errorf("the summary:\n%s", stdout)
	}
}

func TestCaptureManualInstallsUnderTheBrowsersName(t *testing.T) {
	// Not as "local": that is this machine's own browser, and a browser a person
	// opened is another one, which its own name then finds. A Chromium browser
	// is named by its brands: Brave's user agent is Chrome's.
	dir := keepProfilesIn(t)
	visited := aPersonVisitsAs(t, "chrome", aPerson{
		navigator: `{"brands": [{"brand": "Brave", "version": "155"}, {"brand": "Chromium", "version": "155"}]}`})
	code, stdout, stderr := exec(t, "capture", "--manual", "--install", "--policy-from", "chrome_155_macos", "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	_, platform := theVisitorsPlatform(t)
	if code != 0 || !strings.Contains(stdout, "--profile manual_brave_155_"+platform) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "manual_brave_155", platform+".json")); err != nil {
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
	if code != 0 || !strings.Contains(stdout, "--profile manual_"+version+"_"+platform) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	before, err := profile.Get("chrome")
	if err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry()
	registry.SetDir(dir)
	after, err := registry.Get("chrome")
	if err != nil || before.Name != after.Name || before.UserAgent != after.UserAgent {
		t.Fatalf("manual capture changed chrome: %+v %v", after, err)
	}
	if _, err := os.Stat(filepath.Join(dir, version)); !os.IsNotExist(err) {
		t.Errorf("implicit capture touched shipped name: %v", err)
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
	for i := range measured.HTTP2.Headers {
		if measured.HTTP2.Headers[i].Name == "user-agent" {
			measured.HTTP2.Headers[i].Value = measured.Navigator.UserAgent
		}
	}
	if _, _, err := saveProfile(t.TempDir(), "chrome_155", measured, false, nil); err == nil {
		t.Fatal("unmeasured mobile policy basis silently selected")
	}
	if saved, _, err := saveProfile(t.TempDir(), "chrome_155", measured, false, nil, "chrome_155_macos"); err != nil || saved.Name != "chrome_155_android" {
		t.Errorf("a phone's: %+v, %v", saved, err)
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
		if code != tc.code || !strings.Contains(stdout, "HTTP/1.1 was not measured from the browser you opened") ||
			!strings.Contains(stderr, "waiting for a browser at") || !strings.Contains(stderr, "4. Its page then gives a second address, https://localhost:") {
			t.Errorf("%s: exit code = %d\n%s\n%s", tc.profile, code, stdout, stderr)
		}
	}
	// Measured over HTTP/1.1 too, it is compared over HTTP/1.1 too.
	visited := aPersonVisitsAs(t, "chrome", aPerson{navigator: `{}`, http1: true})
	code, stdout, stderr := exec(t, "compare", "--manual", "--color", "never", "--profile", "chrome", "--full")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || strings.Contains(stdout, "HTTP/1.1 was not measured") || !strings.Contains(stdout, "http1_header_order") {
		t.Errorf("over HTTP/1.1 too: exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	// As JSON, without a word in front of the document.
	visited = aPersonVisits(t, "chrome")
	code, stdout, _ = exec(t, "compare", "--manual", "--json")
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
		// The wire UA is authoritative. Simulate a coherent visitor instead
		// of a navigator report contradicting an actual desktop request.
		for i := range measured.HTTP2.Headers {
			if strings.EqualFold(measured.HTTP2.Headers[i].Name, "user-agent") {
				measured.HTTP2.Headers[i].Value = tc.ua
			}
		}
		if measured.HTTP1 != nil {
			for i := range measured.HTTP1.Headers {
				if strings.EqualFold(measured.HTTP1.Headers[i].Name, "user-agent") {
					measured.HTTP1.Headers[i].Value = tc.ua
				}
			}
		}
		dir := t.TempDir()
		if _, _, err := saveProfile(dir, "chrome_155", measured, true, nil); err == nil {
			t.Fatal("unshipped platform silently selected a policy basis")
		}
		saved, path, err := saveProfile(dir, "chrome_155", measured, true, nil, "chrome_155_macos")
		if err != nil || saved.Name != "chrome_155_"+tc.platform ||
			path != filepath.Join(dir, "chrome_155", tc.platform+".json") {
			t.Errorf("%s: saved at %s: %v", tc.platform, path, err)
		}
	}
}

func TestCaptureManualMeasuresWhatTheBrowserDrawsForEachConnection(t *testing.T) {
	// The page's connections say what the browser draws for each, and how it
	// resumes: the profile draws what was measured. The person wears Chrome's
	// profile, which tls-forge draws as Chrome does, and resumes as it does.
	visited := aPersonVisitsAs(t, "chrome", aPerson{navigator: `{}`, connects: true})
	dir := t.TempDir()
	code, stdout, stderr := exec(t, "capture", "--manual", "--save", dir, "--timeout", "60s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.Contains(stdout, "per connection   the order of its extensions drawn for each, a GREASE ECH payload of ") ||
		!strings.Contains(stdout, " bytes (27 hellos)") ||
		!strings.Contains(stdout, "resumed          as tls-forge resumes: the hello it sent cold, and pre_shared_key last") ||
		strings.Contains(stdout, "not every time") {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	version, platform := theVisitorsPlatform(t)
	data, err := os.ReadFile(filepath.Join(dir, "manual_"+version, platform+".json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := profile.Load(data)
	if err != nil || saved.PerConnection == nil || !saved.PerConnection.ShufflesExtensions ||
		len(saved.PerConnection.ECHPayloadLengths) != 4 || strings.Contains(saved.Notes, "not in every hello") ||
		strings.Contains(saved.Notes, "resumed otherwise") {
		t.Errorf("saved %+v, %q, %v", saved.PerConnection, saved.Notes, err)
	}
}

func TestWhatWasDrawnAndHowItResumedAreSaid(t *testing.T) {
	for _, tc := range []struct {
		drawn *profile.Drawn
		err   error
		want  string
	}{
		{nil, errors.New("broken"), "not measured: broken"},
		{nil, nil, "not measured: too few connections"},
		{&profile.Drawn{Hellos: 20}, nil, "its extensions in one order (20 hellos)"},
		{&profile.Drawn{Hellos: 20, ECH: []int{208}}, nil, "its extensions in one order, a GREASE ECH payload of 208 bytes every time (20 hellos)"},
		{&profile.Drawn{Hellos: 27, Order: true, ECH: []int{144, 240}}, nil,
			"the order of its extensions drawn for each, a GREASE ECH payload of 144, 240 bytes (27 hellos)"},
	} {
		if got := drawnSaid(tc.drawn, tc.err); got != tc.want {
			t.Errorf("%+v, %v: %q", tc.drawn, tc.err, got)
		}
	}
	for _, tc := range []struct {
		r    profile.Resumption
		err  error
		want string
	}{
		{profile.Resumption{}, errors.New("broken"), "not read: broken"},
		{profile.Resumption{}, nil, "it resumed none of the sessions it was given"},
		{profile.Resumption{Measured: true, Identities: 1}, nil, "as tls-forge resumes: the hello it sent cold, and pre_shared_key last"},
		{profile.Resumption{Measured: true, Added: []uint16{42}, Missing: []uint16{0, 16}, NotLast: true}, nil,
			"otherwise than tls-forge resumes: adds " + fingerprint.ExtensionName(42) + ", lacks server_name, alpn, " +
				"pre_shared_key not last, offers 0 tickets"},
		{profile.Resumption{Measured: true, Identities: 2}, nil, "otherwise than tls-forge resumes: offers 2 tickets"},
	} {
		if got := resumptionSaid(tc.r, tc.err); got != tc.want {
			t.Errorf("%+v, %v: %q", tc.r, tc.err, got)
		}
	}
}

func TestTheClientHintsABrowserSentAreSaid(t *testing.T) {
	// How many of those a server asks for it sent; that it sent none of them,
	// the unasked alone; and nothing of a capture that kept none.
	for _, tc := range []struct {
		sent []capture.HeaderField
		want string
	}{
		{[]capture.HeaderField{{Name: "sec-ch-ua", Value: "x"}, {Name: "dpr", Value: "2"}},
			"client hints     1 of the 21 a server asks for, sent when asked"},
		{[]capture.HeaderField{{Name: "sec-ch-ua", Value: "x"}, {Name: "sec-ch-ua-platform", Value: "y"}},
			"client hints     none of those a server asks for, though asked"},
		{nil, ""},
	} {
		var out bytes.Buffer
		printCapture(newPrinter(&out), &capture.Capture{ClientHints: tc.sent})
		got := ""
		for line := range strings.Lines(out.String()) {
			if strings.Contains(line, "client hints") {
				got = strings.TrimSpace(line)
			}
		}
		if got != tc.want {
			t.Errorf("%v: %q", tc.sent, got)
		}
	}
}

func TestAProfileNotesWhatItCannotSay(t *testing.T) {
	// An extension some hellos carry and others do not, and a resumption
	// otherwise than tls-forge's, are said beside the profile; a capture
	// whose page opened too few connections is said to be one.
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome"))
	if err != nil {
		t.Fatalf("MeasureSelf: %v", err)
	}
	for range 20 {
		measured.Connections = append(measured.Connections, measured.RawClientHello)
	}
	measured.Connections[4] = withRawExtension(t, measured.RawClientHello, 42)
	measured.ResumedClientHello = withRawExtension(t, measured.RawClientHello, 42)
	_, path, err := saveProfile(filepath.Join(t.TempDir(), "p.json"), "chrome_155", measured, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := profile.Load(data)
	early := fingerprint.ExtensionName(42)
	if err != nil || !strings.Contains(saved.Notes, "; not in every hello: "+early) ||
		!strings.Contains(saved.Notes, "; resumed otherwise than tls-forge resumes: adds "+early) {
		t.Errorf("notes %q, %v", saved.Notes, err)
	}
	var out bytes.Buffer
	printCapture(newPrinter(&out), measured)
	if !strings.Contains(out.String(), "not every time   "+early+": in some of its hellos only") {
		t.Errorf("summary:\n%s", out.String())
	}
	// Without the connections a page opens, nothing of them is said.
	plain := *measured
	plain.Connections, plain.ResumedClientHello = nil, nil
	out.Reset()
	printCapture(newPrinter(&out), &plain)
	if strings.Contains(out.String(), "per connection") || strings.Contains(out.String(), "resumed") {
		t.Errorf("summary of a launched browser's:\n%s", out.String())
	}
	measured.Connections = measured.Connections[:2]
	out.Reset()
	printCapture(newPrinter(&out), measured)
	if !strings.Contains(out.String(), "per connection   not measured: too few connections") {
		t.Errorf("summary:\n%s", out.String())
	}
}

// withRawExtension is raw, a ClientHello's record, with an empty extension of
// type typ after its others.
func withRawExtension(t *testing.T, raw []byte, typ uint16) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	read := func(at, n int) int {
		v := 0
		for _, b := range out[at : at+n] {
			v = v<<8 | int(b)
		}
		return v
	}
	put := func(at, n, v int) {
		for i := range n {
			out[at+n-1-i] = byte(v >> (8 * i))
		}
	}
	at := 5 + 4 + 2 + 32
	at += 1 + read(at, 1)
	at += 2 + read(at, 2)
	at += 1 + read(at, 1)
	out = append(out, byte(typ>>8), byte(typ), 0, 0)
	put(at, 2, read(at, 2)+4)
	put(5+1, 3, read(5+1, 3)+4)
	put(3, 2, read(3, 2)+4)
	return out
}

func TestCaptureManualMeasuresHTTP1ByAVisitOfItsOwn(t *testing.T) {
	// The page's second address, opened as the first was, gives the profile
	// the browser's HTTP/1.1 as it sent it: spelt as Chrome spells it.
	visited := aPersonVisitsAs(t, "chrome", aPerson{navigator: `{}`, http1: true})
	dir := t.TempDir()
	code, stdout, stderr := exec(t, "capture", "--manual", "--save", dir, "--timeout", "30s")
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.Contains(stdout, "HTTP/1.1 order") {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	version, platform := theVisitorsPlatform(t)
	data, err := os.ReadFile(filepath.Join(dir, "manual_"+version, platform+".json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := profile.Load(data)
	if err != nil || saved.HTTP1 == nil || len(saved.HTTP1.HeaderOrder) == 0 {
		t.Fatalf("saved %+v, %v", saved.HTTP1, err)
	}
	if _, err := saved.ClientProfile(); err != nil {
		t.Errorf("the saved profile cannot be used: %v", err)
	}
}
