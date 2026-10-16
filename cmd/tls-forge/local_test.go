package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// resolved is the profile a name resolves to.
func resolved(t *testing.T, name string) *profile.Profile {
	t.Helper()
	p, err := profile.Get(name)
	if err != nil {
		t.Fatalf("resolving %s: %v", name, err)
	}
	return p
}

// installed captures the stand-in browser into a profile directory of this
// test's own, which is what having measured this machine looks like.
func installed(t *testing.T) {
	t.Helper()
	keepProfilesIn(t)
	if code, _, stderr := exec(t, "capture", "--browser", browserStandIn(t),
		"--timeout", "30s", "--install"); code != 0 {
		t.Fatalf("capture --install: %s", stderr)
	}
}

func TestARunPrefersTheBrowserMeasuredHere(t *testing.T) {
	// The point of having measured it. A shipped profile is a recording of
	// somebody else's browser on an earlier day; this one is the browser a
	// server would compare against.
	installed(t)
	_, _, stderr := exec(t, "fetch", "--timeout", "1s", "https://127.0.0.1:1/")
	if !strings.Contains(stderr, localName+"_"+profile.HostPlatform()) {
		t.Errorf("did not wear the local profile:\n%s", stderr)
	}
	if !strings.Contains(stderr, "measured on this machine") {
		t.Errorf("did not say where it came from:\n%s", stderr)
	}
}

func TestWithoutALocalProfileAShippedOneIsWorn(t *testing.T) {
	keepProfilesIn(t)
	_, _, stderr := exec(t, "fetch", "--timeout", "1s", "https://127.0.0.1:1/")
	if !strings.Contains(stderr, "shipped with tls-forge") {
		t.Errorf("did not fall back to a shipped profile:\n%s", stderr)
	}
	if strings.Contains(stderr, localName+"_") {
		t.Errorf("wore a local profile that does not exist:\n%s", stderr)
	}
}

func TestANamedProfileIsTakenAtItsWord(t *testing.T) {
	// Measured here or not, `--profile x` means x.
	installed(t)
	_, _, stderr := exec(t, "fetch", "--profile", "chrome_151_linux",
		"--timeout", "1s", "https://127.0.0.1:1/")
	if !strings.Contains(stderr, "chrome_151_linux") {
		t.Errorf("did not wear what was asked for:\n%s", stderr)
	}
}

func TestEveryCommandThatFetchesSaysWhatItIsWearing(t *testing.T) {
	// "Which browser am I pretending to be" is the one thing this program does
	// and the one thing that is otherwise invisible.
	keepProfilesIn(t)
	for _, args := range [][]string{
		{"fetch", "--timeout", "1s", "https://127.0.0.1:1/"},
		{"fetch", "--timeout", "1s", "--progress", "never", "--retry", "0",
			"-u", "https://127.0.0.1:1/"},
	} {
		t.Run(args[0], func(t *testing.T) {
			if _, _, stderr := exec(t, args...); !strings.Contains(stderr, "profile ") {
				t.Errorf("%s said nothing about its profile:\n%s", args[0], stderr)
			}
		})
	}
}

func TestTheListingAgreesWithWhatARunWears(t *testing.T) {
	// A listing that marked a shipped profile while every run wore the local
	// one would be worse than no listing.
	installed(t)
	_, stdout, _ := exec(t, "profiles")

	// The marked row reads "*   local_macos               <", so the name is the
	// field before the arrow, past whatever marker the row carries.
	var marked string
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-1] == "<" {
			marked = fields[len(fields)-2]
		}
	}
	want := localName + "_" + profile.HostPlatform()
	if marked != want {
		t.Errorf("the listing marks %q as the default, want %q\n%s", marked, want, stdout)
	}
}

func TestTheReportSaysWhatSomebodyNeedsToKnow(t *testing.T) {
	keepProfilesIn(t)
	said := &strings.Builder{}
	openReport(newPrinter(said), "chrome_151_linux", resolved(t, "chrome_151_linux")).close()

	// Which profile, which browser, which version, which platform, where the
	// file is, and the user-agent a server will actually read.
	for _, want := range []string{
		"chrome_151_linux", "shipped with tls-forge",
		"Chrome 151 on Linux", "built into tls-forge",
		"Chrome/151.0.0.0",
	} {
		if !strings.Contains(said.String(), want) {
			t.Errorf("the report does not mention %q:\n%s", want, said)
		}
	}
}

func TestTheReportSaysWhoseTCPIPARunHas(t *testing.T) {
	// A profile measured on another platform than this one: the run says the
	// connection under it is this machine's.
	keepProfilesIn(t)
	elsewhere := "linux"
	if profile.HostPlatform() == "linux" {
		elsewhere = "windows"
	}
	said := &strings.Builder{}
	openReport(newPrinter(said), "chrome_151_"+elsewhere, resolved(t, "chrome_151_"+elsewhere)).close()
	if !strings.Contains(said.String(), "tcp/ip") ||
		!strings.Contains(said.String(), "the profile is "+platformLabel(elsewhere)+"'s") {
		t.Errorf("the report does not say whose TCP/IP the run has:\n%s", said)
	}

	// This machine's own: nothing to say.
	said.Reset()
	openReport(newPrinter(said), "chrome_151_"+profile.HostPlatform(), resolved(t, "chrome_151_"+profile.HostPlatform())).close()
	if strings.Contains(said.String(), "tcp/ip") {
		t.Errorf("the report warned about a profile of this machine's platform:\n%s", said)
	}
}

func TestNetworkNote(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mine.json")
	if err := os.WriteFile(file, []byte(`{"name":"mine_windows","base":"chrome_133"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile, err := profile.Get(file)
	if err != nil {
		t.Fatalf("loading %s: %v", file, err)
	}
	named := func(name string) *profile.Profile { return &profile.Profile{Name: name} }

	for _, tc := range []struct {
		name    string
		asked   string
		profile *profile.Profile
		host    string
		want    string // empty: nothing to say
	}{
		{"this machine's platform", "chrome_155", named("chrome_155_macos"), "macos", ""},
		{"no platform in the name", "local", named("local"), "macos", ""},
		{"a catalogue entry", "firefox_148", named("firefox_148"), "linux", ""},
		{"another platform, asked for", "chrome_155_windows", named("chrome_155_windows"), "macos",
			"this machine's, macOS: the profile is Windows's"},
		{"another platform, because this one has no capture", "chrome_155", named("chrome_155_linux"), "freebsd",
			"this machine's, freebsd, which no capture of this browser is for: the profile is Linux's"},
		{"a family name that landed elsewhere", "chrome", named("chrome_155_windows"), "linux",
			"which no capture of this browser is for"},
		{"a file named as it is", file, fromFile, "macos", "this machine's, macOS: the profile is Windows's"},
		{"a phone's, measured by hand", "safari_18_ios", named("safari_18_ios"), "macos",
			"the profile is iOS's"},
	} {
		got := networkNote(tc.asked, tc.profile, tc.host)
		switch {
		case tc.want == "" && got != "":
			t.Errorf("%s: said %q, want nothing", tc.name, got)
		case tc.want != "" && !strings.Contains(got, tc.want):
			t.Errorf("%s: said %q, want %q in it", tc.name, got, tc.want)
		case tc.want != "" && !strings.HasSuffix(got, "a server that reads TCP/IP can tell the two apart"):
			t.Errorf("%s: said %q without why it matters", tc.name, got)
		}
	}
}

func TestTheReportNamesTheFileAProfileCameFrom(t *testing.T) {
	// "Which profile" is half an answer when several names resolve to one file
	// and one name can resolve to several files.
	installed(t)
	said := &strings.Builder{}
	openReport(newPrinter(said), localName, resolved(t, localName)).close()

	kept := filepath.Join(profile.Default.Dir(), localName, profile.HostPlatform()+".json")
	if !strings.Contains(said.String(), kept) {
		t.Errorf("the report does not name %s:\n%s", kept, said)
	}
	if !strings.Contains(said.String(), "measured on this machine") {
		t.Errorf("the report does not say it was measured here:\n%s", said)
	}
}

func TestTheReportStaysOpenForOneMoreLine(t *testing.T) {
	keepProfilesIn(t)
	said := &strings.Builder{}
	identity := openReport(newPrinter(said), "chrome_151_linux", resolved(t, "chrome_151_linux"))
	if strings.Count(said.String(), identityRule) != 1 {
		t.Fatalf("the report was closed before anyone asked:\n%s", said)
	}

	identity.field("exit-ip", "203.0.113.7")
	identity.close()
	// Asked twice, as fetch does on its way out, and ended once. Nothing joins
	// it afterwards either.
	identity.close()
	identity.field("late", "too late")

	lines := reportLines(said.String())
	last := len(lines) - 1
	if lines[last] != identityRule || lines[last-1] != "  exit-ip     203.0.113.7" {
		t.Errorf("the report does not end with the added line and one rule:\n%s", said)
	}
	if got := strings.Count(said.String(), identityRule); got != 2 {
		t.Errorf("the report has %d rules, want one above and one below:\n%s", got, said)
	}
	if strings.Contains(said.String(), "too late") {
		t.Errorf("a line was added to a report that had ended:\n%s", said)
	}
}

func TestAProfileGivenAsAPathSaysSo(t *testing.T) {
	// A file handed over directly can carry any name it likes, including one
	// this machine also keeps, so where it came from is read off the path.
	keepProfilesIn(t)
	elsewhere := filepath.Join(t.TempDir(), "mine.json")
	data, err := os.ReadFile("../../profile/data/chrome_151/linux.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elsewhere, data, 0o644); err != nil {
		t.Fatal(err)
	}

	said := &strings.Builder{}
	openReport(newPrinter(said), elsewhere, resolved(t, elsewhere)).close()
	if !strings.Contains(said.String(), "read from the file named") {
		t.Errorf("the report does not say where it came from:\n%s", said)
	}
	if !strings.Contains(said.String(), elsewhere) {
		t.Errorf("the report does not name the file:\n%s", said)
	}
}

func TestShortenPutsTheHomeDirectoryBack(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	inside := filepath.Join(home, "profiles", "x.json")
	if got := shorten(inside); got != filepath.Join("~", "profiles", "x.json") {
		t.Errorf("shorten(%q) = %q", inside, got)
	}
	// Anything not under it is left alone rather than mangled.
	outside := filepath.Join(t.TempDir(), "x.json")
	if got := shorten(outside); got != outside {
		t.Errorf("shorten(%q) = %q", outside, got)
	}
}

func TestPlatformLabel(t *testing.T) {
	for platform, want := range map[string]string{
		"macos": "macOS", "windows": "Windows", "linux": "Linux", "android": "Android", "ios": "iOS", "plan9": "plan9",
	} {
		if got := platformLabel(platform); got != want {
			t.Errorf("platformLabel(%q) = %q, want %q", platform, got, want)
		}
	}
}

func TestBrowserFrom(t *testing.T) {
	for _, tc := range []struct{ ua, family, major string }{
		{"… Chrome/151.0.0.0 Safari/537.36", "chrome", "151"},
		{"… Chrome/151.0.0.0 Edg/151.0.0.0", "edge", "151"},
		{"… Chrome/120.0.0.0 OPR/106.0.0.0", "opera", "106"},
		{"… Firefox/133.0", "firefox", "133"},
		{"… Version/18.1 Safari/605.1.15", "safari", "18"},
		// The phones' own names for themselves, ahead of what they are built on.
		{"… Chrome/138.0.0.0 Mobile Safari/537.36 EdgA/138.0.0.0", "edge", "138"},
		{"… Version/18.0 EdgiOS/138.0.3351.65 Mobile/15E148 Safari/604.1", "edge", "138"},
		{"… SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36", "samsung", "28"},
		{"… Chrome/134.0.0.0 YaBrowser/25.4.1.1027 Safari/537.36", "yandex", "25"},
		{"… CriOS/138.0.7204.156 Mobile/15E148 Safari/604.1", "chrome", "138"},
		{"… FxiOS/140.0 Mobile/15E148 Safari/605.1.15", "firefox", "140"},
		{"Mozilla/5.0 (compatible; Nobody/1.0)", "", ""},
		// A token with nothing after it: the family is known, the version is not.
		{"… Chrome/", "chrome", ""},
	} {
		family, major := browserFrom(tc.ua)
		if family != tc.family || major != tc.major {
			t.Errorf("browserFrom(%q) = %q, %q, want %q, %q", tc.ua, family, major, tc.family, tc.major)
		}
	}
}

func TestBrowserOfSaysNothingAboutABrowserItCannotRead(t *testing.T) {
	// Better a missing line than a confident wrong one: the user-agent is
	// printed in full underneath either way.
	if got := browserOf(&profile.Profile{Name: "x", UserAgent: "Nobody/1.0"}); got != "" {
		t.Errorf("browserOf = %q, want nothing", got)
	}
	// And the platform is only added when the name carries one.
	got := browserOf(&profile.Profile{Name: "mine", UserAgent: "… Chrome/151.0.0.0"})
	if got != "Chrome 151" {
		t.Errorf("browserOf = %q, want no platform on a name without one", got)
	}
}

func TestBrowserOfAPhone(t *testing.T) {
	for _, tc := range []struct{ name, ua, want string }{
		{"chrome_138_android", "… Chrome/138.0.0.0 Mobile Safari/537.36", "Chrome 138 on Android"},
		{"safari_18_ios", "… Version/18.5 Mobile/15E148 Safari/604.1", "Safari 18 on iOS"},
	} {
		if got := browserOf(&profile.Profile{Name: tc.name, UserAgent: tc.ua}); got != tc.want {
			t.Errorf("browserOf(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestARunWearingACatalogueProfileSaysWhatItLacks(t *testing.T) {
	// A handshake from the catalogue, with no headers of its own: the header of
	// the run says where it came from and what it goes without, rather than
	// claiming to have shipped with tls-forge.
	server := startEcho(t)
	code, _, stderr := exec(t, "fetch", "--insecure", "--profile", "firefox_148", server.URL()+"/api/all")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	for _, want := range []string{
		"profile     firefox_148 · from tls-client's catalogue: a handshake, and no headers",
		"from        tls-client's catalogue, built into tls-forge",
		"headers     none of its own: only those given with -H go out, and no User-Agent unless one is",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the run's header has no %q:\n%s", want, stderr)
		}
	}
	// A profile that has headers says nothing of the kind.
	_, _, stderr = exec(t, "fetch", "--insecure", server.URL()+"/api/all")
	if strings.Contains(stderr, "headers     none of its own") || strings.Contains(stderr, "catalogue") {
		t.Errorf("the default profile's header:\n%s", stderr)
	}
}
