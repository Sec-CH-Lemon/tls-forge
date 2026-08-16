package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

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
		{"batch", "--timeout", "1s", "--progress", "never", "--repeat", "0",
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
	report(newPrinter(said), "chrome_151_linux")

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

func TestTheReportNamesTheFileAProfileCameFrom(t *testing.T) {
	// "Which profile" is half an answer when several names resolve to one file
	// and one name can resolve to several files.
	installed(t)
	said := &strings.Builder{}
	report(newPrinter(said), localName)

	kept := filepath.Join(profile.Default.Dir(), localName, profile.HostPlatform()+".json")
	if !strings.Contains(said.String(), kept) {
		t.Errorf("the report does not name %s:\n%s", kept, said)
	}
	if !strings.Contains(said.String(), "measured on this machine") {
		t.Errorf("the report does not say it was measured here:\n%s", said)
	}
}

func TestTheReportIsSilentForAProfileThatDoesNotResolve(t *testing.T) {
	// The client is about to fail with a message that says so properly, and two
	// complaints about one mistake is one too many.
	said := &strings.Builder{}
	report(newPrinter(said), "no-such-profile")
	if said.String() != "" {
		t.Errorf("report = %q, want silence", said)
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
	report(newPrinter(said), elsewhere)
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
		"macos": "macOS", "windows": "Windows", "linux": "Linux", "plan9": "plan9",
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
