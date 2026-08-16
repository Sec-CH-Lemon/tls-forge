package main

import (
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
	if !strings.Contains(stderr, "profile: "+localName+"_"+profile.HostPlatform()) {
		t.Errorf("did not wear the local profile:\n%s", stderr)
	}
	if !strings.Contains(stderr, "measured on this machine") {
		t.Errorf("did not say where it came from:\n%s", stderr)
	}
}

func TestWithoutALocalProfileAShippedOneIsWorn(t *testing.T) {
	keepProfilesIn(t)
	_, _, stderr := exec(t, "fetch", "--timeout", "1s", "https://127.0.0.1:1/")
	if !strings.Contains(stderr, "(shipped)") {
		t.Errorf("did not fall back to a shipped profile:\n%s", stderr)
	}
	if strings.Contains(stderr, "profile: "+localName) {
		t.Errorf("wore a local profile that does not exist:\n%s", stderr)
	}
}

func TestANamedProfileIsTakenAtItsWord(t *testing.T) {
	// Measured here or not, `--profile x` means x.
	installed(t)
	_, _, stderr := exec(t, "fetch", "--profile", "chrome_151_linux",
		"--timeout", "1s", "https://127.0.0.1:1/")
	if !strings.Contains(stderr, "profile: chrome_151_linux") {
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
			if _, _, stderr := exec(t, args...); !strings.Contains(stderr, "profile: ") {
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

func TestDescribe(t *testing.T) {
	// Silent for a name that resolves to nothing: the client is about to fail
	// with a message that says so properly.
	if got := describe("no-such-profile"); got != "" {
		t.Errorf("describe of an unknown profile = %q, want silence", got)
	}
	if got := describe("chrome_151_linux"); !strings.Contains(got, "Chrome 151") {
		t.Errorf("describe = %q, want the browser and version in it", got)
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
