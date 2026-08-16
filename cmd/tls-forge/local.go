package main

import (
	"os"
	"path/filepath"
	"strings"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// localName is what a profile measured from the browser on this machine is
// filed under.
//
// One name rather than one per version, because there is only ever one browser
// on a machine and its version is not the interesting part: `--profile local`
// means "whatever Chrome I have", and re-measuring after an update replaces it
// rather than leaving two. Version-named profiles are the ones that ship.
const localName = "local"

// wear settles which profile the run will use and says so.
//
// Preferring a locally measured profile over a shipped one is the whole point
// of having measured it: a shipped profile is a recording of somebody else's
// browser on an earlier day, and the one on this machine is the browser a
// server would compare against.
func (f clientFlags) wear(errOut *printer) {
	if !f.chose("profile") {
		*f.profile = defaultProfileName()
	}
	report(errOut, *f.profile)
}

// defaultProfileName is what a run wears when nobody names a profile: the
// browser measured on this machine if there is one, and a shipped profile
// otherwise.
//
// One function rather than the rule written twice, because the other place it
// is needed is the `profiles` listing, and a listing that pointed at a shipped
// profile while every run wore the local one would be worse than no listing.
func defaultProfileName() string {
	if profile.Default.HasHandshake(localName) {
		return localName
	}
	return tlsforge.DefaultProfile
}

// report says which browser this run is pretending to be.
//
// Every time, on stderr, because that is the one thing this program does and
// the one thing otherwise invisible: a run wearing a profile measured six
// months ago looks exactly like a run wearing the right one. The file is named
// because "which profile" is only half an answer when several can resolve to
// one name, and the user-agent in full because it is the part a server reads
// and the part a person can check at a glance.
func report(errOut *printer, name string) {
	p, err := profile.Get(name)
	if err != nil {
		// The client is about to fail with a message that says so properly, and
		// two complaints about one mistake is one too many.
		return
	}

	rule := strings.Repeat("─", 72)
	errOut.println(rule)
	field := func(label, value string) {
		if value != "" {
			errOut.printf("  %-11s %s\n", label, value)
		}
	}
	field("profile", p.Name+" · "+origin(p))
	field("browser", browserOf(p))
	field("from", from(p))
	field("user-agent", p.UserAgent)
	errOut.println(rule)
}

// origin says whether this was measured here or came with the binary, which is
// the difference between wearing this machine's browser and wearing a recording
// of somebody else's.
//
// Decided by where the file actually is rather than by its name, because a
// profile handed over as a path can carry any name it likes, including one this
// machine also keeps.
func origin(p *profile.Profile) string {
	switch dir := profile.Default.Dir(); {
	case p.Source() == "":
		return "shipped with tls-forge"
	case dir != "" && strings.HasPrefix(p.Source(), dir+string(filepath.Separator)):
		return "measured on this machine"
	}
	return "read from the file named"
}

// from is where the profile was read, and says so even when there is no file:
// "inside the binary" is an answer, and a blank line is not.
func from(p *profile.Profile) string {
	if p.Source() == "" {
		return "built into tls-forge"
	}
	return shorten(p.Source())
}

// browserOf reads the browser, its version and the platform out of a profile,
// as a line a person can take in without parsing a user-agent.
func browserOf(p *profile.Profile) string {
	family, version := browserFrom(p.UserAgent)
	if family == "" {
		return ""
	}
	said := strings.ToUpper(family[:1]) + family[1:]
	if version != "" {
		said += " " + version
	}
	if _, platform := profile.Split(p.Name); platform != "" {
		said += " on " + platformLabel(platform)
	}
	return said
}

// platformLabel spells a platform the way its makers do, since this line is for
// reading rather than for matching.
func platformLabel(platform string) string {
	switch platform {
	case "macos":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return platform
}

// shorten puts the home directory back as ~, because the interesting half of
// the path is the end of it and the beginning is the same on every line
// somebody has ever read.
func shorten(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(path, home+string(filepath.Separator)) {
		return path
	}
	return "~" + path[len(home):]
}
