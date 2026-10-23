package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v6"
	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
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
	f.wearOpen(errOut).close()
}

// wearOpen is wear with the report left open, for a command that has a line of
// its own to end it with.
//
// Left open rather than printed late. What fetch adds needs a client to ask,
// and a run that fails before it has one should still have said what it was
// wearing. The profile is the one the run resolved, by the name it was asked
// for.
func (f clientFlags) wearOpen(errOut *printer) *identityReport {
	return openReport(errOut, *f.profile, f.run.profile)
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

// identityRule is drawn above and below the report of what a run is wearing.
var identityRule = strings.Repeat("─", 72)

// identityReport is what a run says it is wearing, while there is still room
// for one more line.
type identityReport struct {
	errOut *printer
	open   bool
}

// openReport says which browser this run is pretending to be, p, which it was
// asked for as name, and leaves the closing rule to whoever asked.
//
// Every time, on stderr, because that is the one thing this program does and
// the one thing otherwise invisible: a run wearing a profile measured six
// months ago looks exactly like a run wearing the right one. The file is named
// because "which profile" is only half an answer when several can resolve to
// one name, and the user-agent in full because it is the part a server reads
// and the part a person can check at a glance.
func openReport(errOut *printer, name string, p *profile.Profile) *identityReport {
	said := &identityReport{errOut: errOut, open: true}
	errOut.println(identityRule)
	said.field("profile", p.Name+" · "+origin(p))
	said.field("browser", browserOf(p))
	said.field("tcp/ip", networkNote(name, p, profile.HostPlatform()))
	said.field("from", from(p))
	said.field("user-agent", p.UserAgent)
	if len(p.Headers) == 0 {
		// A handshake from the catalogue, or a hand-written profile that names
		// none: the run would otherwise look like it wears a browser's headers.
		said.field("headers", "none of its own: only those given with -H go out, and no User-Agent unless one is")
	}
	return said
}

// field is one line of the report. A value nobody has is a line nobody needs.
func (r *identityReport) field(label, value string) {
	if r.open && value != "" {
		r.errOut.printf("  %-11s %s\n", label, value)
	}
}

// close ends the report, once, however many times it is asked.
//
// Fetch asks twice: when it has said everything, and again on its way out, so
// that a run which stops before then ends its report as well.
func (r *identityReport) close() {
	if !r.open {
		return
	}
	r.open = false
	r.errOut.println(identityRule)
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
	case fromCatalogue(p):
		return "from tls-client's catalogue: a handshake, and no headers"
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
	switch {
	case fromCatalogue(p):
		return "tls-client's catalogue, built into tls-forge"
	case p.Source() == "":
		return "built into tls-forge"
	}
	return shorten(p.Source())
}

// fromCatalogue says a profile is a bare name out of the transport's catalogue:
// read from no file, measured from no browser, borrowing its handshake.
func fromCatalogue(p *profile.Profile) bool {
	return p.Source() == "" && len(p.ClientHello) == 0 && p.Base != ""
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

// networkNote is what a profile cannot change, said when it matters: the
// TCP/IP a connection is made with is this machine's, whatever platform the
// profile was measured on. A server that reads the first packets of a
// connection (their TTL, window and options) sees this machine's operating
// system behind the profile's user-agent, so a run that wears another
// platform's profile is told so.
//
// And told when it did not ask for one: a version named without a platform is
// this machine's capture when there is one and another platform's when there
// is not, which nothing else on the screen would reveal. A profile named by
// its file was chosen as it is.
func networkNote(asked string, p *profile.Profile, host string) string {
	_, platform := profile.Split(p.Name)
	if platform == "" || platform == host {
		return ""
	}
	_, named := profile.Split(asked)
	if named != "" || asked == p.Source() {
		return fmt.Sprintf("this machine's, %s: the profile is %s's, and a server that reads TCP/IP can tell the two apart",
			platformLabel(host), platformLabel(platform))
	}
	return fmt.Sprintf("this machine's, %s, which no capture of this browser is for: the profile is %s's, "+
		"and a server that reads TCP/IP can tell the two apart", platformLabel(host), platformLabel(platform))
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
	case "android":
		return "Android"
	case "ios":
		return "iOS"
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
