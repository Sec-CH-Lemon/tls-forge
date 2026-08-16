package main

import (
	"fmt"
	"slices"
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
//
// It says so every time, on stderr, because "which browser am I pretending to
// be" is the one thing this program does and the one thing that is otherwise
// invisible. A run that quietly wore a profile from six months ago would look
// exactly like a run that wore the right one.
func (f clientFlags) wear(errOut *printer) {
	if !f.chose("profile") {
		*f.profile = defaultProfileName()
	}
	if said := describe(*f.profile); said != "" {
		errOut.println(said)
	}
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

// describe names the profile, the browser it was taken from and where it came
// from, in one line.
//
// Silent when the name resolves to nothing: the client is about to fail with a
// message that says so properly, and two complaints about one mistake is one
// too many.
func describe(name string) string {
	p, err := profile.Get(name)
	if err != nil {
		return ""
	}

	browser := "an unrecognised browser"
	if family, version := browserFrom(p.UserAgent); family != "" {
		browser = strings.ToUpper(family[:1]) + family[1:]
		if version != "" {
			browser += " " + version
		}
	}

	origin := "shipped"
	if slices.Contains(profile.Default.KeptHere(), p.Name) {
		origin = "measured on this machine"
	}
	return fmt.Sprintf("profile: %s — %s (%s)", p.Name, browser, origin)
}
