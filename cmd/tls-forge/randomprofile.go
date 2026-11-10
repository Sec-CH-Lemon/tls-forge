package main

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// wearable is what --random-profile draws from: every browser measured, shipped
// with tls-forge or kept on this machine, by the name it is filed under, that
// this build can wear. One a build cannot wear (made for another engine major,
// or a file that does not load) is left out, as the run would refuse it; the
// handshakes of tls-client's catalogue are left out too, having no headers of a
// browser's own. In name order, for a header and a log that read the same each
// run. Never none: the profiles tls-forge ships are among them, the newest
// Chrome a run wears without --profile with them.
func wearable() []*profile.Profile {
	var names []string
	for _, group := range profile.Default.Measured() {
		if len(group.Variants) == 0 {
			names = append(names, group.Name)
		}
		for _, v := range group.Variants {
			names = append(names, group.Name+"_"+v.Platform)
		}
	}
	var drawn []*profile.Profile
	for _, name := range names {
		if p, err := profile.Get(name); err == nil {
			drawn = append(drawn, p)
		}
	}
	sort.Slice(drawn, func(i, j int) bool { return drawn[i].Name < drawn[j].Name })
	return drawn
}

// pickProfile draws the profile of each request under --random-profile. Seeded
// from the clock, and named, so that a test can make the draws repeatable.
var pickProfile = rand.New(rand.NewSource(time.Now().UnixNano()))

// profileDraw is a run's profiles to draw from, one for each request it makes.
// Its workers draw at once, and a rand.Rand is not safe for that.
type profileDraw struct {
	mu   sync.Mutex
	from []*profile.Profile
}

// next is the profile of the next request.
func (d *profileDraw) next() *profile.Profile {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.from[pickProfile.Intn(len(d.from))]
}

// names are the profiles it draws from, by name.
func (d *profileDraw) names() []string {
	names := make([]string, len(d.from))
	for i, p := range d.from {
		names[i] = p.Name
	}
	return names
}

// randomReport is the header of a run that draws a profile for each request:
// how many it draws from and which, where they came from, and how many are
// another platform's than this machine's, whose TCP/IP a server reading it
// sees is this machine's.
func randomReport(errOut *printer, d *profileDraw, host string) *identityReport {
	said := &identityReport{errOut: errOut, open: true}
	errOut.println(identityRule)
	said.field("profile", fmt.Sprintf("random · each request wears one of %d, drawn for it", len(d.from)))
	said.field("profiles", strings.Join(d.names(), ", "))
	shipped, here, elsewhere := 0, 0, 0
	for _, p := range d.from {
		if p.Source() == "" {
			shipped++
		} else {
			here++
		}
		if _, platform := profile.Split(p.Name); platform != "" && platform != host {
			elsewhere++
		}
	}
	var from []string
	if shipped > 0 {
		from = append(from, fmt.Sprintf("%d shipped with tls-forge", shipped))
	}
	if here > 0 {
		from = append(from, fmt.Sprintf("%d kept on this machine", here))
	}
	said.field("from", strings.Join(from, ", "))
	if elsewhere > 0 {
		said.field("tcp/ip", fmt.Sprintf("this machine's, %s: %d of the %d are another platform's, and a server that "+
			"reads TCP/IP can tell those apart", platformLabel(host), elsewhere, len(d.from)))
	}
	return said
}
