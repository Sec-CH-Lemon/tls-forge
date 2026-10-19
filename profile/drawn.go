package profile

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// minDrawn is how many hellos a capture needs, its own and those of the other
// connections its page opened, for what its browser draws for every
// connection to be measured rather than said by its name.
const minDrawn = 16

// echTag is what the AEAD of a GREASE ECH payload adds to it: 16 bytes, for
// AES-128-GCM and ChaCha20-Poly1305 alike.
const echTag = 16

// boringECH are the lengths BoringSSL draws a GREASE ECH payload from, before
// the tag, each as likely: 32 times 4 to 7.
var boringECH = []uint16{128, 160, 192, 224}

// Drawn is what a browser drew anew for each connection, measured from the
// hellos of a capture: the measured one and those of the other connections
// its page opened (echo.WithManual).
type Drawn struct {
	// Hellos is how many it was measured from.
	Hellos int
	// Order says the order of the extensions moved from one hello to
	// another, those both carry compared.
	Order bool
	// ECH are the lengths of the GREASE ECH payloads seen on the wire, each
	// once, ascending; none without one.
	ECH []int
	// Sometimes are the extensions some of them carried and others did not,
	// ascending: what a profile cannot draw.
	Sometimes []uint16
}

// DrawnOf measures what the browser of a capture drew for each connection,
// or nil for a capture with too few hellos to tell. GREASE, padding and
// pre_shared_key are set aside: what is drawn for each, the length of the
// hello and a ticket decide.
func DrawnOf(c *capture.Capture) (*Drawn, error) {
	if len(c.Connections)+1 < minDrawn {
		return nil, nil
	}
	raws := append([][]byte{c.RawClientHello}, c.Connections...)
	d := &Drawn{Hellos: len(raws)}
	carried := map[uint16]int{}
	lengths := map[int]bool{}
	var first []uint16
	for i, raw := range raws {
		hello, err := fingerprint.ParseClientHello(raw)
		if err != nil {
			return nil, fmt.Errorf("profile: the hello of connection %d: %w", i, err)
		}
		order := slices.DeleteFunc(hello.ExtensionTypes(), func(t uint16) bool {
			return fingerprint.IsGREASE(t) || t == fingerprint.ExtPadding || t == fingerprint.ExtPreSharedKey
		})
		for _, t := range order {
			carried[t]++
		}
		if ech, ok := hello.EncryptedClientHello(); ok {
			lengths[ech.PayloadLength] = true
		}
		if i == 0 {
			first = order
			continue
		}
		if !slices.Equal(alsoIn(order, first), alsoIn(first, order)) {
			d.Order = true
		}
	}
	for _, t := range slices.Sorted(maps.Keys(carried)) {
		if carried[t] < d.Hellos {
			d.Sometimes = append(d.Sometimes, t)
		}
	}
	d.ECH = slices.Sorted(maps.Keys(lengths))
	return d, nil
}

// alsoIn is what of order other has too, in order's order.
func alsoIn(order, other []uint16) []uint16 {
	return slices.DeleteFunc(slices.Clone(order), func(t uint16) bool { return !slices.Contains(other, t) })
}

// perConnection is what a profile draws for every connection, as measured:
// the order of its extensions when it moved, and the length of its GREASE ECH
// payload, before the tag, when it varied. BoringSSL's four when every length
// seen is one of them, since a browser that draws from them draws each, and
// a page's hellos may not show all four; those seen otherwise.
func (d *Drawn) perConnection() *PerConnection {
	out := &PerConnection{ShufflesExtensions: d.Order}
	var lengths []uint16
	for _, length := range d.ECH {
		if length > echTag {
			lengths = append(lengths, uint16(length-echTag))
		}
	}
	switch {
	case len(lengths) < 2:
	case !slices.ContainsFunc(lengths, func(l uint16) bool { return !slices.Contains(boringECH, l) }):
		out.ECHPayloadLengths = slices.Clone(boringECH)
	default:
		out.ECHPayloadLengths = lengths
	}
	return out
}

// Resumption is how the browser of a capture resumed a session, against the
// hello it sent cold: tls-forge resumes as Chrome does, with the cold hello
// and pre_shared_key last, one ticket offered (withResumption).
type Resumption struct {
	// Measured says the capture has a resumed hello.
	Measured bool
	// Added are the extensions the resumed hello carries and the cold one
	// does not, pre_shared_key aside; Missing those it lacks. Ascending.
	Added, Missing []uint16
	// NotLast says pre_shared_key was not its last extension.
	NotLast bool
	// Identities is how many tickets it offered.
	Identities int
}

// AsTLSForge says the browser resumed as tls-forge resumes.
func (r Resumption) AsTLSForge() bool {
	return r.Measured && len(r.Added) == 0 && len(r.Missing) == 0 && !r.NotLast && r.Identities == 1
}

// ResumptionOf is how the browser of a capture resumed a session, against its
// cold hello; not Measured for a capture with no resumed hello.
func ResumptionOf(c *capture.Capture) (Resumption, error) {
	if len(c.ResumedClientHello) == 0 {
		return Resumption{}, nil
	}
	cold, err := c.Hello()
	if err != nil {
		return Resumption{}, fmt.Errorf("profile: %w", err)
	}
	resumed, err := fingerprint.ParseClientHello(c.ResumedClientHello)
	if err != nil {
		return Resumption{}, fmt.Errorf("profile: the resumed hello: %w", err)
	}
	set := func(hello *fingerprint.ClientHello) []uint16 {
		return slices.Sorted(slices.Values(slices.DeleteFunc(hello.ExtensionTypes(), func(t uint16) bool {
			return fingerprint.IsGREASE(t) || t == fingerprint.ExtPadding || t == fingerprint.ExtPreSharedKey
		})))
	}
	coldSet, resumedSet := set(cold), set(resumed)
	r := Resumption{Measured: true}
	for _, t := range resumedSet {
		if !slices.Contains(coldSet, t) {
			r.Added = append(r.Added, t)
		}
	}
	for _, t := range coldSet {
		if !slices.Contains(resumedSet, t) {
			r.Missing = append(r.Missing, t)
		}
	}
	types := resumed.ExtensionTypes()
	r.NotLast = len(types) == 0 || types[len(types)-1] != fingerprint.ExtPreSharedKey
	if psk, ok := resumed.PreSharedKey(); ok {
		r.Identities = psk.Identities
	}
	return r, nil
}
