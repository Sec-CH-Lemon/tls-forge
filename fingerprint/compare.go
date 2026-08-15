package fingerprint

import (
	"fmt"
	"sort"
	"strings"
)

// Difference is one way in which a candidate handshake failed to be the
// reference handshake.
//
// It carries both sides and, where a list is involved, which entries are
// missing and which are extra — because "the JA4 differs" is a fact nobody can
// act on, while "you are not sending mldsa44" is a fix.
type Difference struct {
	Field     string
	Reference string
	Candidate string
	Missing   []string
	Extra     []string
}

func (d Difference) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n    browser: %s\n    client:  %s", d.Field, d.Reference, d.Candidate)
	if len(d.Missing) > 0 {
		fmt.Fprintf(&b, "\n    missing: %s", strings.Join(d.Missing, ", "))
	}
	if len(d.Extra) > 0 {
		fmt.Fprintf(&b, "\n    extra:   %s", strings.Join(d.Extra, ", "))
	}
	return b.String()
}

// Report is the outcome of comparing a candidate against a reference.
type Report struct {
	Differences []Difference
}

// OK reports a candidate indistinguishable from the reference on every field
// compared.
func (r Report) OK() bool { return len(r.Differences) == 0 }

func (r Report) String() string {
	if r.OK() {
		return "no differences"
	}
	parts := make([]string, len(r.Differences))
	for i, d := range r.Differences {
		parts[i] = d.String()
	}
	return strings.Join(parts, "\n")
}

// CompareTLS diffs a candidate ClientHello against a reference one, usually a
// real browser's.
//
// Two fields are deliberately NOT compared, and leaving them out is what makes
// the result meaningful:
//
//   - Extension ORDER. Chrome shuffles it on every connection, so the browser
//     does not match itself. The extension SET is compared instead, which is
//     what JA4 hashes and what a server can actually rely on.
//   - GREASE values. Random per connection by design (RFC 8701).
//
// Everything else — ciphers in order, groups in order, signature algorithms in
// order, key shares, ALPN, ALPS, versions, point formats, certificate
// compression — is stable for a given browser build and is compared exactly.
func CompareTLS(reference, candidate *ClientHello) Report {
	var diffs []Difference
	add := func(d *Difference) {
		if d != nil {
			diffs = append(diffs, *d)
		}
	}

	add(diffValue("ja4", reference.JA4(), candidate.JA4()))
	add(diffOrdered("cipher_suites", namesOf(withoutGREASE(reference.CipherSuites), CipherName),
		namesOf(withoutGREASE(candidate.CipherSuites), CipherName)))
	// Set, not sequence: see the note above.
	add(diffSet("extensions", namesOf(withoutGREASE(reference.ExtensionTypes()), ExtensionName),
		namesOf(withoutGREASE(candidate.ExtensionTypes()), ExtensionName)))
	add(diffOrdered("supported_versions", namesOf(withoutGREASE(reference.SupportedVersions()), VersionName),
		namesOf(withoutGREASE(candidate.SupportedVersions()), VersionName)))
	add(diffOrdered("supported_groups", namesOf(withoutGREASE(reference.SupportedGroups()), GroupName),
		namesOf(withoutGREASE(candidate.SupportedGroups()), GroupName)))
	add(diffOrdered("signature_algorithms", namesOf(withoutGREASE(reference.SignatureAlgorithms()), SignatureName),
		namesOf(withoutGREASE(candidate.SignatureAlgorithms()), SignatureName)))
	add(diffOrdered("key_share_groups", namesOf(withoutGREASE(reference.KeyShareGroups()), GroupName),
		namesOf(withoutGREASE(candidate.KeyShareGroups()), GroupName)))
	add(diffOrdered("alpn", reference.ALPN(), candidate.ALPN()))
	add(diffOrdered("application_settings", reference.ApplicationSettings(), candidate.ApplicationSettings()))
	add(diffOrdered("ec_point_formats", decimalStrings(reference.ECPointFormats()),
		decimalStrings(candidate.ECPointFormats())))
	add(diffOrdered("psk_key_exchange_modes", decimalStrings(reference.PSKKeyExchangeModes()),
		decimalStrings(candidate.PSKKeyExchangeModes())))
	add(diffOrdered("compress_certificate", decimalStrings16(reference.CertCompressionAlgorithms()),
		decimalStrings16(candidate.CertCompressionAlgorithms())))

	return Report{Differences: diffs}
}

// CompareHTTP2 diffs the connection preamble and the request headers.
//
// Header VALUES are not compared here: they are the caller's to choose and vary
// per request (referer, cookie, sec-fetch-*). What is compared is the shape a
// library controls and usually gets wrong — settings, their order, the window
// update, the pseudo-header order and the header order.
func CompareHTTP2(reference, candidate *HTTP2) Report {
	var diffs []Difference
	add := func(d *Difference) {
		if d != nil {
			diffs = append(diffs, *d)
		}
	}

	add(diffValue("http2_akamai", reference.Akamai(), candidate.Akamai()))
	add(diffOrdered("http2_settings", settingStrings(reference.Settings), settingStrings(candidate.Settings)))
	add(diffValue("http2_window_update", fmt.Sprint(reference.WindowUpdate), fmt.Sprint(candidate.WindowUpdate)))
	add(diffOrdered("pseudo_header_order", reference.PseudoHeaderOrder(), candidate.PseudoHeaderOrder()))
	add(diffOrdered("header_order", reference.HeaderOrder(), candidate.HeaderOrder()))

	return Report{Differences: diffs}
}

func diffValue(field, reference, candidate string) *Difference {
	if reference == candidate {
		return nil
	}
	return &Difference{Field: field, Reference: reference, Candidate: candidate}
}

// diffOrdered compares two sequences exactly, and additionally reports set
// membership so a caller can tell "wrong order" from "wrong contents" — the two
// have completely different fixes.
func diffOrdered(field string, reference, candidate []string) *Difference {
	if equalStrings(reference, candidate) {
		return nil
	}
	return &Difference{
		Field:     field,
		Reference: render(reference),
		Candidate: render(candidate),
		Missing:   subtract(reference, candidate),
		Extra:     subtract(candidate, reference),
	}
}

// diffSet ignores order entirely.
func diffSet(field string, reference, candidate []string) *Difference {
	missing, extra := subtract(reference, candidate), subtract(candidate, reference)
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	return &Difference{
		Field:     field,
		Reference: render(sorted(reference)),
		Candidate: render(sorted(candidate)),
		Missing:   missing,
		Extra:     extra,
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// subtract returns the entries of a that b does not have, counting duplicates:
// a client that sends a cipher twice differs from one that sends it once.
func subtract(a, b []string) []string {
	remaining := make(map[string]int, len(b))
	for _, v := range b {
		remaining[v]++
	}
	var out []string
	for _, v := range a {
		if remaining[v] > 0 {
			remaining[v]--
			continue
		}
		out = append(out, v)
	}
	return out
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func render(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func decimalStrings(values []uint8) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprint(v)
	}
	return out
}

func decimalStrings16(values []uint16) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprint(v)
	}
	return out
}

func settingStrings(settings []Setting) []string {
	out := make([]string, len(settings))
	for i, s := range settings {
		out[i] = fmt.Sprintf("%s=%d", SettingName(s.ID), s.Value)
	}
	return out
}
