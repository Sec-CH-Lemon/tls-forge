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

	// Unchecked is what both sides have and no rule says how to compare: an
	// extension nobody has described, whose contents differ. It is neither a
	// match nor a difference, and a report with any is not a match.
	Unchecked []Difference `json:",omitempty"`
}

// OK reports a candidate indistinguishable from the reference on every field
// compared, with nothing left that could not be.
func (r Report) OK() bool { return len(r.Differences) == 0 && len(r.Unchecked) == 0 }

func (r Report) String() string {
	if r.OK() {
		return "no differences"
	}
	parts := make([]string, 0, len(r.Differences)+len(r.Unchecked))
	for _, d := range r.Differences {
		parts = append(parts, d.String())
	}
	for _, d := range r.Unchecked {
		parts = append(parts, "not checked: "+d.String())
	}
	return strings.Join(parts, "\n")
}

// Field is one property a fingerprint is compared on, with the values from one
// side of the comparison.
//
// The list exists so that the fields are named once. Comparing and displaying
// want the same set, and a second copy of it in the command line would drift:
// a field added here would quietly stop being shown, or a field shown there
// would quietly stop being compared.
type Field struct {
	Name   string
	Values []string

	// Set compares membership rather than sequence. True only where the browser
	// itself varies the order, which is the extension list and nothing else.
	Set bool

	// Scalar is a single value rather than a list, so a mismatch has no
	// meaningful "missing" and "extra".
	Scalar bool

	// Varies is a value the browser draws afresh for every connection, such as
	// the length of its ECH payload: shown for both sides and never compared,
	// since the browser would not match itself.
	Varies bool
}

// Render is the value as a person reads it.
//
// A Set field renders sorted. Its order is not compared because the browser
// varies it, so printing the order it happened to arrive in would invite the
// reader to compare something that is not being compared.
func (f Field) Render() string {
	if f.Set {
		return render(sorted(f.Values))
	}
	return render(f.Values)
}

// Matches reports whether two fields agree, by the rule that field is compared
// with.
//
// Display has to ask this rather than compare the rendered strings, or a Set
// field whose order differs would be shown as a difference while the verdict
// below it said everything matched. The two answers have to come from one rule.
func (f Field) Matches(other Field) bool {
	switch {
	case f.Varies:
		return true
	case f.Scalar:
		return f.Render() == other.Render()
	case f.Set:
		return len(subtract(f.Values, other.Values)) == 0 && len(subtract(other.Values, f.Values)) == 0
	default:
		return equalStrings(f.Values, other.Values)
	}
}

func scalar(name, value string) Field {
	return Field{Name: name, Values: []string{value}, Scalar: true}
}

// TLSFields is everything a ClientHello is compared on, in a fixed order: the
// manifest of the comparison.
//
// What the browser draws for every connection is not compared as it is, since
// the browser would not match itself; its shape is, which does not change:
//
//   - Extension ORDER. Chrome shuffles it on every connection. The extension
//     SET is compared instead, which is what JA4 hashes, and the order of the
//     trust anchors, drawn once for each browser process, likewise.
//   - GREASE values (RFC 8701). Where they go, how long they are and which are
//     one value is compared as grease.
//   - The random, the session id, the keys, ECH's config id, key and payload,
//     and the tickets and binders of pre_shared_key: their lengths are
//     compared, the bytes are not.
//   - The length of the ECH payload, which Chrome draws from four for every
//     connection: shown, never compared (Varies).
//   - The contents of server_name, which are the site's, and of padding, whose
//     length follows from the rest.
//
// Everything else is stable for a given browser build and is compared exactly.
// An extension both sides send that none of this describes, with contents
// that differ, is reported by CompareTLS as not checked.
func TLSFields(hello *ClientHello) []Field {
	ech, echPayload := echShape(hello)
	return []Field{
		scalar("ja4", hello.JA4()),
		scalar("record_version", VersionName(hello.RecordVersion)),
		scalar("records", fmt.Sprint(hello.Records)),
		scalar("legacy_version", VersionName(hello.LegacyVersion)),
		scalar("session_id_length", fmt.Sprint(len(hello.SessionID))),
		{Name: "cipher_suites", Values: namesOf(withoutGREASE(hello.CipherSuites), CipherName)},
		{Name: "compression_methods", Values: decimalStrings(hello.CompressionMethods)},
		{Name: "extensions", Values: namesOf(withoutGREASE(hello.ExtensionTypes()), ExtensionName), Set: true},
		{Name: "grease", Values: greaseLayout(hello)},
		{Name: "supported_versions", Values: namesOf(withoutGREASE(hello.SupportedVersions()), VersionName)},
		{Name: "supported_groups", Values: namesOf(withoutGREASE(hello.SupportedGroups()), GroupName)},
		{Name: "signature_algorithms", Values: namesOf(withoutGREASE(hello.SignatureAlgorithms()), SignatureName)},
		{Name: "key_share_groups", Values: namesOf(withoutGREASE(hello.KeyShareGroups()), GroupName)},
		{Name: "key_share_lengths", Values: keyShareLengths(hello)},
		{Name: "alpn", Values: hello.ALPN()},
		{Name: "application_settings", Values: hello.ApplicationSettings()},
		{Name: "ec_point_formats", Values: decimalStrings(hello.ECPointFormats())},
		{Name: "psk_key_exchange_modes", Values: decimalStrings(hello.PSKKeyExchangeModes())},
		{Name: "compress_certificate", Values: decimalStrings16(hello.CertCompressionAlgorithms())},
		{Name: "trust_anchors", Values: hello.TrustAnchors(), Set: true},
		scalar("ech_grease", ech),
		{Name: "ech_payload_length", Values: []string{echPayload}, Scalar: true, Varies: true},
		scalar("pre_shared_key", pskShape(hello)),
		{Name: "extension_contents", Values: extensionContents(hello), Set: true},
	}
}

// HTTP2Fields is everything the connection preamble and first request are
// compared on.
//
// Header values are included. A profile is a complete browser identity, and a
// Chrome ClientHello paired with a HeadlessChrome user-agent is exactly the kind
// of cross-layer contradiction this comparison exists to expose. The values of
// :path and :authority are not: the two measurements ask for different pages,
// and a browser opened by hand reaches the server by a name of its own.
func HTTP2Fields(h *HTTP2) []Field {
	return []Field{
		scalar("http2_akamai", h.Akamai()),
		{Name: "http2_settings", Values: settingStrings(h.Settings)},
		scalar("http2_window_update", fmt.Sprint(h.WindowUpdate)),
		{Name: "http2_priority_frames", Values: priorityStrings(h.Priorities)},
		scalar("http2_header_priority", headerPriority(h.HeaderPriority)),
		{Name: "pseudo_header_order", Values: h.PseudoHeaderOrder()},
		{Name: "pseudo_header_values", Values: pseudoHeaderStrings(h.Headers)},
		{Name: "header_order", Values: h.HeaderOrder()},
		{Name: "header_values", Values: regularHeaderStrings(h.Headers)},
	}
}

// priorityString is a priority as RFC 9113 counts its weight, 1 to 256: one
// more than the byte on the wire.
func priorityString(p Priority) string {
	exclusive := ""
	if p.Exclusive {
		exclusive = "exclusive, "
	}
	return fmt.Sprintf("stream %d, %sdepends on %d, weight %d", p.StreamID, exclusive, p.DependsOn, int(p.Weight)+1)
}

func priorityStrings(priorities []Priority) []string {
	out := make([]string, len(priorities))
	for i, p := range priorities {
		out[i] = priorityString(p)
	}
	return out
}

func headerPriority(p *Priority) string {
	if p == nil {
		return "(none)"
	}
	return priorityString(*p)
}

// pseudoHeaderStrings are the pseudo-headers with their values, but for the
// page asked for and the name the server was reached by.
func pseudoHeaderStrings(headers []HeaderField) []string {
	var out []string
	for _, header := range headers {
		if strings.HasPrefix(header.Name, ":") && header.Name != ":path" && header.Name != ":authority" {
			out = append(out, header.Name+": "+header.Value)
		}
	}
	return out
}

func regularHeaderStrings(headers []HeaderField) []string {
	out := make([]string, 0, len(headers))
	for _, header := range headers {
		if !strings.HasPrefix(header.Name, ":") {
			out = append(out, header.Name+": "+header.Value)
		}
	}
	return out
}

// CompareTLS diffs a candidate ClientHello against a reference one, usually a
// real browser's. TLSFields says what is compared, and what is not.
func CompareTLS(reference, candidate *ClientHello) Report {
	report := compareFields(TLSFields(reference), TLSFields(candidate))
	report.Unchecked = uncheckedExtensions(reference, candidate)
	return report
}

// CompareHTTP2 diffs the connection preamble and the request headers.
func CompareHTTP2(reference, candidate *HTTP2) Report {
	return compareFields(HTTP2Fields(reference), HTTP2Fields(candidate))
}

// CompareHTTP1 diffs HTTP/1.1 request header order, casing and values.
func CompareHTTP1(reference, candidate *HTTP1) Report {
	return compareFields(HTTP1Fields(reference), HTTP1Fields(candidate))
}

// compareFields walks two lists produced by the same function, so they are the
// same length and in the same order.
func compareFields(reference, candidate []Field) Report {
	var diffs []Difference
	for i, want := range reference {
		got := candidate[i]
		var d *Difference
		switch {
		case want.Varies:
			continue
		case want.Scalar:
			d = diffValue(want.Name, want.Render(), got.Render())
		case want.Set:
			d = diffSet(want.Name, want.Values, got.Values)
		default:
			d = diffOrdered(want.Name, want.Values, got.Values)
		}
		if d != nil {
			diffs = append(diffs, *d)
		}
	}
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
