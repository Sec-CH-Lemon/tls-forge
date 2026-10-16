package fingerprint

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

func TestCompareTLSIdentical(t *testing.T) {
	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, chrome151().records()))
	if !report.OK() {
		t.Errorf("identical helloes reported differences:\n%s", report)
	}
	if got, want := report.String(), "no differences"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCompareTLSIgnoresExtensionOrderAndGREASE(t *testing.T) {
	// Chrome does both on every connection, so a comparison that noticed either
	// would report the browser as differing from itself. It shuffles the
	// extensions between its two GREASE ones, which stay first and last, and
	// draws every GREASE value afresh.
	shuffled := chrome151()
	middle := shuffled.extensions[1 : len(shuffled.extensions)-1]
	rotated := append(append([]Extension{}, middle[7:]...), middle[:7]...)
	copy(middle, rotated)
	shuffled.ciphers[0] = 0x3a3a
	shuffled.extensions[0].Type, shuffled.extensions[len(shuffled.extensions)-1].Type = 0x5a5a, 0x6a6a

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, shuffled.records()))
	if !report.OK() {
		t.Errorf("reordering extensions was reported as a difference:\n%s", report)
	}
}

func TestCompareTLSNamesTheMissingSignatureAlgorithm(t *testing.T) {
	// The real case this library exists for: a stock TLS profile that is right
	// about everything except the post-quantum signature schemes.
	withoutMLDSA := chrome151()
	for i, ext := range withoutMLDSA.extensions {
		if ext.Type == ExtSignatureAlgorithms {
			withoutMLDSA.extensions[i].Data = vector16(
				0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
		}
	}

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, withoutMLDSA.records()))
	if report.OK() {
		t.Fatal("expected a difference")
	}

	rendered := report.String()
	for _, want := range []string{"ja4", "signature_algorithms", "mldsa44", "mldsa65", "mldsa87", "missing:"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("report does not mention %q:\n%s", want, rendered)
		}
	}
}

func TestCompareTLSDetectsEachField(t *testing.T) {
	reference := chrome151()

	for _, tc := range []struct {
		name  string
		build func() *helloBuilder
		field string
	}{
		{"ciphers", func() *helloBuilder {
			b := chrome151()
			b.ciphers = []uint16{0x1301, 0x1302}
			return b
		}, "cipher_suites"},
		{"a missing extension", func() *helloBuilder {
			b := chrome151()
			b.extensions = b.extensions[:len(b.extensions)-2]
			return b
		}, "extensions"},
		{"groups", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtSupportedGroups, vector16(29, 23))
		}, "supported_groups"},
		{"versions", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtSupportedVersions, vector8of16(0x0303))
		}, "supported_versions"},
		{"key shares", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtKeyShare, keyShare(29))
		}, "key_share_groups"},
		{"ALPN", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtALPN, alpn("http/1.1"))
		}, "alpn"},
		{"ALPS", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtApplicationSettingsOld, alpn("http/1.1"))
		}, "application_settings"},
		{"point formats", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtECPointFormats, vector8(0, 1))
		}, "ec_point_formats"},
		{"PSK modes", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtPSKKeyExchangeModes, vector8(0))
		}, "psk_key_exchange_modes"},
		{"certificate compression", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtCompressCertificate, vector8of16(1))
		}, "compress_certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := CompareTLS(mustParse(t, reference.records()), mustParse(t, tc.build().records()))
			if report.OK() {
				t.Fatalf("expected a difference in %s", tc.field)
			}
			if !strings.Contains(report.String(), tc.field) {
				t.Errorf("report does not name %q:\n%s", tc.field, report)
			}
		})
	}
}

func TestCompareTLSDistinguishesOrderFromContents(t *testing.T) {
	// Same ciphers, different order: the two have completely different fixes, so
	// the report must not describe one as the other.
	//
	// Indices 1 and 2 rather than 0 and 1: index 0 is GREASE, which is filtered
	// before comparison, so swapping it changes nothing at all.
	reordered := chrome151()
	reordered.ciphers[1], reordered.ciphers[2] = reordered.ciphers[2], reordered.ciphers[1]

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, reordered.records()))
	if report.OK() {
		t.Fatal("expected a difference")
	}
	for _, diff := range report.Differences {
		if diff.Field != "cipher_suites" {
			continue
		}
		if len(diff.Missing) != 0 || len(diff.Extra) != 0 {
			t.Errorf("a pure reordering reported missing=%v extra=%v; both should be empty",
				diff.Missing, diff.Extra)
		}
	}
}

func TestCompareTLSCountsDuplicates(t *testing.T) {
	twice := newHello().withCiphers(0x1301, 0x1301)
	once := newHello().withCiphers(0x1301)
	report := CompareTLS(mustParse(t, twice.records()), mustParse(t, once.records()))
	if report.OK() {
		t.Fatal("a cipher sent twice differs from one sent once")
	}
}

// heldToEveryField fails for a field fields compares, Varies aside, that no
// change was reported under: the manifest has no field a test does not hold
// it to.
func heldToEveryField(t *testing.T, fields []Field, held map[string]bool) {
	t.Helper()
	var unheld []string
	for _, field := range fields {
		if field.Varies == "" && !held[field.Name] {
			unheld = append(unheld, field.Name)
		}
	}
	if len(unheld) > 0 {
		t.Errorf("no change is held to %v", unheld)
	}
}

// navigation is chromeHTTP2 opening a page no static entry holds, as the
// browser measured does, so that how :path is written says something.
func navigation() *HTTP2 {
	h := chromeHTTP2Fields()
	h.Headers[3].Value = "/?http1=done"
	h.Raw = preambleOf(h, wire{})
	return h
}

func TestCompareHTTP2(t *testing.T) {
	reference := navigation()

	if report := CompareHTTP2(reference, navigation()); !report.OK() {
		t.Errorf("identical connections reported differences:\n%s", report)
	}

	held := map[string]bool{}
	for _, tc := range []struct {
		name   string
		mutate func(*HTTP2)
		field  string
	}{
		{"a PRIORITY frame", func(h *HTTP2) {
			h.Priorities = []Priority{{StreamID: 3, DependsOn: 0, Weight: 200}}
		}, "http2_akamai"},
		{"settings order", func(h *HTTP2) {
			h.Settings[0], h.Settings[1] = h.Settings[1], h.Settings[0]
		}, "http2_settings"},
		{"window update", func(h *HTTP2) { h.WindowUpdate = 65535 }, "http2_window_update"},
		{"a PRIORITY frame, read", func(h *HTTP2) {
			h.Priorities = []Priority{{StreamID: 3, Exclusive: true, DependsOn: 0, Weight: 200}}
		}, "http2_priority_frames"},
		{"no priority on HEADERS", func(h *HTTP2) { h.HeaderPriority = nil }, "http2_header_priority"},
		{"another weight on HEADERS", func(h *HTTP2) { h.HeaderPriority.Weight = 219 }, "http2_header_priority"},
		{"pseudo-header order", func(h *HTTP2) {
			h.Headers[1], h.Headers[2] = h.Headers[2], h.Headers[1]
		}, "pseudo_header_order"},
		{"another method", func(h *HTTP2) { h.Headers[0].Value = "POST" }, "pseudo_header_values"},
		{"header order", func(h *HTTP2) {
			h.Headers[4], h.Headers[6] = h.Headers[6], h.Headers[4]
		}, "header_order"},
		{"header value", func(h *HTTP2) {
			h.Headers[4].Value = "different"
		}, "header_values"},
		{"a PRIORITY frame first", func(h *HTTP2) { h.Raw = preambleOf(h, wire{priority: true}) }, "http2_frames"},
		{"no WINDOW_UPDATE frame", func(h *HTTP2) { h.Raw = preambleOf(h, wire{noWindow: true}) }, "http2_frames"},
		{"a CONTINUATION", func(h *HTTP2) { h.Raw = preambleOf(h, wire{split: true}) }, "http2_frames"},
		{"user-agent never to be indexed", func(h *HTTP2) {
			h.Raw = preambleOf(h, wire{sensitive: "user-agent"})
		}, "http2_hpack"},
		{"a table size update first", func(h *HTTP2) { h.Raw = preambleOf(h, wire{sizeUpdate: true}) }, "http2_hpack"},
		{"the page never to be indexed", func(h *HTTP2) { h.Raw = preambleOf(h, wire{sensitive: ":path"}) }, "http2_hpack_path"},
	} {
		held[tc.field] = true
		t.Run(tc.name, func(t *testing.T) {
			candidate := navigation()
			tc.mutate(candidate)
			report := CompareHTTP2(reference, candidate)
			if !slices.ContainsFunc(report.Differences, func(d Difference) bool { return d.Field == tc.field }) {
				t.Errorf("report does not name %q:\n%s", tc.field, report)
			}
		})
	}
	heldToEveryField(t, HTTP2Fields(reference), held)
}

func TestCompareHTTP1(t *testing.T) {
	reference := &HTTP1{Method: "GET", Proto: "HTTP/1.1", Headers: []HeaderField{
		{Name: "Host", Value: "browser.example"},
		{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
		{Name: "Connection", Value: "keep-alive"},
	}}
	identical := &HTTP1{Method: "GET", Proto: "HTTP/1.1", Headers: []HeaderField{
		{Name: "Host", Value: "client.example"},
		{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
		{Name: "Connection", Value: "keep-alive"},
	}}
	if report := CompareHTTP1(reference, identical); !report.OK() {
		t.Errorf("destination-specific Host value differed:\n%s", report)
	}

	held := map[string]bool{}
	for _, tc := range []struct {
		name   string
		mutate func(*HTTP1)
		field  string
	}{
		{"HTTP/1.0", func(h *HTTP1) { h.Proto = "HTTP/1.0" }, "http1_request"},
		{"another method", func(h *HTTP1) { h.Method = "HEAD" }, "http1_request"},
		{"order", func(h *HTTP1) { h.Headers[1], h.Headers[2] = h.Headers[2], h.Headers[1] }, "http1_header_order"},
		{"casing", func(h *HTTP1) { h.Headers[1].Name = "Sec-Ch-Ua" }, "http1_header_order"},
		{"value", func(h *HTTP1) { h.Headers[2].Value = "close" }, "http1_header_values"},
	} {
		held[tc.field] = true
		t.Run(tc.name, func(t *testing.T) {
			candidate := &HTTP1{Method: identical.Method, Proto: identical.Proto,
				Headers: append([]HeaderField(nil), identical.Headers...)}
			tc.mutate(candidate)
			report := CompareHTTP1(reference, candidate)
			if !slices.ContainsFunc(report.Differences, func(d Difference) bool { return d.Field == tc.field }) {
				t.Errorf("difference in %s was not reported:\n%s", tc.field, report)
			}
		})
	}
	heldToEveryField(t, HTTP1Fields(reference), held)
}

func TestHTTP2FieldsExcludeThePageAndTheSiteName(t *testing.T) {
	// The two measurements ask for different pages, and a browser opened by
	// hand reaches the server by a name of its own: what is asked for and
	// where, and how either was written down.
	left, right := chromeHTTP2(), chromeHTTP2Fields()
	right.Headers[1].Value = "192.168.1.5:8443"
	right.Headers[3].Value = "/another/path/that/no/table/holds"
	right.Raw = preambleOf(right, wire{})
	if report := CompareHTTP2(left, right); !report.OK() {
		t.Errorf("the page or the site's name differed:\n%s", report)
	}
	// Nor whether either was Huffman-coded, which their letters decide: "["
	// and "~" take thirteen bits of Huffman code, and are written as they are.
	plain := chromeHTTP2Fields()
	plain.Headers[1].Value = "[::1]:8443"
	plain.Headers[3].Value = "/~~~~~~~~"
	plain.Raw = preambleOf(plain, wire{})
	if report := CompareHTTP2(navigation(), plain); !report.OK() {
		t.Errorf("Huffman coding of the page or the site's name differed:\n%s", report)
	}
	// When the client acknowledges the server's SETTINGS depends on when they
	// came.
	right.Raw = preambleOf(right, wire{ackFirst: true})
	if report := CompareHTTP2(left, right); !report.OK() {
		t.Errorf("an acknowledgement differed:\n%s", report)
	}
	// A page the static table holds whole is written as that entry by any
	// client: how the other side wrote its page is not held to it.
	page := HTTP2Fields(left)[len(HTTP2Fields(left))-1]
	if page.Name != "http2_hpack_path" || page.Render() != "indexed static 4" ||
		page.Varies != "the page asked for decides it" {
		t.Errorf("the page /: %+v", page)
	}
	if report := CompareHTTP2(left, navigation()); !report.OK() {
		t.Errorf("/ against another page:\n%s", report)
	}
	if report := CompareHTTP2(navigation(), left); !report.OK() {
		t.Errorf("another page against /:\n%s", report)
	}
	if got := HTTP2Fields(left)[6]; got.Name != "pseudo_header_values" ||
		!slices.Equal(got.Values, []string{":method: GET", ":scheme: https"}) {
		t.Errorf("pseudo-header values: %+v", got)
	}
}

func TestHTTP2FieldsSayHowEachFieldWasWritten(t *testing.T) {
	// Written by x/net's encoder, which indexes every field and names :path
	// from the static table's second entry for it.
	want := map[string][]string{
		"http2_frames": {"SETTINGS on 0", "WINDOW_UPDATE on 0", "HEADERS on 1, END_STREAM|END_HEADERS|PRIORITY"},
		"http2_hpack": {":method: indexed static 2", ":authority: with indexing, name static 1",
			":scheme: indexed static 7", "sec-ch-ua: with indexing, new name huffman, value huffman",
			"user-agent: with indexing, name static 58, value huffman",
			"accept: with indexing, name static 19, value huffman"},
		"http2_hpack_path": {"with indexing, name static 5"},
	}
	for _, field := range HTTP2Fields(navigation()) {
		if expected, ok := want[field.Name]; ok && (!slices.Equal(field.Values, expected) || field.Missing || field.Varies != "") {
			t.Errorf("%s: %+v", field.Name, field)
		}
	}
	// A request without a :path, as CONNECT is.
	connect := &HTTP2{Headers: []HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "a:443"}}}
	connect.Raw = preambleOf(connect, wire{})
	if got := HTTP2Fields(connect)[len(HTTP2Fields(connect))-1]; got.Render() != "(none)" || got.Missing {
		t.Errorf("no :path: %+v", got)
	}
}

func TestWhatWasNotRecordedIsNotChecked(t *testing.T) {
	// A capture made before the frames were kept has none: not a match, and
	// not a difference either.
	recorded, unrecorded := chromeHTTP2(), chromeHTTP2()
	unrecorded.Raw = nil
	report := CompareHTTP2(recorded, unrecorded)
	if report.OK() || len(report.Differences) != 0 || len(report.Unchecked) != 3 ||
		report.Unchecked[0].Field != "http2_frames" || report.Unchecked[1].Candidate != "(not recorded)" ||
		report.Unchecked[2].Field != "http2_hpack_path" {
		t.Errorf("one side unrecorded: %+v", report)
	}
	// Frames that cannot be read are said why.
	unrecorded.Raw = []byte{0, 0}
	report = CompareHTTP2(unrecorded, recorded)
	if len(report.Unchecked) != 3 || !strings.Contains(report.Unchecked[0].Reference, "cut short") {
		t.Errorf("unreadable frames: %+v", report)
	}
	// A header block that cannot be read leaves the frames to compare.
	broken := chromeHTTP2Fields()
	var out bytes.Buffer
	framer := http2.NewFramer(&out, nil)
	_ = framer.WriteSettings(http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 2, Val: 0},
		http2.Setting{ID: 4, Val: 6291456}, http2.Setting{ID: 6, Val: 262144})
	_ = framer.WriteWindowUpdate(0, 15663105)
	_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0xff}, EndStream: true,
		EndHeaders: true, Priority: http2.PriorityParam{Exclusive: true, Weight: 255}})
	broken.Raw = out.Bytes()
	report = CompareHTTP2(recorded, broken)
	if len(report.Differences) != 0 || len(report.Unchecked) != 2 || report.Unchecked[0].Field != "http2_hpack" ||
		report.Unchecked[1].Field != "http2_hpack_path" {
		t.Errorf("an unreadable header block: %+v", report)
	}
	missing := Field{Name: "http2_frames", Values: []string{"(not recorded)"}, Missing: true}
	if missing.Matches(missing) || (Field{Name: "x"}).Matches(missing) {
		t.Error("a missing field matched")
	}
}

func TestPrioritiesAreSaidAsRFC9113CountsTheirWeight(t *testing.T) {
	if got := headerPriority(&Priority{StreamID: 1, Exclusive: true, Weight: 255}); got != "stream 1, exclusive, depends on 0, weight 256" {
		t.Errorf("Chrome's: %q", got)
	}
	if got := priorityString(Priority{StreamID: 5, DependsOn: 3, Weight: 0}); got != "stream 5, depends on 3, weight 1" {
		t.Errorf("a PRIORITY frame: %q", got)
	}
	if got := headerPriority(nil); got != "(none)" {
		t.Errorf("none: %q", got)
	}
}

func TestDifferenceRendering(t *testing.T) {
	diff := Difference{
		Field:     "supported_groups",
		Reference: "X25519MLKEM768, X25519",
		Candidate: "X25519",
		Missing:   []string{"X25519MLKEM768"},
	}
	rendered := diff.String()
	for _, want := range []string{"supported_groups", "browser:", "client:", "missing:", "X25519MLKEM768"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendering omits %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "extra:") {
		t.Errorf("rendering shows an empty extras line:\n%s", rendered)
	}

	withExtra := Difference{Field: "f", Extra: []string{"unexpected"}}
	if !strings.Contains(withExtra.String(), "extra:   unexpected") {
		t.Errorf("rendering omits extras:\n%s", withExtra)
	}
}

func TestRenderEmptyList(t *testing.T) {
	report := CompareTLS(
		mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn("h2")).records()),
		mustParse(t, newHello().withCiphers(0x1301).records()),
	)
	if !strings.Contains(report.String(), "(none)") {
		t.Errorf("an absent list should render as (none):\n%s", report)
	}
}

func replaceExtension(b *helloBuilder, typ uint16, data []byte) *helloBuilder {
	for i, ext := range b.extensions {
		if ext.Type == typ {
			b.extensions[i].Data = data
		}
	}
	return b
}

func TestFieldMatchesUsesTheRuleTheFieldIsComparedWith(t *testing.T) {
	// Display asks this so that a field cannot be shown as a difference while
	// the verdict underneath says everything matched. Each kind of field has to
	// answer by the same rule the comparison uses.
	for _, tc := range []struct {
		name        string
		left, right Field
		want        bool
	}{
		{"scalar agrees", scalar("ja4", "t13d"), scalar("ja4", "t13d"), true},
		{"scalar differs", scalar("ja4", "t13d"), scalar("ja4", "t13i"), false},

		// The browser shuffles its extension order per connection, so this is
		// the field the two answers would disagree about if order were read.
		{
			"set ignores order",
			Field{Name: "extensions", Values: []string{"alpn", "key_share"}, Set: true},
			Field{Name: "extensions", Values: []string{"key_share", "alpn"}, Set: true},
			true,
		},
		{
			"set notices a missing value",
			Field{Name: "extensions", Values: []string{"alpn", "key_share"}, Set: true},
			Field{Name: "extensions", Values: []string{"alpn"}, Set: true},
			false,
		},
		{
			"set notices an extra value",
			Field{Name: "extensions", Values: []string{"alpn"}, Set: true},
			Field{Name: "extensions", Values: []string{"alpn", "key_share"}, Set: true},
			false,
		},

		{
			"ordered agrees",
			Field{Name: "alpn", Values: []string{"h2", "http/1.1"}},
			Field{Name: "alpn", Values: []string{"h2", "http/1.1"}},
			true,
		},
		{
			"ordered reads order",
			Field{Name: "alpn", Values: []string{"h2", "http/1.1"}},
			Field{Name: "alpn", Values: []string{"http/1.1", "h2"}},
			false,
		},

		// Drawn for every connection: shown, and never a difference.
		{
			"varies is never a difference",
			Field{Name: "ech_payload_length", Values: []string{"176"}, Scalar: true, Varies: drawn},
			Field{Name: "ech_payload_length", Values: []string{"240"}, Scalar: true, Varies: drawn},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.left.Matches(tc.right); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetFieldRendersSorted(t *testing.T) {
	// Printing a set in arrival order invites the reader to compare an order
	// that is deliberately not being compared.
	f := Field{Name: "extensions", Values: []string{"key_share", "alpn"}, Set: true}
	if got := f.Render(); got != "alpn, key_share" {
		t.Errorf("Render() = %q", got)
	}
}
