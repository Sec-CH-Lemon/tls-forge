package fingerprint

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fixture is a hello kept in testdata, as it went on the wire.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// builderOf is a builder holding what a parsed hello holds, so that a test can
// change one thing of a real hello and render it again. The random comes out
// as zeros, which nothing compares.
func builderOf(t *testing.T, raw []byte) *helloBuilder {
	t.Helper()
	hello := mustParse(t, raw)
	b := newHello()
	b.legacyVersion = hello.LegacyVersion
	b.sessionID = slices.Clone(hello.SessionID)
	b.ciphers = slices.Clone(hello.CipherSuites)
	b.compression = slices.Clone(hello.CompressionMethods)
	for _, ext := range hello.Extensions {
		b.extensions = append(b.extensions, Extension{Type: ext.Type, Data: slices.Clone(ext.Data)})
	}
	return b
}

// set replaces the contents of an extension the builder has.
func (b *helloBuilder) set(typ uint16, data []byte) *helloBuilder {
	for i, ext := range b.extensions {
		if ext.Type == typ {
			b.extensions[i].Data = data
			return b
		}
	}
	panic("no such extension")
}

// shares is a key_share body with a key of the given length for each group.
func shares(entries ...KeyShare) []byte {
	var list []byte
	for _, entry := range entries {
		list = binary.BigEndian.AppendUint16(list, entry.Group)
		list = binary.BigEndian.AppendUint16(list, uint16(entry.Length))
		list = append(list, make([]byte, entry.Length)...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// anchors is a trust_anchors body holding these IDs.
func anchors(ids ...[]byte) []byte {
	var list []byte
	for _, id := range ids {
		list = append(list, byte(len(id)))
		list = append(list, id...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// psk is a pre_shared_key body: an identity of each length given, then a
// binder of each.
func psk(identities, binders []int) []byte {
	var ids, bs []byte
	for _, n := range identities {
		ids = binary.BigEndian.AppendUint16(ids, uint16(n))
		ids = append(ids, make([]byte, n)...)
		ids = binary.BigEndian.AppendUint32(ids, 7)
	}
	for _, n := range binders {
		bs = append(bs, byte(n))
		bs = append(bs, make([]byte, n)...)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(ids)))
	out = append(out, ids...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(bs)))
	return append(out, bs...)
}

func TestTheRecordLayerIsKept(t *testing.T) {
	hello := mustParse(t, fixture(t, "chrome155-clienthello.bin"))
	if hello.RecordVersion != 0x0301 || hello.Records != 1 {
		t.Errorf("Chrome's hello: record version %#04x, %d records", hello.RecordVersion, hello.Records)
	}
	b := builderOf(t, fixture(t, "chrome155-clienthello.bin"))
	b.recordVersion = 0x0303
	if hello := mustParse(t, b.records()); hello.RecordVersion != 0x0303 || hello.Records != 1 {
		t.Errorf("record version %#04x, %d records", hello.RecordVersion, hello.Records)
	}
	b.split = 512
	if hello := mustParse(t, b.records()); hello.Records != 4 {
		t.Errorf("a hello cut every 512 bytes came in %d records", hello.Records)
	}
	// An empty record first is a record, and the version is the first's.
	message := handshakeMessage(typeClientHello, newHello().withCiphers(0x1301).body())
	raw := append([]byte{recordTypeHandshake, 0x03, 0x02, 0, 0}, recordsOf(message)...)
	if hello := mustParse(t, raw); hello.RecordVersion != 0x0302 || hello.Records != 2 {
		t.Errorf("after an empty record: record version %#04x, %d records", hello.RecordVersion, hello.Records)
	}
}

func TestKeySharesSayHowLongEachKeyIs(t *testing.T) {
	hello := mustParse(t, fixture(t, "chrome155-clienthello.bin"))
	got := hello.KeyShares()
	if len(got) != 3 || !IsGREASE(got[0].Group) || got[0].Length != 1 ||
		got[1] != (KeyShare{Group: 4588, Length: 1216}) || got[2] != (KeyShare{Group: 29, Length: 32}) {
		t.Errorf("Chrome's key shares: %+v", got)
	}
	if groups := hello.KeyShareGroups(); !reflect.DeepEqual(groups, []uint16{got[0].Group, 4588, 29}) {
		t.Errorf("groups %v", groups)
	}
	// A list that runs past its end is none; an entry cut short ends the list
	// where it is, as every list of the parser does.
	cut := []byte{0, 29, 0, 1, 0, 0, 23}
	for _, tc := range []struct {
		body []byte
		want []KeyShare
	}{
		{[]byte{0, 9, 0, 29}, nil},
		{append(binary.BigEndian.AppendUint16(nil, uint16(len(cut))), cut...), []KeyShare{{Group: 29, Length: 1}}},
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtKeyShare, tc.body).records())
		if got := hello.KeyShares(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%x: %+v", tc.body, got)
		}
	}
	if got := mustParse(t, newHello().withCiphers(0x1301).records()).KeyShares(); got != nil {
		t.Errorf("no key_share: %+v", got)
	}
}

func TestTrustAnchorsAreRelativeOIDs(t *testing.T) {
	got := mustParse(t, fixture(t, "chrome155-clienthello.bin")).TrustAnchors()
	if len(got) != 28 || !slices.Contains(got, "44947.2.1") || !slices.Contains(got, "52580.200109.1.7") ||
		!slices.Contains(got, "11129.9.1") {
		t.Errorf("Chrome's trust anchors: %v", got)
	}
	for _, tc := range []struct {
		id   []byte
		want string
	}{
		{[]byte{0x01}, "1"},
		{[]byte{0x00}, "0"},
		{[]byte{0x82, 0xdf, 0x13, 0x02, 0x01}, "44947.2.1"},
		{[]byte{0x81, 0x80, 0x00}, "16384"},
		// A needless leading zero would be another ID, not this one again.
		{[]byte{0x80, 0x01}, "8001"},
		{[]byte{0x01, 0x80, 0x01}, "018001"},
		// An arc that never ends.
		{[]byte{0x81}, "81"},
		{[]byte{0x01, 0x81}, "0181"},
		// The largest arc read, 2^63 + 127, and one past what 64 bits hold.
		{[]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}, "9223372036854775935"},
		{[]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81, 0x7f}, "81808080808080808" + "17f"},
		{[]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, "8180808080808080808000"},
		{nil, "(empty)"},
	} {
		if got := relativeOID(tc.id); got != tc.want {
			t.Errorf("relativeOID(%x) = %q, want %q", tc.id, got, tc.want)
		}
	}
	// In the order sent; a list that runs past its end is none, and an ID
	// that does ends the list where it is.
	for _, tc := range []struct {
		body []byte
		want []string
	}{
		{anchors([]byte{0x82, 0xdf, 0x13, 0x02, 0x01}, []byte{0x01}), []string{"44947.2.1", "1"}},
		{[]byte{0, 9, 1, 1}, nil},
		{[]byte{0, 3, 1, 1, 5}, []string{"1"}},
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtTrustAnchors, tc.body).records())
		if got := hello.TrustAnchors(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%x: %v", tc.body, got)
		}
	}
}

func TestPreSharedKeyIsReadWithoutItsKeys(t *testing.T) {
	got, ok := mustParse(t, fixture(t, "chrome155-clienthello-resumed.bin")).PreSharedKey()
	if !ok || got.Identities != 1 || !reflect.DeepEqual(got.Binders, []int{32}) {
		t.Errorf("Chrome's: %+v, %v", got, ok)
	}
	if _, ok := mustParse(t, fixture(t, "chrome155-clienthello.bin")).PreSharedKey(); ok {
		t.Error("a cold hello has none")
	}
	whole := psk([]int{100, 80}, []int{32, 48})
	for name, tc := range map[string]struct {
		body []byte
		ok   bool
		want PSK
	}{
		"two of each":             {whole, true, PSK{Identities: 2, Binders: []int{32, 48}}},
		"no binder":               {psk([]int{100}, nil), true, PSK{Identities: 1}},
		"bytes to spare":          {append(slices.Clone(whole), 0), false, PSK{}},
		"identities past the end": {[]byte{0, 200}, false, PSK{}},
		"binders past the end":    {append(psk([]int{4}, nil)[:12], 0, 9), false, PSK{}},
		"an identity cut short":   {[]byte{0, 3, 0, 9, 1, 0, 0}, false, PSK{}},
		"an age cut short":        {[]byte{0, 5, 0, 1, 1, 0, 0, 0, 0}, false, PSK{}},
		"a binder cut short":      {[]byte{0, 0, 0, 2, 9, 1}, false, PSK{}},
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtPreSharedKey, tc.body).records())
		got, ok := hello.PreSharedKey()
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, %v", name, got, ok)
		}
	}
}

func TestGREASEIsComparedByWhereItGoes(t *testing.T) {
	want := []string{
		"cipher_suites first",
		"extensions first, empty", "extensions last, 1 byte", "extensions each a value of their own",
		"supported_groups first", "key_share first, key 1 byte", "key_share the group of supported_groups",
		"supported_versions first", "signature_algorithms first",
	}
	for _, name := range []string{"chrome155-clienthello.bin", "chrome155-clienthello-resumed.bin"} {
		// A resumed hello ends with pre_shared_key, after the second GREASE.
		if got := greaseLayout(mustParse(t, fixture(t, name))); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
	}

	b := builderOf(t, fixture(t, "chrome155-clienthello.bin"))
	b.ciphers = append(b.ciphers[1:4], append([]uint16{0x0a0a}, b.ciphers[4:]...)...)
	last := len(b.extensions) - 1
	b.extensions[last].Type = b.extensions[0].Type
	b.set(ExtKeyShare, shares(KeyShare{Group: 0x1a1a, Length: 0}, KeyShare{Group: 29, Length: 32}))
	got := greaseLayout(mustParse(t, b.records()))
	for _, line := range []string{
		"cipher_suites 4 of 16", "extensions a value twice", "key_share first, key empty",
		"key_share a group supported_groups does not have",
	} {
		if !slices.Contains(got, line) {
			t.Errorf("%q is not in %q", line, got)
		}
	}
	// One GREASE extension has no other to be the same value as.
	b.extensions = b.extensions[:last]
	if got := greaseLayout(mustParse(t, b.records())); slices.ContainsFunc(got, func(line string) bool {
		return strings.HasPrefix(line, "extensions each") || strings.HasPrefix(line, "extensions a value")
	}) {
		t.Errorf("one GREASE extension: %q", got)
	}
	// None at all: nothing to say.
	if got := greaseLayout(mustParse(t, newHello().withCiphers(0x1301).records())); got != nil {
		t.Errorf("no GREASE: %q", got)
	}
}

func TestPositionAndSize(t *testing.T) {
	for _, tc := range []struct {
		i, n int
		want string
	}{{0, 1, "first"}, {0, 5, "first"}, {4, 5, "last"}, {2, 5, "3 of 5"}} {
		if got := position(tc.i, tc.n); got != tc.want {
			t.Errorf("position(%d, %d) = %q", tc.i, tc.n, got)
		}
	}
	for n, want := range map[int]string{0: "empty", 1: "1 byte", 2: "2 bytes"} {
		if got := size(n); got != want {
			t.Errorf("size(%d) = %q", n, got)
		}
	}
}

func TestEachExtensionsContentsHaveARule(t *testing.T) {
	// Every extension this package names is either read by a field, known to
	// be the same every time, or known not to be the client's: none is left
	// to be found out about in a comparison.
	for typ := range extensionNames {
		rules := 0
		for _, rule := range []map[uint16]bool{readByAField, sameEveryTime, notTheClients} {
			if rule[typ] {
				rules++
			}
		}
		if rules != 1 && typ != 44 {
			t.Errorf("%s has %d rules", ExtensionName(typ), rules)
		}
	}
	// cookie comes only in a hello answering a HelloRetryRequest, with what
	// the server asked for: no rule can say, so it is checked when it
	// differs.
	if !unknownExtension(44) || unknownExtension(0x0a0a) || unknownExtension(ExtStatusRequest) {
		t.Error("the rules changed")
	}
}

func TestAnExtensionNoRuleDescribesIsNotChecked(t *testing.T) {
	base := builderOf(t, fixture(t, "chrome155-clienthello.bin")).withExtension(0x7777, []byte{1, 2})
	same := mustParse(t, base.records())

	// The same bytes on both sides are a match, whatever they are.
	if report := CompareTLS(same, same); !report.OK() {
		t.Errorf("the same unknown extension:\n%s", report)
	}
	// Different bytes cannot be told from random ones.
	other := builderOf(t, fixture(t, "chrome155-clienthello.bin")).withExtension(0x7777, nil)
	report := CompareTLS(same, mustParse(t, other.records()))
	want := []Difference{{Field: "contents of 0x7777", Reference: "0102", Candidate: "empty"}}
	if report.OK() || len(report.Differences) != 0 || !reflect.DeepEqual(report.Unchecked, want) {
		t.Fatalf("report: %+v", report)
	}
	if got := report.String(); got != "not checked: contents of 0x7777\n    browser: 0102\n    client:  empty" {
		t.Errorf("String() = %q", got)
	}
	// Sent by one side alone, it is a difference of the extensions, and there
	// is nothing to check.
	report = CompareTLS(same, mustParse(t, builderOf(t, fixture(t, "chrome155-clienthello.bin")).records()))
	if len(report.Unchecked) != 0 || len(report.Differences) == 0 || report.Differences[1].Field != "extensions" {
		t.Errorf("one side alone: %+v", report)
	}
	// Written out, the list is there only when there is something in it.
	encoded, err := json.Marshal(Report{})
	if err != nil || string(encoded) != `{"Differences":null}` {
		t.Errorf("an empty report is %s, %v", encoded, err)
	}
}

func TestWhatIsNotTheClientsIsNotCompared(t *testing.T) {
	// The site's name, and padding whose length is what the rest leaves.
	base := builderOf(t, fixture(t, "chrome155-clienthello.bin")).withExtension(ExtPadding, make([]byte, 10))
	other := builderOf(t, fixture(t, "chrome155-clienthello.bin")).withExtension(ExtPadding, make([]byte, 30))
	other.set(ExtServerName, sni("example.com"))
	if report := CompareTLS(mustParse(t, base.records()), mustParse(t, other.records())); !report.OK() {
		t.Errorf("server_name and padding:\n%s", report)
	}
}

func TestShapesThatDoNotParse(t *testing.T) {
	hello := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtEncryptedClientHello, []byte{1, 2, 3}).
		withExtension(ExtPreSharedKey, []byte{9}).records())
	if fixed, payload := echShape(hello); fixed != "unreadable, 3 bytes" || payload != "(none)" {
		t.Errorf("ECH: %q, %q", fixed, payload)
	}
	if got := pskShape(hello); got != "unreadable, 1 byte" {
		t.Errorf("pre_shared_key: %q", got)
	}
	none := mustParse(t, newHello().withCiphers(0x1301).records())
	if fixed, payload := echShape(none); fixed != "(none)" || payload != "(none)" {
		t.Errorf("no ECH: %q, %q", fixed, payload)
	}
	for _, tc := range []struct {
		body []byte
		want string
	}{
		{psk([]int{4}, []int{32}), "1 identity, binders of 32 bytes"},
		{psk([]int{4, 4}, []int{32, 48}), "2 identities, binders of 32, 48 bytes"},
		{psk([]int{4}, nil), "1 identity, no binder"},
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtPreSharedKey, tc.body).records())
		if got := pskShape(hello); got != tc.want {
			t.Errorf("pskShape = %q, want %q", got, tc.want)
		}
	}
	unknown := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtEncryptedClientHello, echBody(9, 9, 144)).records())
	if fixed, _ := echShape(unknown); fixed != "0x0009, 0x0009, key 32 bytes" {
		t.Errorf("an unknown suite: %q", fixed)
	}
}
