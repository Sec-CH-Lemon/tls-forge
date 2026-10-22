package profile

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v4/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v4/fingerprint"
	"github.com/igor-lemon/fhttp/http2/hpack"
	tls "github.com/igor-lemon/utls"
)

func chromeHelloBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

func withRawExtension(t *testing.T, raw []byte, id uint16, data []byte) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	if len(out) < 44 || out[0] != 0x16 || out[5] != 0x01 {
		t.Fatal("fixture is not a complete ClientHello record")
	}

	// Skip the fixed ClientHello prefix, then its three length-prefixed vectors
	// to reach the extension block's uint16 length.
	pos := 9 + 2 + 32
	vector8 := func() {
		if pos >= len(out) {
			t.Fatal("truncated ClientHello vector")
		}
		pos += 1 + int(out[pos])
	}
	vector16 := func() {
		if pos+2 > len(out) {
			t.Fatal("truncated ClientHello vector")
		}
		n := int(binary.BigEndian.Uint16(out[pos : pos+2]))
		pos += 2 + n
	}
	vector8()  // legacy_session_id
	vector16() // cipher_suites
	vector8()  // legacy_compression_methods
	if pos+2 > len(out) {
		t.Fatal("ClientHello has no extension block")
	}
	extensionsLenAt := pos
	extensionsLen := int(binary.BigEndian.Uint16(out[pos : pos+2]))
	pos += 2
	if pos+extensionsLen != len(out) {
		t.Fatal("fixture has trailing or truncated ClientHello bytes")
	}

	addition := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(addition[0:2], id)
	binary.BigEndian.PutUint16(addition[2:4], uint16(len(data)))
	copy(addition[4:], data)
	out = append(out, addition...)
	binary.BigEndian.PutUint16(out[extensionsLenAt:extensionsLenAt+2], uint16(extensionsLen+len(addition)))
	binary.BigEndian.PutUint16(out[3:5], uint16(len(out)-5))
	handshakeLen := len(out) - 9
	out[6] = byte(handshakeLen >> 16)
	out[7] = byte(handshakeLen >> 8)
	out[8] = byte(handshakeLen)
	return out
}

func TestSpecFromCapturedClientHello(t *testing.T) {
	p := &Profile{EngineMajor: Major(4), Name: "test", ClientHello: chromeHelloBytes(t)}

	spec, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if got, want := len(spec.CipherSuites), 16; got != want {
		t.Errorf("ciphers = %d, want %d", got, want)
	}
	// The capture's 18, and the pre_shared_key the browser resumes a session
	// with, last.
	if got, want := len(spec.Extensions), 19; got != want {
		t.Errorf("extensions = %d, want %d", got, want)
	}
	if _, ok := spec.Extensions[len(spec.Extensions)-1].(*tls.UtlsPreSharedKeyExtension); !ok {
		t.Errorf("the last extension is %T, want the pre_shared_key slot", spec.Extensions[len(spec.Extensions)-1])
	}

	// Fresh on every call. utls extensions are pointers with mutable state, and a
	// spec shared between connections is a spec whose key share is reused —
	// which is both a bug and a fingerprint, since no browser reuses one.
	again, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if &spec.Extensions[0] == &again.Extensions[0] {
		t.Error("Spec returned a shared extension slice")
	}
}

func TestSpecRejectsBluntMimicry(t *testing.T) {
	// Every extension a captured Chrome sends must map to a real utls type. If
	// one ever falls through to a replayed blob, the ECH GREASE payload — random
	// per connection in a browser — becomes a constant, which is a unique marker
	// on every request this library makes. Failing loudly is the point.
	spec, err := (&Profile{EngineMajor: Major(4), Name: "chrome", ClientHello: chromeHelloBytes(t)}).Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if name := reflect.TypeOf(ext).String(); strings.Contains(name, "GenericExtension") {
			t.Fatalf("%s is a replayed blob, not an extension that regenerates per connection", name)
		}
	}

	// The ECH extension is the one that matters most here: its payload is random
	// per connection in a real browser, so it must have become a live GREASE ECH
	// extension rather than a recording of one.
	var sawECH bool
	for _, ext := range spec.Extensions {
		if strings.Contains(reflect.TypeOf(ext).String(), "EncryptedClientHello") {
			sawECH = true
		}
	}
	if !sawECH {
		t.Error("the captured ECH extension did not survive into the spec")
	}

	unknown := withRawExtension(t, chromeHelloBytes(t), 0x1234, []byte{1, 2, 3})
	if _, err := (&Profile{EngineMajor: Major(4), Name: "unknown", ClientHello: unknown}).Spec(); err == nil ||
		!strings.Contains(err.Error(), "unsupported extension 4660") {
		t.Errorf("unknown extension error = %v", err)
	}
}

func TestSpecAllowsMeasuredTrustAnchors(t *testing.T) {
	// In byte order, as Chrome 154 and later send them: as captured. Out of
	// it, as an older Chrome sent them: the captured IDs, in the order this
	// process drew for them.
	for _, captured := range [][]byte{{0, 4, 1, 0xaa, 1, 0xbb}, {0, 4, 1, 0xbb, 1, 0xaa}} {
		raw := withRawExtension(t, chromeHelloBytes(t), fingerprint.ExtTrustAnchors, captured)
		sent := trustAnchorsSent(t, &Profile{EngineMajor: Major(4), Name: "chrome_152", ClientHello: raw})
		if sent == nil {
			t.Fatal("trust_anchors did not survive into the spec")
		}
		want, err := splitTrustAnchors(captured)
		if err != nil {
			t.Fatal(err)
		}
		if inByteOrder(want) && !bytes.Equal(sent, captured) {
			t.Errorf("trust_anchors = %x, want them as captured, %x", sent, captured)
		}
		got, err := splitTrustAnchors(sent)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(want, func(i, j int) bool { return bytes.Compare(want[i], want[j]) < 0 })
		sort.Slice(got, func(i, j int) bool { return bytes.Compare(got[i], got[j]) < 0 })
		if !reflect.DeepEqual(got, want) {
			t.Errorf("trust_anchors = %x, want the captured IDs %x", got, want)
		}
	}
}

// trustAnchorsSent is the trust_anchors payload of p's spec, nil for none.
func trustAnchorsSent(t *testing.T, p *Profile) []byte {
	t.Helper()
	spec, err := p.Spec()
	if err != nil {
		t.Fatalf("%s: Spec: %v", p.Name, err)
	}
	return trustAnchorsIn(spec)
}

// trustAnchorsIn is the trust_anchors payload of spec, nil for none.
func trustAnchorsIn(spec tls.ClientHelloSpec) []byte {
	for _, extension := range spec.Extensions {
		if generic, ok := extension.(*tls.GenericExtension); ok && generic.Id == fingerprint.ExtTrustAnchors {
			return generic.Data
		}
	}
	return nil
}

func TestSpecFromBase(t *testing.T) {
	spec, err := (&Profile{EngineMajor: Major(4), Name: "borrowed", Base: "chrome_133"}).Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("base profile produced an empty spec")
	}
}

func TestSpecErrors(t *testing.T) {
	if _, err := (&Profile{EngineMajor: Major(4), Name: "empty"}).Spec(); err == nil {
		t.Error("a profile with neither a hello nor a base cannot produce a spec")
	}
	if _, err := (&Profile{EngineMajor: Major(4), Name: "bad-base", Base: "netscape_4"}).Spec(); err == nil {
		t.Error("an unknown base should be reported")
	}
	if _, err := (&Profile{EngineMajor: Major(4), Name: "junk", ClientHello: []byte{1, 2, 3}}).Spec(); err == nil {
		t.Error("unparseable bytes should be reported")
	}
}

func TestClientProfileFromCapturedHello(t *testing.T) {
	p := &Profile{EngineMajor: Major(4),
		Name:        "test",
		ClientHello: chromeHelloBytes(t),
		HTTP2: HTTP2{
			Settings:          []Setting{{ID: 1, Value: 65536}, {ID: 4, Value: 6291456}},
			ConnectionFlow:    15663105,
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			Priorities:        []Priority{{StreamID: 3, Weight: 200}},
			HeaderPriority:    &Priority{StreamID: 1, Exclusive: true, Weight: 255},
		},
	}

	built, err := p.ClientProfile()
	if err != nil {
		t.Fatalf("ClientProfile: %v", err)
	}
	if got, want := built.GetConnectionFlow(), uint32(15663105); got != want {
		t.Errorf("connection flow = %d, want %d", got, want)
	}
	if got, want := len(built.GetSettingsOrder()), 2; got != want {
		t.Errorf("settings order = %d entries, want %d", got, want)
	}
	if got := built.GetSettings()[1]; got != 65536 {
		t.Errorf("HEADER_TABLE_SIZE = %d", got)
	}
	if got, want := built.GetStreamID(), uint32(1); got != want {
		t.Errorf("stream id = %d, want %d (the default when unset)", got, want)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	original := &Profile{EngineMajor: Major(4),
		Name: "browser", ClientHello: []byte{1}, Headers: []Field{{Name: "accept"}},
		ClientHints: []Field{{Name: "dpr", Value: "1"}},
		HTTP1: &HTTP1{HeaderOrder: []string{"Host", "accept"},
			Headers: []Field{{Name: "accept", Value: "text/plain"}}},
		HTTP2: HTTP2{
			Settings: []Setting{{ID: 1}}, PseudoHeaderOrder: []string{":method"},
			Priorities: []Priority{{StreamID: 1}}, HeaderPriority: &Priority{StreamID: 3},
		},
	}
	cloned := original.Clone()
	cloned.ClientHello[0] = 2
	cloned.Headers[0].Name = "changed"
	cloned.ClientHints[0].Value = "2"
	cloned.HTTP1.HeaderOrder[0] = "changed"
	cloned.HTTP1.Headers[0].Value = "changed"
	cloned.HTTP2.Settings[0].ID = 2
	cloned.HTTP2.PseudoHeaderOrder[0] = ":path"
	cloned.HTTP2.Priorities[0].StreamID = 5
	cloned.HTTP2.HeaderPriority.StreamID = 7

	if original.ClientHello[0] != 1 || original.Headers[0].Name != "accept" || original.ClientHints[0].Value != "1" ||
		original.HTTP1.HeaderOrder[0] != "Host" || original.HTTP1.Headers[0].Value != "text/plain" ||
		original.HTTP2.Settings[0].ID != 1 || original.HTTP2.PseudoHeaderOrder[0] != ":method" ||
		original.HTTP2.Priorities[0].StreamID != 1 || original.HTTP2.HeaderPriority.StreamID != 3 {
		t.Errorf("clone mutated the original: %+v", original)
	}
	var absent *Profile
	if absent.Clone() != nil {
		t.Error("a nil profile clone should stay nil")
	}
}

func TestClientProfileUsesTheBaseVerbatim(t *testing.T) {
	// A profile that only names a base IS that base. Rebuilding it from parts
	// would be a second, drifting copy of settings this library does not own.
	built, err := (&Profile{EngineMajor: Major(4), Name: "chrome_133", Base: "chrome_133"}).ClientProfile()
	if err != nil {
		t.Fatalf("ClientProfile: %v", err)
	}
	if got := built.GetClientHelloStr(); !strings.Contains(strings.ToLower(got), "chrome") {
		t.Errorf("client hello id = %q, want the base's", got)
	}
}

func TestClientProfileErrors(t *testing.T) {
	if _, err := (&Profile{EngineMajor: Major(4), Name: "x", Base: "nope"}).ClientProfile(); err == nil {
		t.Error("an unknown base should be reported")
	}
	if _, err := (&Profile{EngineMajor: Major(4), Name: "x"}).ClientProfile(); err == nil {
		t.Error("a profile that cannot handshake should be reported")
	}
	if _, err := (&Profile{EngineMajor: Major(4), Name: "x", Base: "chrome_133",
		HTTP1: &HTTP1{HeaderOrder: []string{"accept"}}}).ClientProfile(); err == nil {
		t.Error("ClientProfile accepted an invalid HTTP/1 section")
	}
	// A profile that names an unknown base AND carries HTTP/2 settings is not a
	// bare base, so it takes the assembly path — which must still fail rather
	// than build a client profile around a handshake it could not resolve.
	broken := &Profile{EngineMajor: Major(4), Name: "x", Base: "nope", HTTP2: HTTP2{Settings: []Setting{{ID: 1}}}}
	if _, err := broken.ClientProfile(); err == nil {
		t.Error("an unknown base should be reported from the assembly path too")
	}
	for _, order := range [][]string{
		nil,
		{":method", ":authority", ":scheme"},
		{":method", ":authority", ":scheme", ":scheme"},
		{":method", ":authority", ":scheme", ":unknown"},
	} {
		p := &Profile{EngineMajor: Major(4), Name: "x", ClientHello: chromeHelloBytes(t), HTTP2: HTTP2{PseudoHeaderOrder: order}}
		if _, err := p.ClientProfile(); err == nil || !strings.Contains(err.Error(), "pseudo_header_order") {
			t.Errorf("ClientProfile accepted pseudo header order %v: %v", order, err)
		}
	}
}

func TestStreamIDIsHonouredWhenSet(t *testing.T) {
	p := &Profile{EngineMajor: Major(4),
		Name:        "test",
		ClientHello: chromeHelloBytes(t),
		HTTP2: HTTP2{Settings: []Setting{{ID: 1, Value: 1}}, StreamID: 7,
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}},
	}
	built, err := p.ClientProfile()
	if err != nil {
		t.Fatalf("ClientProfile: %v", err)
	}
	if got, want := built.GetStreamID(), uint32(7); got != want {
		t.Errorf("stream id = %d, want %d", got, want)
	}
}

func TestHeaderAccessors(t *testing.T) {
	p := &Profile{EngineMajor: Major(4), Headers: []Field{
		{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
		{Name: "user-agent", Value: "Mozilla/5.0"},
	}}
	if got, want := p.HeaderOrder(), []string{"sec-ch-ua", "user-agent"}; !reflect.DeepEqual(got, want) {
		t.Errorf("HeaderOrder = %v, want %v", got, want)
	}
	if got, ok := p.Header("USER-AGENT"); !ok || got != "Mozilla/5.0" {
		t.Errorf("Header = %q, %v", got, ok)
	}
	if _, ok := p.Header("cookie"); ok {
		t.Error("Header reported one that is not there")
	}
}

func TestLoadAndSave(t *testing.T) {
	original := &Profile{EngineMajor: Major(4),
		Name:        "chrome_151",
		UserAgent:   "Mozilla/5.0",
		ClientHello: chromeHelloBytes(t),
		HTTP2: HTTP2{Settings: []Setting{{ID: 1, Value: 65536}},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}},
		Headers: []Field{{Name: "accept", Value: "*/*"}},
		HTTP1: &HTTP1{HeaderOrder: []string{"Host", "accept", "Connection"},
			Headers: []Field{{Name: "Connection", Value: "keep-alive"}}},
		Notes: "captured 2026-08-15",
	}

	saved, err := original.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if saved[len(saved)-1] != '\n' {
		t.Error("saved profile should end with a newline")
	}

	loaded, err := Load(saved)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Saved in the current schema, whatever it was in; nothing else changes,
	// and the profile saved is not touched.
	want := *original
	want.Schema = Schema
	want.Behavior = original.RuntimeBehavior().Clone()
	delete(want.Behavior, "tls.ech_payload_lengths")
	if original.PerConnection == nil {
		want.PerConnection = &PerConnection{ShufflesExtensions: original.ShufflesExtensions(), ECHPayloadLengths: original.echPayloadLengths()}
	}
	if !reflect.DeepEqual(loaded, &want) || original.Schema != 0 {
		t.Errorf("round trip changed the profile:\n got %+v\nwant %+v", loaded, &want)
	}
}

func TestAProfileIsReadAsItsSchemaSays(t *testing.T) {
	read := func(document string) (*Profile, error) { return Load([]byte(document)) }
	// Written before there was a schema: read as it always was, what the
	// format does not have passed over.
	legacy, err := read(`{"engine_major":4,"name":"old","base":"chrome_133","heders":[{"name":"a","value":"b"}]}`)
	if err != nil || legacy.Name != "old" || legacy.Schema != 0 || legacy.Headers != nil {
		t.Errorf("a profile with no schema: %+v, %v", legacy, err)
	}
	if current, err := read(`{"engine_major":4,"schema":1,"name":"new","base":"chrome_133"}`); err != nil || current.Schema != 1 {
		t.Errorf("schema 1: %+v, %v", current, err)
	}
	for _, tc := range []struct{ name, document, want string }{
		{"a field spelt wrong", `{"engine_major":4,"schema":1,"name":"x","base":"chrome_133","heders":[]}`, `unknown field "heders"`},
		{"one spelt wrong inside another", `{"engine_major":4,"schema":1,"name":"x","base":"chrome_133","http2":{"setings":[]}}`,
			`unknown field "setings"`},
		{"a newer schema", `{"engine_major":4,"schema":5,"name":"x"}`, "schema 5 is newer than this tls-forge reads, 4"},
		{"schema 2 is as strict", `{"engine_major":4,"schema":2,"name":"x","base":"chrome_133","heders":[]}`, `unknown field "heders"`},
		{"client hints in schema 1", `{"engine_major":4,"schema":1,"name":"x","base":"chrome_133",` +
			`"client_hints":[{"name":"sec-ch-ua-arch","value":"\"arm\""}]}`, "schema 1 has no client_hints"},
		{"schema 0", `{"engine_major":4,"schema":0,"name":"x"}`, "schema 0 is not one"},
		{"a schema below it", `{"engine_major":4,"schema":-3,"name":"x"}`, "schema -3 is not one"},
		{"a schema that is no number", `{"engine_major":4,"schema":"1","name":"x"}`, "cannot unmarshal string"},
		{"more after the profile", `{"engine_major":4,"schema":1,"name":"x","base":"chrome_133"} {}`, "extra data"},
	} {
		if _, err := read(tc.document); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load([]byte("{")); err == nil {
		t.Error("malformed JSON should be reported")
	}
	if _, err := Load([]byte(`{"engine_major":4,"user_agent":"x"}`)); err == nil {
		t.Error("a profile without a name should be reported")
	}
	if _, err := Load([]byte(`{"engine_major":4,"name":"x","base":"chrome_133","http2":{"settings":[{"id":1}]}}`)); err == nil || !strings.Contains(err.Error(), "pseudo_header_order") {
		t.Errorf("a profile without pseudo headers was accepted: %v", err)
	}
	for _, section := range []string{
		`{"header_order":[]}`,
		`{"header_order":["Host","host"]}`,
		`{"header_order":["accept","Host"]}`,
		`{"header_order":["Host",":path"]}`,
		`{"header_order":["Host"],"headers":[{"name":"Host","value":"x"}]}`,
		`{"header_order":["Host"],"headers":[{"name":"Connection","value":"close"}]}`,
	} {
		_, err := Load([]byte(`{"engine_major":4,"name":"x","base":"chrome_133","http1":` + section + `}`))
		if err == nil || !strings.Contains(err.Error(), "http1") {
			t.Errorf("invalid HTTP/1 section %s was accepted: %v", section, err)
		}
	}
	legacy, err := Load([]byte(`{"engine_major":4,"name":"old","base":"chrome_133"}`))
	if err != nil || legacy.HTTP1 != nil {
		t.Errorf("legacy profile no longer loads: %+v, %v", legacy, err)
	}
}

func TestAProfilesClientHintsAreOnesAServerAsksFor(t *testing.T) {
	load := func(hints string) error {
		_, err := Load([]byte(`{"engine_major":4,"schema":2,"name":"x","base":"chrome_133","client_hints":[` + hints + `]}`))
		return err
	}
	if err := load(`{"name":"sec-ch-ua-arch","value":"\"arm\""},{"name":"rtt","value":"100"},` +
		`{"name":"sec-ch-ua-model","value":"\"\""}`); err != nil {
		t.Errorf("valid hints: %v", err)
	}
	for _, tc := range []struct{ hints, says string }{
		{`{"name":"sec-ch-ua-foo","value":"1"}`, `"sec-ch-ua-foo" is no client hint a server asks for`},
		{`{"name":"Sec-CH-UA-Arch","value":"1"}`, `"Sec-CH-UA-Arch" is no client hint`},
		{`{"name":"sec-ch-ua","value":"1"}`, `"sec-ch-ua" is no client hint a server asks for`},
		{`{"name":"sec-ch-ua-mobile","value":"?0"}`, `"sec-ch-ua-mobile" is no client hint`},
		{`{"name":"sec-ch-ua-platform","value":"\"macOS\""}`, `"sec-ch-ua-platform" is no client hint`},
		{`{"name":"save-data","value":"on"}`, `"save-data" is no client hint`},
		{`{"name":"dpr","value":"1"},{"name":"dpr","value":"2"}`, "client hint dpr is said twice"},
		{`{"name":"dpr","value":""}`, "client hint dpr has no value a header can carry"},
		{`{"name":"dpr","value":"1\r\nX: y"}`, "client hint dpr has no value a header can carry"},
	} {
		if err := load(tc.hints); err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want %q", tc.hints, err, tc.says)
		}
	}
	// The error names the hints there are, which are Chrome's but the three
	// it always sends.
	err := load(`{"name":"x","value":"1"}`)
	if err == nil || !strings.Contains(err.Error(), "device-memory, sec-ch-device-memory") ||
		strings.Contains(err.Error(), "sec-ch-ua,") || !strings.Contains(err.Error(), "sec-ch-prefers-reduced-transparency") {
		t.Errorf("%v", err)
	}
}

func TestShufflesExtensionsByBrowserFamily(t *testing.T) {
	for _, tc := range []struct {
		profile Profile
		want    bool
	}{
		{profile: Profile{EngineMajor: Major(4), Name: "chrome_151"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "brave_146"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "opera_91"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "custom", Base: "chrome_133"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "custom", UserAgent: "Mozilla/5.0 Chrome/151.0"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "firefox_148"}, want: false},
		{profile: Profile{EngineMajor: Major(4), Name: "safari_18_5"}, want: false},
		// Chrome on Android is Chrome; on iOS it is Apple's stack under another
		// name, said by the platform in its name or by its user agent.
		{profile: Profile{EngineMajor: Major(4), Name: "chrome_138_android"}, want: true},
		{profile: Profile{EngineMajor: Major(4), Name: "chrome_138_ios"}, want: false},
		{profile: Profile{EngineMajor: Major(4), Name: "chrome_138", UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) CriOS/138.0"}, want: false},
		{profile: Profile{EngineMajor: Major(4), Name: "chrome_138", UserAgent: "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) CriOS/138.0"}, want: false},
		{profile: Profile{EngineMajor: Major(4), Name: "custom", Base: "safari_ios_18_5"}, want: false},
	} {
		if got := tc.profile.ShufflesExtensions(); got != tc.want {
			t.Errorf("%q ShufflesExtensions = %v, want %v", tc.profile.Name, got, tc.want)
		}
		// What a browser context is measured on is the same family.
		if got := tc.profile.Chromium(); got != tc.want {
			t.Errorf("%q Chromium = %v, want %v", tc.profile.Name, got, tc.want)
		}
	}
}

func TestEncodeJSONReportsFailures(t *testing.T) {
	// Not reachable through Profile, whose fields are all encodable — but the
	// error is returned rather than swallowed so that adding a field json cannot
	// encode fails loudly instead of writing a truncated profile.
	if _, err := encodeJSON(make(chan int)); err == nil {
		t.Error("expected an error for a value json cannot encode")
	}
}

func TestFromCapture(t *testing.T) {
	measured := &capture.Capture{
		RawClientHello: chromeHelloBytes(t),
		HTTP2: &capture.HTTP2{
			Settings:          []capture.Setting{{ID: 1, Value: 65536}},
			WindowUpdate:      15663105,
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			Priorities:        []capture.Priority{{StreamID: 3, Weight: 200}},
			HeaderPriority:    &capture.Priority{StreamID: 1, Exclusive: true, Weight: 255},
			Headers: []capture.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
				{Name: "user-agent", Value: "Mozilla/5.0 Chrome/151"},
				{Name: "cookie", Value: "session=secret"},
				{Name: "referer", Value: "https://example.com"},
				{Name: "content-length", Value: "0"},
				{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			},
		},
		HTTP1: &capture.HTTP1{
			Method:      "GET",
			Path:        "/",
			Proto:       "HTTP/1.1",
			HeaderOrder: []string{"host", "sec-ch-ua", "user-agent", "connection", "cookie"},
			HeaderNames: []string{"Host", "sec-ch-ua", "User-Agent", "Connection", "Cookie"},
			Headers: []capture.HeaderField{
				{Name: "host", Value: "localhost"},
				{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
				{Name: "user-agent", Value: "Mozilla/5.0 Chrome/151"},
				{Name: "connection", Value: "keep-alive"},
				{Name: "cookie", Value: "session=secret"},
			},
		},
		Navigator: &capture.Navigator{UserAgent: "Mozilla/5.0 Chrome/151"},
	}

	built, err := FromCapture("chrome_151", measured)
	if err != nil {
		t.Fatalf("FromCapture: %v", err)
	}
	if built.Schema != Schema {
		t.Errorf("a profile captured is in schema %d", built.Schema)
	}

	if got, want := built.HeaderOrder(), []string{"sec-ch-ua", "user-agent", "accept-encoding"}; !reflect.DeepEqual(got, want) {
		t.Errorf("headers = %v, want %v", got, want)
	}
	// Per-request headers must not survive into a profile: a replayed cookie
	// pins a dead session and a replayed referer describes someone else's click.
	for _, forbidden := range []string{"cookie", "referer", "content-length"} {
		if _, ok := built.Header(forbidden); ok {
			t.Errorf("profile carried the per-request header %q", forbidden)
		}
	}
	if got, want := built.HTTP2.PseudoHeaderOrder,
		[]string{":method", ":authority", ":scheme", ":path"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pseudo header order = %v, want %v", got, want)
	}
	if built.HTTP1 == nil {
		t.Fatal("HTTP/1 capture was not stored")
	}
	if got, want := built.HTTP1.HeaderOrder,
		[]string{"Host", "sec-ch-ua", "User-Agent", "Connection"}; !reflect.DeepEqual(got, want) {
		t.Errorf("HTTP/1 order = %v, want %v", got, want)
	}
	if got, want := built.HTTP1.Headers,
		[]Field{{Name: "Connection", Value: "keep-alive"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("HTTP/1-specific headers = %v, want %v", got, want)
	}
	if built.HTTP2.ConnectionFlow != 15663105 {
		t.Errorf("connection flow = %d", built.HTTP2.ConnectionFlow)
	}
	if built.HTTP2.HeaderPriority == nil || built.HTTP2.HeaderPriority.Weight != 255 {
		t.Errorf("header priority = %+v", built.HTTP2.HeaderPriority)
	}
	if len(built.HTTP2.Priorities) != 1 {
		t.Errorf("priorities = %v", built.HTTP2.Priorities)
	}
	if built.UserAgent != "Mozilla/5.0 Chrome/151" {
		t.Errorf("user agent = %q", built.UserAgent)
	}
	measured.RawClientHello[0] ^= 0xff
	if built.ClientHello[0] == measured.RawClientHello[0] {
		t.Error("profile aliases the capture's ClientHello bytes")
	}
}

func TestFromCaptureWithoutHTTP2(t *testing.T) {
	_, err := FromCapture("plain", &capture.Capture{RawClientHello: chromeHelloBytes(t)})
	if err == nil || !strings.Contains(err.Error(), "no HTTP/2") {
		t.Fatalf("FromCapture error = %v, want missing HTTP/2 data", err)
	}
}

func TestHTTP1ProfileConversionEdgeCases(t *testing.T) {
	if got := http1FromCapture(nil, nil); got != nil {
		t.Errorf("nil capture = %+v", got)
	}
	if got := http1FromCapture(&capture.HTTP1{}, nil); got != nil {
		t.Errorf("empty capture = %+v", got)
	}
	if got := http1FromCapture(&capture.HTTP1{Headers: []capture.HeaderField{
		{Name: "cookie", Value: "private=1"},
	}}, nil); got != nil {
		t.Errorf("per-request-only capture = %+v", got)
	}

	// Old captures have no HeaderNames. Their lower-case parsed names remain a
	// valid, conservative fallback, and repeated values retain their wire order.
	got := http1FromCapture(&capture.HTTP1{Headers: []capture.HeaderField{
		{Name: "host", Value: "example.test"},
		{Name: "x-repeat", Value: "one"},
		{Name: "x-repeat", Value: "two"},
		{Name: "user-agent", Value: "h1-agent"},
	}}, []Field{
		{Name: "x-repeat", Value: "one"},
		{Name: "user-agent", Value: "h2-agent"},
	})
	if got == nil {
		t.Fatal("legacy HTTP/1 capture was discarded")
		return
	}
	if want := []string{"host", "x-repeat", "user-agent"}; !reflect.DeepEqual(got.HeaderOrder, want) {
		t.Errorf("order = %v, want %v", got.HeaderOrder, want)
	}
	wantFields := []Field{
		{Name: "x-repeat", Value: "one"},
		{Name: "x-repeat", Value: "two"},
		{Name: "user-agent", Value: "h1-agent"},
	}
	if !reflect.DeepEqual(got.Headers, wantFields) {
		t.Errorf("overrides = %+v, want %+v", got.Headers, wantFields)
	}
}

func TestFromCaptureErrors(t *testing.T) {
	if _, err := FromCapture("", &capture.Capture{}); err == nil {
		t.Error("an empty profile name should be rejected")
	}
	for _, tc := range []struct {
		name string
		in   *capture.Capture
		want string
	}{
		{"nil", nil, "nil capture"},
		{"no hello", &capture.Capture{}, "no ClientHello"},
		{"unparseable hello", &capture.Capture{RawClientHello: []byte{1, 2, 3}}, "fingerprint:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromCapture("x", tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestFromCaptureRefusesAHelloThatNamesNoServer(t *testing.T) {
	// Chrome 155.0.8059.85 opened https://127.0.0.1:PORT/ (capture --manual
	// --host 127.0.0.1, 2026-10-19): a browser names no server to an address,
	// and a profile of that hello sent none to localhost either, JA4 t13i1516
	// where Chrome's to a name is t13d1517. Its JA4 said too, it is refused all
	// the same; the same browser at a name is not.
	atAnAddress, err := os.ReadFile("../testdata/chrome155-clienthello-at-an-address.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	hello, err := fingerprint.ParseClientHello(atAnAddress)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, named := hello.Extension(fingerprint.ExtServerName); named || hello.JA4() != "t13i1516h2_8daaf6152771_cb7bf5808d99" {
		t.Fatalf("the fixture names a server, or is another hello: %s", hello.JA4())
	}
	atAName, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		tls  capture.TLS
		ok   bool
	}{
		{"at an address", atAnAddress, capture.TLS{}, false},
		{"at an address, its JA4 said", atAnAddress, capture.FromClientHello(hello), false},
		{"at a name", atAName, capture.TLS{}, true},
	} {
		_, err := FromCapture("chrome_155", &capture.Capture{RawClientHello: tc.raw, TLS: tc.tls, HTTP2: &capture.HTTP2{
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			Headers:           []capture.HeaderField{{Name: ":method", Value: "GET"}},
		}})
		if tc.ok != (err == nil) || !tc.ok && !strings.Contains(err.Error(), "names no server (no server_name)") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestFromCaptureRefusesAResumedHandshake(t *testing.T) {
	// A resumed hello carries pre_shared_key, so its JA4 is not the one a server
	// sees on first contact. Building a profile from it would produce something
	// that matches the browser about half the time — the worst possible outcome,
	// because it looks like it works. The bytes say which it is; what the
	// capture says of them is held to them.
	cold := chromeHelloBytes(t)
	resumed, err := os.ReadFile("../testdata/chrome155-clienthello-resumed.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// A pre_shared_key that does not parse is one all the same.
	malformed := withExtension(t, chromeHelloBytes(t), fingerprint.ExtPreSharedKey, []byte{0xff})
	rendered := func(raw []byte, resumed bool) capture.TLS {
		hello, err := fingerprint.ParseClientHello(raw)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		out := capture.FromClientHello(hello)
		out.Resumed = resumed
		return out
	}
	const ok, refused, contradicts = "", "RESUMED", "not one capture"
	for _, tc := range []struct {
		name string
		raw  []byte
		tls  capture.TLS
		want string
	}{
		{"cold, said cold", cold, rendered(cold, false), ok},
		{"cold, said resumed", cold, rendered(cold, true), contradicts},
		{"cold, nothing said", cold, capture.TLS{}, ok},
		{"resumed, said resumed", resumed, rendered(resumed, true), refused},
		{"resumed, said cold", resumed, rendered(resumed, false), contradicts},
		{"resumed, nothing said", resumed, capture.TLS{}, refused},
		{"a malformed pre_shared_key, nothing said", malformed, capture.TLS{}, refused},
		{"a malformed pre_shared_key, said cold", malformed, rendered(malformed, false), contradicts},
		{"another hello's JA4", cold, rendered(resumed, false), contradicts},
	} {
		measured := &capture.Capture{RawClientHello: tc.raw, TLS: tc.tls, HTTP2: &capture.HTTP2{
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			Headers:           []capture.HeaderField{{Name: ":method", Value: "GET"}},
		}}
		_, err := FromCapture("chrome", measured)
		switch {
		case tc.want == ok && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != ok && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want it to say %q", tc.name, err, tc.want)
		}
	}
}

// withExtension is a hello record with one more extension, last, its lengths
// set again.
func withExtension(t *testing.T, raw []byte, typ uint16, data []byte) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	// read is the big-endian number of n bytes at at.
	read := func(at, n int) int {
		v := 0
		for _, b := range out[at : at+n] {
			v = v<<8 | int(b)
		}
		return v
	}
	put := func(at, n, v int) {
		for i := range n {
			out[at+n-1-i] = byte(v >> (8 * i))
		}
	}
	// The record's header, the message's, its version and random; then the
	// session id, the cipher suites and the compression methods.
	at := 5 + 4 + 2 + 32
	at += 1 + read(at, 1)
	at += 2 + read(at, 2)
	at += 1 + read(at, 1)
	extensions := at
	out = append(out, byte(typ>>8), byte(typ), byte(len(data)>>8), byte(len(data)))
	out = append(out, data...)
	grow := 4 + len(data)
	put(3, 2, read(3, 2)+grow)
	put(6, 3, read(6, 3)+grow)
	put(extensions, 2, read(extensions, 2)+grow)
	if _, err := fingerprint.ParseClientHello(out); err != nil {
		t.Fatalf("withExtension: %v", err)
	}
	return out
}

func TestWithResumption(t *testing.T) {
	// A hello that offers no psk_key_exchange_modes resumes nothing, and gets no
	// slot to.
	cold := tls.ClientHelloSpec{Extensions: []tls.TLSExtension{&tls.SNIExtension{}, &tls.UtlsGREASEExtension{}}}
	if got := withResumption(cold); len(got.Extensions) != 2 {
		t.Errorf("a hello with no PSK modes got %d extensions", len(got.Extensions))
	}
	// One that has a pre_shared_key already, a hello captured on a resumed
	// connection, keeps the one it has.
	raw, err := os.ReadFile("../testdata/chrome155-clienthello-resumed.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	spec, err := (&Profile{EngineMajor: Major(4), Name: "resumed", ClientHello: raw}).Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	psks := 0
	for _, extension := range spec.Extensions {
		if _, ok := extension.(tls.PreSharedKeyExtension); ok {
			psks++
		}
	}
	if psks != 1 {
		t.Errorf("a hello with a pre_shared_key has %d of them", psks)
	}
}

func TestPseudoNamesIgnoresUnknownLetters(t *testing.T) {
	got := pseudoNames(&capture.HTTP2{PseudoHeaderOrder: []string{"m", "z", "p"}})
	if want := []string{":method", ":path"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pseudoNames = %v, want %v", got, want)
	}
}

func TestAChromiumProfileWritesHeadersAndWindowsAsChromeDoes(t *testing.T) {
	// As Chrome 155 wrote them (testdata/chrome155-hpack.json): a
	// pseudo-header but :authority without indexing, named by the first
	// static entry of its name; any other field with incremental indexing,
	// one too large for the table too; against a table as large as a server
	// allows.
	pseudo := hpack.Representation{WithoutIndexing: true, FirstStaticName: true}
	indexed := hpack.Representation{IndexTooLarge: true}
	fields := []struct {
		field hpack.HeaderField
		want  hpack.Representation
	}{
		{hpack.HeaderField{Name: ":path", Value: "/a"}, pseudo},
		{hpack.HeaderField{Name: ":method", Value: "PUT"}, pseudo},
		{hpack.HeaderField{Name: ":scheme", Value: "wss"}, pseudo},
		{hpack.HeaderField{Name: ":protocol", Value: "websocket"}, pseudo},
		{hpack.HeaderField{Name: ":authority", Value: "a"}, indexed},
		{hpack.HeaderField{Name: "cookie", Value: strings.Repeat("a", 5000)}, indexed},
		{hpack.HeaderField{Name: "x-a", Value: "1"}, indexed},
		{hpack.HeaderField{Name: "authority", Value: "a"}, indexed},
	}
	for name, tc := range map[string]struct {
		p      *Profile
		chrome bool
	}{
		"a captured Chrome on macOS":   {mustGet(t, "chrome_155_macos"), true},
		"a captured Chrome on Linux":   {mustGet(t, "chrome_155_linux"), true},
		"a captured Chrome on Windows": {mustGet(t, "chrome_155_windows"), true},
		"Chrome from the catalogue":    {&Profile{EngineMajor: Major(4), Name: "chrome_133", Base: "chrome_133"}, true},
		"Firefox from the catalogue":   {&Profile{EngineMajor: Major(4), Name: "firefox_148", Base: "firefox_148"}, false},
		"Chrome on an iPhone":          {&Profile{EngineMajor: Major(4), Name: "chrome_ios", Base: "safari_ios_18_0", UserAgent: "CriOS iPhone"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			built, err := tc.p.ClientProfile()
			if err != nil {
				t.Fatalf("ClientProfile: %v", err)
			}
			of := built.GetHeaderRepresentation()
			if (of != nil) != tc.chrome {
				t.Fatalf("writes headers as Chromium: %v", of != nil)
			}
			if limit, want := built.GetMaxEncoderHeaderTableSize(), map[bool]uint32{true: math.MaxUint32}[tc.chrome]; limit != want {
				t.Errorf("a table of at most %d bytes, want %d", limit, want)
			}
			// And tells a server of its windows as Chrome does: a little
			// after five seconds.
			if delay, want := built.GetWindowUpdateDelay(), map[bool]time.Duration{true: 5 * time.Second}[tc.chrome]; delay != want {
				t.Errorf("waits %s to tell of a little of a window, want %s", delay, want)
			}
			// And cuts header blocks and bodies into frames, and writes TLS
			// records and HTTP/1.1 requests, as Chrome does.
			if payload, want := built.GetMaxHeaderFramePayload(), map[bool]uint32{true: 16374}[tc.chrome]; payload != want {
				t.Errorf("header frames of at most %d bytes, want %d", payload, want)
			}
			if payload, want := built.GetMaxDataFramePayload(), map[bool]uint32{true: 16375}[tc.chrome]; payload != want {
				t.Errorf("DATA frames of at most %d bytes, want %d", payload, want)
			}
			if disabled := built.GetDynamicRecordSizingDisabled(); disabled != tc.chrome {
				t.Errorf("TLS records as large as its writes: %v", disabled)
			}
			if merged, want := built.GetMaxMergedHeadAndBody(), map[bool]int{true: 1400}[tc.chrome]; merged != want {
				t.Errorf("an HTTP/1.1 head and body merged up to %d bytes, want %d", merged, want)
			}
			// And waits for a stream on a connection it holds, as Chrome does.
			if strict := built.GetStrictMaxConcurrentStreams(); strict != tc.chrome {
				t.Errorf("waits for a stream: %v", strict)
			}
			// And sends its request before a TLS 1.2 server's Finished, as
			// Chrome does.
			if early := built.GetFalseStart(); early != tc.chrome {
				t.Errorf("false starts: %v", early)
			}
			if of == nil {
				return
			}
			for _, f := range fields {
				if r := of(f.field); r != f.want {
					t.Errorf("%s written %+v, want %+v", f.field.Name, r, f.want)
				}
			}
		})
	}
}

func mustGet(t *testing.T, name string) *Profile {
	t.Helper()
	p, err := Get(name)
	if err != nil {
		t.Fatalf("Get(%s): %v", name, err)
	}
	return p
}
