package profile

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

func chromeHelloBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

func TestSpecFromCapturedClientHello(t *testing.T) {
	p := &Profile{Name: "test", ClientHello: chromeHelloBytes(t)}

	spec, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if got, want := len(spec.CipherSuites), 16; got != want {
		t.Errorf("ciphers = %d, want %d", got, want)
	}
	if got, want := len(spec.Extensions), 18; got != want {
		t.Errorf("extensions = %d, want %d", got, want)
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
	spec, err := (&Profile{Name: "chrome", ClientHello: chromeHelloBytes(t)}).Spec()
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
}

func TestSpecFromBase(t *testing.T) {
	spec, err := (&Profile{Name: "borrowed", Base: "chrome_133"}).Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("base profile produced an empty spec")
	}
}

func TestSpecErrors(t *testing.T) {
	if _, err := (&Profile{Name: "empty"}).Spec(); err == nil {
		t.Error("a profile with neither a hello nor a base cannot produce a spec")
	}
	if _, err := (&Profile{Name: "bad-base", Base: "netscape_4"}).Spec(); err == nil {
		t.Error("an unknown base should be reported")
	}
	if _, err := (&Profile{Name: "junk", ClientHello: []byte{1, 2, 3}}).Spec(); err == nil {
		t.Error("unparseable bytes should be reported")
	}
}

func TestClientProfileFromCapturedHello(t *testing.T) {
	p := &Profile{
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
	original := &Profile{
		Name: "browser", ClientHello: []byte{1}, Headers: []Field{{Name: "accept"}},
		HTTP2: HTTP2{
			Settings: []Setting{{ID: 1}}, PseudoHeaderOrder: []string{":method"},
			Priorities: []Priority{{StreamID: 1}}, HeaderPriority: &Priority{StreamID: 3},
		},
	}
	cloned := original.Clone()
	cloned.ClientHello[0] = 2
	cloned.Headers[0].Name = "changed"
	cloned.HTTP2.Settings[0].ID = 2
	cloned.HTTP2.PseudoHeaderOrder[0] = ":path"
	cloned.HTTP2.Priorities[0].StreamID = 5
	cloned.HTTP2.HeaderPriority.StreamID = 7

	if original.ClientHello[0] != 1 || original.Headers[0].Name != "accept" ||
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
	built, err := (&Profile{Name: "chrome_133", Base: "chrome_133"}).ClientProfile()
	if err != nil {
		t.Fatalf("ClientProfile: %v", err)
	}
	if got := built.GetClientHelloStr(); !strings.Contains(strings.ToLower(got), "chrome") {
		t.Errorf("client hello id = %q, want the base's", got)
	}
}

func TestClientProfileErrors(t *testing.T) {
	if _, err := (&Profile{Name: "x", Base: "nope"}).ClientProfile(); err == nil {
		t.Error("an unknown base should be reported")
	}
	if _, err := (&Profile{Name: "x"}).ClientProfile(); err == nil {
		t.Error("a profile that cannot handshake should be reported")
	}
	// A profile that names an unknown base AND carries HTTP/2 settings is not a
	// bare base, so it takes the assembly path — which must still fail rather
	// than build a client profile around a handshake it could not resolve.
	broken := &Profile{Name: "x", Base: "nope", HTTP2: HTTP2{Settings: []Setting{{ID: 1}}}}
	if _, err := broken.ClientProfile(); err == nil {
		t.Error("an unknown base should be reported from the assembly path too")
	}
	for _, order := range [][]string{
		nil,
		{":method", ":authority", ":scheme"},
		{":method", ":authority", ":scheme", ":scheme"},
		{":method", ":authority", ":scheme", ":unknown"},
	} {
		p := &Profile{Name: "x", ClientHello: chromeHelloBytes(t), HTTP2: HTTP2{PseudoHeaderOrder: order}}
		if _, err := p.ClientProfile(); err == nil || !strings.Contains(err.Error(), "pseudo_header_order") {
			t.Errorf("ClientProfile accepted pseudo header order %v: %v", order, err)
		}
	}
}

func TestStreamIDIsHonouredWhenSet(t *testing.T) {
	p := &Profile{
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
	p := &Profile{Headers: []Field{
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
	original := &Profile{
		Name:        "chrome_151",
		UserAgent:   "Mozilla/5.0",
		ClientHello: chromeHelloBytes(t),
		HTTP2: HTTP2{Settings: []Setting{{ID: 1, Value: 65536}},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}},
		Headers: []Field{{Name: "accept", Value: "*/*"}},
		Notes:   "captured 2026-08-15",
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
	if !reflect.DeepEqual(loaded, original) {
		t.Errorf("round trip changed the profile:\n got %+v\nwant %+v", loaded, original)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load([]byte("{")); err == nil {
		t.Error("malformed JSON should be reported")
	}
	if _, err := Load([]byte(`{"user_agent":"x"}`)); err == nil {
		t.Error("a profile without a name should be reported")
	}
	if _, err := Load([]byte(`{"name":"x","base":"chrome_133","http2":{"settings":[{"id":1}]}}`)); err == nil || !strings.Contains(err.Error(), "pseudo_header_order") {
		t.Errorf("a profile without pseudo headers was accepted: %v", err)
	}
}

func TestShufflesExtensionsByBrowserFamily(t *testing.T) {
	for _, tc := range []struct {
		profile Profile
		want    bool
	}{
		{profile: Profile{Name: "chrome_151"}, want: true},
		{profile: Profile{Name: "brave_146"}, want: true},
		{profile: Profile{Name: "opera_91"}, want: true},
		{profile: Profile{Name: "custom", Base: "chrome_133"}, want: true},
		{profile: Profile{Name: "custom", UserAgent: "Mozilla/5.0 Chrome/151.0"}, want: true},
		{profile: Profile{Name: "firefox_148"}, want: false},
		{profile: Profile{Name: "safari_18_5"}, want: false},
	} {
		if got := tc.profile.ShufflesExtensions(); got != tc.want {
			t.Errorf("%q ShufflesExtensions = %v, want %v", tc.profile.Name, got, tc.want)
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
		Navigator: &capture.Navigator{UserAgent: "Mozilla/5.0 Chrome/151"},
	}

	built, err := FromCapture("chrome_151", measured)
	if err != nil {
		t.Fatalf("FromCapture: %v", err)
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

func TestFromCaptureRefusesAResumedHandshake(t *testing.T) {
	// A resumed hello carries pre_shared_key, so its JA4 is not the one a server
	// sees on first contact. Building a profile from it would produce something
	// that matches the browser about half the time — the worst possible outcome,
	// because it looks like it works.
	raw := chromeHelloBytes(t)
	hello, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	rendered := capture.FromClientHello(hello)
	rendered.Resumed = true

	_, err = FromCapture("chrome", &capture.Capture{RawClientHello: raw, TLS: rendered})
	if err == nil || !strings.Contains(err.Error(), "RESUMED") {
		t.Fatalf("error = %v, want it to explain the resumption", err)
	}
}

func TestPseudoNamesIgnoresUnknownLetters(t *testing.T) {
	got := pseudoNames(&capture.HTTP2{PseudoHeaderOrder: []string{"m", "z", "p"}})
	if want := []string{":method", ":path"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pseudoNames = %v, want %v", got, want)
	}
}
