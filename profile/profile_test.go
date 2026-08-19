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
}

func TestStreamIDIsHonouredWhenSet(t *testing.T) {
	p := &Profile{
		Name:        "test",
		ClientHello: chromeHelloBytes(t),
		HTTP2:       HTTP2{Settings: []Setting{{ID: 1, Value: 1}}, StreamID: 7},
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
		HTTP2:       HTTP2{Settings: []Setting{{ID: 1, Value: 65536}}},
		Headers:     []Field{{Name: "accept", Value: "*/*"}},
		Notes:       "captured 2026-08-15",
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
}

func TestFromCaptureWithoutHTTP2(t *testing.T) {
	built, err := FromCapture("plain", &capture.Capture{RawClientHello: chromeHelloBytes(t)})
	if err != nil {
		t.Fatalf("FromCapture: %v", err)
	}
	if len(built.Headers) != 0 {
		t.Errorf("headers = %v, want none", built.Headers)
	}
}

func TestFromCaptureErrors(t *testing.T) {
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

func TestHeadersFromACapture(t *testing.T) {
	if got := Headers(nil); got != nil {
		t.Errorf("Headers(nil) = %v", got)
	}
	if got := Headers(&capture.Capture{}); got != nil {
		t.Errorf("Headers(no HTTP/2) = %v", got)
	}
	got := Headers(&capture.Capture{HTTP2: &capture.HTTP2{Headers: []capture.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: "Accept", Value: "*/*"},
		{Name: "cookie", Value: "a=b"},
		{Name: "x-browser-year", Value: "2026"},
	}}})
	want := []Field{
		{Name: "accept", Value: "*/*"},
		{Name: "x-browser-year", Value: "2026"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Headers = %v, want %v", got, want)
	}
}

func fields(pairs ...string) []Field {
	out := make([]Field, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Field{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func TestGoogleBlockFindsWhatTheSecondCaptureAdded(t *testing.T) {
	ordinary := fields("accept", "*/*", "sec-fetch-site", "none")
	google := fields("accept", "*/*", "x-browser-year", "2026", "x-client-data", "c=", "sec-fetch-site", "none")

	block, err := GoogleBlock(ordinary, google)
	if err != nil {
		t.Fatalf("GoogleBlock: %v", err)
	}
	if block.After != "accept" {
		t.Errorf("after = %q, want accept", block.After)
	}
	if got := names(block.Headers); len(got) != 2 || got[0] != "x-browser-year" || got[1] != "x-client-data" {
		t.Errorf("headers = %v", got)
	}
	// The whole point of storing a block rather than a list: it splices back
	// into what was measured.
	if !sameFields(block.Into(ordinary), google) {
		t.Errorf("the block does not reproduce the capture:\n%v", block.Into(ordinary))
	}
}

func TestGoogleBlockAtTheFront(t *testing.T) {
	block, err := GoogleBlock(fields("accept", "*/*"), fields("x-first", "1", "accept", "*/*"))
	if err != nil {
		t.Fatalf("GoogleBlock: %v", err)
	}
	if block.After != "" {
		t.Errorf("after = %q, want empty for a block that came first", block.After)
	}
}

func TestGoogleBlockWithNothingExtra(t *testing.T) {
	// Every browser that is not Google Chrome. Not an error, and nothing to keep.
	block, err := GoogleBlock(fields("accept", "*/*"), fields("accept", "*/*"))
	if block != nil || err != nil {
		t.Errorf("block = %+v, err = %v", block, err)
	}
}

func TestGoogleBlockRefusesWhatItCannotReproduce(t *testing.T) {
	// Two pieces rather than one block: splicing them together would replay an
	// order nobody saw.
	_, err := GoogleBlock(
		fields("accept", "*/*", "user-agent", "ua"),
		fields("accept", "*/*", "x-one", "1", "user-agent", "ua", "x-two", "2"))
	if err == nil {
		t.Error("a scattered block was accepted")
	}

	// The two captures disagreeing about a header they share is the same
	// problem wearing different clothes: the difference is not just a block.
	if _, err := GoogleBlock(
		fields("accept", "*/*"),
		fields("accept", "text/html", "x-one", "1")); err == nil {
		t.Error("captures that differ elsewhere were accepted")
	}

	// A header the ordinary capture had and the Google one did not. The block
	// would describe a list one header longer than the one measured.
	if _, err := GoogleBlock(
		fields("accept", "*/*", "priority", "u=0, i"),
		fields("accept", "*/*", "x-one", "1")); err == nil {
		t.Error("a capture missing a header was accepted")
	}
}

func TestGoogleBlockInto(t *testing.T) {
	base := fields("accept", "*/*", "sec-fetch-site", "none")

	var absent *Google
	if got := absent.Into(base); !sameFields(got, base) {
		t.Errorf("a nil block changed the list: %v", got)
	}
	if got := (&Google{}).Into(base); !sameFields(got, base) {
		t.Errorf("an empty block changed the list: %v", got)
	}

	front := (&Google{Headers: fields("x-first", "1")}).Into(base)
	if front[0].Name != "x-first" {
		t.Errorf("a block with no anchor did not go first: %v", names(front))
	}

	// An anchor edited out of the profile by hand. Sending the headers in the
	// wrong place is visible; not sending them is not.
	stray := (&Google{After: "nonesuch", Headers: fields("x-last", "1")}).Into(base)
	if stray[len(stray)-1].Name != "x-last" {
		t.Errorf("a block with a missing anchor was dropped: %v", names(stray))
	}
}
