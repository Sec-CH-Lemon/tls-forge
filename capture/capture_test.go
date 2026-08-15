package capture

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// The fixture is a real Chrome 151 ClientHello, recorded off the wire. Tests
// here use it rather than a hand-built one so that a change to the rendering is
// checked against bytes a browser actually sent.
func chromeHello(t *testing.T) *fingerprint.ClientHello {
	t.Helper()
	raw, err := os.ReadFile("../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	hello, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return hello
}

func TestFromClientHello(t *testing.T) {
	rendered := FromClientHello(chromeHello(t))

	if want := "t13d1516h2_8daaf6152771_806a8c22fdea"; rendered.JA4 != want {
		t.Errorf("JA4 = %s, want %s", rendered.JA4, want)
	}
	if rendered.Resumed {
		t.Error("a cold hello was rendered as resumed")
	}
	if rendered.ServerName != "localhost" {
		t.Errorf("ServerName = %q", rendered.ServerName)
	}
	if got, want := rendered.ALPN, []string{"h2", "http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ALPN = %v, want %v", got, want)
	}
	if got, want := rendered.LegacyVersion.Name, "TLS 1.2"; got != want {
		t.Errorf("LegacyVersion = %q, want %q", got, want)
	}

	// The point of Value is that the JSON is readable without a registry.
	if rendered.SignatureAlgorithms[0].Name != "mldsa44" {
		t.Errorf("first signature algorithm = %q, want mldsa44", rendered.SignatureAlgorithms[0].Name)
	}
	if rendered.CertCompression[0].Name != "brotli" {
		t.Errorf("certificate compression = %q, want brotli", rendered.CertCompression[0].Name)
	}
}

func TestCertCompressionNames(t *testing.T) {
	for value, want := range map[uint16]string{1: "zlib", 2: "brotli", 3: "zstd", 9: "0x0009"} {
		if got := certCompressionName(value); got != want {
			t.Errorf("certCompressionName(%d) = %q, want %q", value, got, want)
		}
	}
}

func TestFromHTTP2(t *testing.T) {
	source := &fingerprint.HTTP2{
		Settings:     []fingerprint.Setting{{ID: 1, Value: 65536}, {ID: 4, Value: 6291456}},
		WindowUpdate: 15663105,
		Priorities:   []fingerprint.Priority{{StreamID: 3, Weight: 200}},
		HeaderPriority: &fingerprint.Priority{
			StreamID: 1, Exclusive: true, Weight: 255,
		},
		Headers: []fingerprint.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: "user-agent", Value: "Mozilla/5.0"},
		},
	}

	rendered := FromHTTP2(source)
	if rendered.Settings[0].Name != "HEADER_TABLE_SIZE" {
		t.Errorf("setting name = %q", rendered.Settings[0].Name)
	}
	if got, want := rendered.HeaderOrder, []string{"user-agent"}; !reflect.DeepEqual(got, want) {
		t.Errorf("HeaderOrder = %v, want %v", got, want)
	}
	if rendered.HeaderPriority == nil || !rendered.HeaderPriority.Exclusive {
		t.Errorf("HeaderPriority = %+v", rendered.HeaderPriority)
	}

	// Round-tripping must be lossless: a comparison reads the converted form,
	// so anything dropped here is a difference that can never be reported.
	back := rendered.Fingerprint()
	if back.Akamai() != source.Akamai() {
		t.Errorf("round trip changed the fingerprint: %s vs %s", back.Akamai(), source.Akamai())
	}
	if !reflect.DeepEqual(back.Priorities, source.Priorities) {
		t.Errorf("round trip lost priorities: %v", back.Priorities)
	}
	if !reflect.DeepEqual(back.HeaderPriority, source.HeaderPriority) {
		t.Errorf("round trip lost the header priority: %v", back.HeaderPriority)
	}
}

func TestFromHTTP2AndFingerprintOnNil(t *testing.T) {
	if got := FromHTTP2(nil); got != nil {
		t.Errorf("FromHTTP2(nil) = %v, want nil", got)
	}
	var absent *HTTP2
	if got := absent.Fingerprint(); got != nil {
		t.Errorf("(*HTTP2)(nil).Fingerprint() = %v, want nil", got)
	}
}

func TestHelloReparsesTheAuthoritativeBytes(t *testing.T) {
	raw, err := os.ReadFile("../testdata/chrome151-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	c := &Capture{RawClientHello: raw}
	hello, err := c.Hello()
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if hello.JA4() != "t13d1516h2_8daaf6152771_806a8c22fdea" {
		t.Errorf("JA4 = %s", hello.JA4())
	}
}

func TestHelloErrors(t *testing.T) {
	if _, err := (&Capture{}).Hello(); err == nil {
		t.Error("a capture with no ClientHello should not produce one")
	}
	if _, err := (&Capture{RawClientHello: []byte{1, 2, 3}}).Hello(); err == nil {
		t.Error("unparseable bytes should be reported")
	}
}

func TestUserAgent(t *testing.T) {
	fromHeaders := &Capture{HTTP2: &HTTP2{Headers: []HeaderField{
		{Name: "user-agent", Value: "from-headers"},
	}}}
	if got := fromHeaders.UserAgent(); got != "from-headers" {
		t.Errorf("UserAgent = %q", got)
	}

	// The header is preferred: it is what the server actually saw, and it is the
	// one that has to agree with the handshake.
	both := &Capture{
		HTTP2:     &HTTP2{Headers: []HeaderField{{Name: "user-agent", Value: "from-headers"}}},
		Navigator: &Navigator{UserAgent: "from-javascript"},
	}
	if got := both.UserAgent(); got != "from-headers" {
		t.Errorf("UserAgent = %q, want the header's value", got)
	}

	onlyNavigator := &Capture{Navigator: &Navigator{UserAgent: "from-javascript"}}
	if got := onlyNavigator.UserAgent(); got != "from-javascript" {
		t.Errorf("UserAgent = %q", got)
	}

	if got := (&Capture{}).UserAgent(); got != "" {
		t.Errorf("UserAgent = %q, want empty", got)
	}
	if got := (&Capture{HTTP2: &HTTP2{}}).UserAgent(); got != "" {
		t.Errorf("UserAgent = %q, want empty", got)
	}
}

func TestCaptureRoundTripsThroughJSON(t *testing.T) {
	// A capture is written to disk and read back on another machine, so the
	// round trip has to be lossless — particularly the raw bytes.
	original := &Capture{
		Source:         SourceBrowser,
		RawClientHello: []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01},
		TLS:            TLS{JA4: "t13d1516h2_x_y"},
		Navigator:      &Navigator{UserAgent: "test", Languages: []string{"en-GB"}},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Capture
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original.RawClientHello, decoded.RawClientHello) {
		t.Errorf("raw bytes changed: %v vs %v", decoded.RawClientHello, original.RawClientHello)
	}
	if decoded.Navigator.Languages[0] != "en-GB" {
		t.Errorf("navigator lost data: %+v", decoded.Navigator)
	}
}
