package fingerprint

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseClientHello(t *testing.T) {
	hello, err := ParseClientHello(chrome151().records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got, want := hello.LegacyVersion, uint16(0x0303); got != want {
		t.Errorf("legacy version = %#04x, want %#04x", got, want)
	}
	if got, want := len(hello.CipherSuites), 16; got != want {
		t.Errorf("cipher suites = %d, want %d", got, want)
	}
	if got, want := len(hello.Extensions), 18; got != want {
		t.Errorf("extensions = %d, want %d", got, want)
	}
	if got, want := len(hello.Random), 32; got != want {
		t.Errorf("random = %d bytes, want %d", got, want)
	}
	if got, want := hello.CompressionMethods, []byte{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("compression = %v, want %v", got, want)
	}
}

func TestParseClientHelloRawIsTrimmedToTheHello(t *testing.T) {
	records := chrome151().records()
	// A real recorder reads whatever the kernel hands it, which routinely
	// includes bytes past the hello. Raw must not depend on how the stream was
	// chopped up, or a capture would round-trip differently every time.
	withExtra := append(append([]byte(nil), records...), 0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5)

	hello, err := ParseClientHello(withExtra)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(hello.Raw), len(records); got != want {
		t.Fatalf("Raw = %d bytes, want %d", got, want)
	}

	again, err := ParseClientHello(hello.Raw)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if again.JA4() != hello.JA4() {
		t.Errorf("re-parsing Raw changed the fingerprint: %s vs %s", again.JA4(), hello.JA4())
	}
}

func TestParseClientHelloAcrossRecords(t *testing.T) {
	message := handshakeMessage(typeClientHello, chrome151().body())
	whole, err := ParseClientHello(recordsOf(message))
	if err != nil {
		t.Fatalf("parse whole: %v", err)
	}
	fragmented, err := ParseClientHello(splitRecords(message, 64))
	if err != nil {
		t.Fatalf("parse fragmented: %v", err)
	}
	if whole.JA4() != fragmented.JA4() {
		t.Errorf("fragmentation changed the fingerprint: %s vs %s", fragmented.JA4(), whole.JA4())
	}
}

func TestParseClientHelloWithoutExtensions(t *testing.T) {
	// Legal in TLS 1.2 and must not read as an error.
	builder := newHello().withCiphers(0x1301)
	hello, err := ParseClientHello(builder.records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hello.Extensions) != 0 {
		t.Errorf("extensions = %d, want 0", len(hello.Extensions))
	}
	// TLS 1.2, no SNI, one cipher, no extensions, no ALPN.
	if got, want := hello.JA4(), "t12i010000_"; got[:len(want)] != want {
		t.Errorf("JA4 = %q, want it to start %q", got, want)
	}
}

func TestParseClientHelloErrors(t *testing.T) {
	full := chrome151().records()

	for _, tc := range []struct {
		name  string
		input []byte
		is    error
		want  string
	}{
		{name: "empty", input: nil, want: "no TLS records"},
		{name: "truncated record header", input: full[:3], want: "truncated TLS record"},
		{name: "record shorter than it claims", input: full[:20], want: "truncated TLS record"},
		{
			// A complete, well-formed record carrying only the start of a
			// handshake message: the records ran out before the message did.
			name:  "hello spans records that never arrive",
			input: recordsOf(handshakeMessage(typeClientHello, chrome151().body())[:10]),
			want:  "incomplete ClientHello",
		},
		{
			name:  "not a handshake record",
			input: []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00},
			is:    ErrNotClientHello,
		},
		{
			name:  "a ServerHello, not a ClientHello",
			input: recordsOf(handshakeMessage(0x02, chrome151().body())),
			is:    ErrNotClientHello,
		},
		{
			name:  "truncated at random",
			input: recordsOf(handshakeMessage(typeClientHello, []byte{0x03, 0x03, 0x00})),
			want:  "truncated at random",
		},
		{
			name:  "truncated at legacy_version",
			input: recordsOf(handshakeMessage(typeClientHello, []byte{0x03})),
			want:  "truncated at legacy_version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClientHello(tc.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("error = %v, want %v", err, tc.is)
			}
			if tc.want != "" && !contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseClientHelloMalformedBody(t *testing.T) {
	// Each case truncates a length-prefixed field so the parser runs out of
	// bytes exactly where that field is read.
	base := chrome151().body()
	for _, tc := range []struct {
		name string
		cut  int
		want string
	}{
		{"session id", 34, "truncated at session_id"},
		{"cipher suites", 36, "malformed cipher_suites"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClientHello(recordsOf(handshakeMessage(typeClientHello, base[:tc.cut])))
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseClientHelloOddCipherList(t *testing.T) {
	body := newHello().withCiphers(0x1301).body()
	// Claim one more byte of ciphers than the list can hold an even number of.
	body[35] = 3
	_, err := ParseClientHello(recordsOf(handshakeMessage(typeClientHello, body)))
	if err == nil || !contains(err.Error(), "cipher_suites") {
		t.Fatalf("error = %v, want a cipher_suites complaint", err)
	}
}

func TestParseClientHelloMalformedExtensions(t *testing.T) {
	body := chrome151().body()
	// Chop the extension block mid-extension.
	_, err := ParseClientHello(recordsOf(handshakeMessage(typeClientHello, body[:len(body)-3])))
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseClientHelloOversized(t *testing.T) {
	// A handshake header that claims more than the reassembly limit, delivered
	// in records that keep arriving.
	body := make([]byte, 1<<17+16)
	_, err := ParseClientHello(splitRecords(handshakeMessage(typeClientHello, body), 16384))
	if err == nil || !contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want a size complaint", err)
	}
}

func TestAccessors(t *testing.T) {
	hello, err := ParseClientHello(chrome151().records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if name, ok := hello.ServerName(); !ok || name != "tls.peet.ws" {
		t.Errorf("ServerName = %q, %v", name, ok)
	}
	if got, want := hello.ALPN(), []string{"h2", "http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ALPN = %v, want %v", got, want)
	}
	if got, want := hello.ApplicationSettings(), []string{"h2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ApplicationSettings = %v, want %v", got, want)
	}
	if got, want := withoutGREASE(hello.SupportedGroups()), []uint16{4588, 29, 23, 24}; !reflect.DeepEqual(got, want) {
		t.Errorf("SupportedGroups = %v, want %v", got, want)
	}
	if got, want := withoutGREASE(hello.KeyShareGroups()), []uint16{4588, 29}; !reflect.DeepEqual(got, want) {
		t.Errorf("KeyShareGroups = %v, want %v", got, want)
	}
	if got, want := withoutGREASE(hello.SupportedVersions()), []uint16{0x0304, 0x0303}; !reflect.DeepEqual(got, want) {
		t.Errorf("SupportedVersions = %v, want %v", got, want)
	}
	if got, want := hello.ECPointFormats(), []uint8{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("ECPointFormats = %v, want %v", got, want)
	}
	if got, want := hello.PSKKeyExchangeModes(), []uint8{1}; !reflect.DeepEqual(got, want) {
		t.Errorf("PSKKeyExchangeModes = %v, want %v", got, want)
	}
	if got, want := hello.CertCompressionAlgorithms(), []uint16{2}; !reflect.DeepEqual(got, want) {
		t.Errorf("CertCompressionAlgorithms = %v, want %v", got, want)
	}
	if got := hello.SignatureAlgorithms(); len(got) != 11 || got[0] != 0x0904 {
		t.Errorf("SignatureAlgorithms = %v", got)
	}
	if _, ok := hello.Extension(ExtPreSharedKey); ok {
		t.Error("a cold hello should not carry pre_shared_key")
	}
}

func TestAccessorsOnAbsentAndMalformedExtensions(t *testing.T) {
	bare, err := ParseClientHello(newHello().withCiphers(0x1301).records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if name, ok := bare.ServerName(); ok || name != "" {
		t.Errorf("ServerName on a hello without one = %q, %v", name, ok)
	}
	for name, got := range map[string]any{
		"ALPN":                bare.ALPN(),
		"ApplicationSettings": bare.ApplicationSettings(),
		"SupportedGroups":     bare.SupportedGroups(),
		"KeyShareGroups":      bare.KeyShareGroups(),
		"SignatureAlgorithms": bare.SignatureAlgorithms(),
		"ECPointFormats":      bare.ECPointFormats(),
		"PSKKeyExchangeModes": bare.PSKKeyExchangeModes(),
		"CertCompression":     bare.CertCompressionAlgorithms(),
		"SupportedVersions":   bare.SupportedVersions(),
	} {
		if !reflect.ValueOf(got).IsNil() {
			t.Errorf("%s on a hello without one = %v, want nil", name, got)
		}
	}

	// Malformed bodies return nothing rather than panicking: this parser reads
	// hostile input by definition.
	broken, err := ParseClientHello(newHello().
		withCiphers(0x1301).
		withExtension(ExtServerName, []byte{0xff}).
		withExtension(ExtALPN, []byte{0xff}).
		withExtension(ExtSupportedGroups, []byte{0xff}).
		withExtension(ExtKeyShare, []byte{0xff}).
		withExtension(ExtApplicationSettings, []byte{0xff}).
		withExtension(ExtECPointFormats, []byte{}).
		records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if name, ok := broken.ServerName(); ok {
		t.Errorf("ServerName on a malformed extension = %q", name)
	}
	if got := broken.ALPN(); got != nil {
		t.Errorf("ALPN on a malformed extension = %v", got)
	}
	if got := broken.SupportedGroups(); got != nil {
		t.Errorf("SupportedGroups on a malformed extension = %v", got)
	}
	if got := broken.KeyShareGroups(); got != nil {
		t.Errorf("KeyShareGroups on a malformed extension = %v", got)
	}
	if got := broken.ApplicationSettings(); got != nil {
		t.Errorf("ApplicationSettings on a malformed extension = %v", got)
	}
}

func TestServerNameSkipsUnknownNameTypes(t *testing.T) {
	// One entry of a type nobody uses, then the hostname. The parser must not
	// stop at the first entry.
	list := append([]byte{9}, 0x00, 0x02, 'x', 'y')
	list = append(list, 0x00, 0x00, 0x03, 'a', 'b', 'c')
	body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)

	hello, err := ParseClientHello(newHello().withCiphers(0x1301).
		withExtension(ExtServerName, body).records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if name, ok := hello.ServerName(); !ok || name != "abc" {
		t.Errorf("ServerName = %q, %v; want \"abc\"", name, ok)
	}
}

func TestServerNameWithNoHostEntry(t *testing.T) {
	list := []byte{9, 0x00, 0x02, 'x', 'y'}
	body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	hello, err := ParseClientHello(newHello().withCiphers(0x1301).
		withExtension(ExtServerName, body).records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := hello.ServerName(); ok {
		t.Error("expected no server name")
	}
}

func TestExtensionReturnsTheFirstOfADuplicate(t *testing.T) {
	hello, err := ParseClientHello(newHello().withCiphers(0x1301).
		withExtension(ExtALPN, alpn("first")).
		withExtension(ExtALPN, alpn("second")).
		records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := hello.ALPN(), []string{"first"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ALPN = %v, want %v", got, want)
	}
}

func TestExtensionTypesKeepsWireOrder(t *testing.T) {
	hello, err := ParseClientHello(chrome151().records())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	types := hello.ExtensionTypes()
	if types[0] != 0x1a1a || types[len(types)-1] != 0xaaaa {
		t.Errorf("extension order not preserved: %v", types)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
