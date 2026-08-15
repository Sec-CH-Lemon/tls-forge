package fingerprint

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// A parser that reads from the network reads hostile input by definition. These
// cases are the ones a fuzzer finds first: a length prefix that promises more
// than the buffer holds, at every level of nesting. None of them may panic, and
// each must return "nothing" rather than a half-read value that would look like
// a real fingerprint.

func TestParseStopsAtEachTruncationPoint(t *testing.T) {
	// Built up field by field so each case is the previous one plus the header
	// of the field it truncates.
	prefix := func() []byte {
		out := binary.BigEndian.AppendUint16(nil, 0x0303)
		out = append(out, make([]byte, 32)...) // random
		out = append(out, 0)                   // empty session id
		out = binary.BigEndian.AppendUint16(out, 2)
		return binary.BigEndian.AppendUint16(out, 0x1301) // one cipher
	}

	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"no compression_methods", prefix(), "truncated at compression_methods"},
		{"extension length missing a byte", append(prefix(), 1, 0, 0x00), "truncated at extensions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClientHello(recordsOf(handshakeMessage(typeClientHello, tc.body)))
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseHandshakeHeaderSplitAcrossRecords(t *testing.T) {
	// Fewer than the four bytes of the handshake header have arrived. The
	// message cannot be sized yet, so the reader must wait rather than guess.
	_, err := ParseClientHello(recordsOf([]byte{typeClientHello, 0x00}))
	if err == nil || !contains(err.Error(), "incomplete ClientHello") {
		t.Fatalf("error = %v, want an incomplete-hello complaint", err)
	}
}

func TestAccessorsOnTruncatedInnerVectors(t *testing.T) {
	// Each body has a well-formed outer length prefix and a truncated entry
	// inside it, which is the shape a naive parser reads past.
	truncatedSNI := []byte{0x00, 0x04, 0x00, 0x00, 0x0a, 0x00}
	truncatedALPN := []byte{0x00, 0x04, 0x01, 'a', 0x09, 'b'}
	// A valid share for X25519, then one for P-256 whose key length runs off the
	// end of the list. The outer prefix is honest; only the second entry lies.
	truncatedKeyShare := []byte{0x00, 0x08, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x17, 0xff, 0xff}

	hello := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtServerName, truncatedSNI).
		withExtension(ExtALPN, truncatedALPN).
		withExtension(ExtKeyShare, truncatedKeyShare).
		withExtension(ExtApplicationSettings, truncatedALPN).
		records())

	if name, ok := hello.ServerName(); ok {
		t.Errorf("ServerName on a truncated entry = %q, want none", name)
	}
	// A partially-read list returns what it managed to read and stops. Reporting
	// nothing would hide the extension entirely; reading on would invent
	// entries.
	if got, want := hello.ALPN(), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ALPN = %v, want %v", got, want)
	}
	if got, want := hello.ApplicationSettings(), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ApplicationSettings = %v, want %v", got, want)
	}
	if got, want := hello.KeyShareGroups(), []uint16{29}; !reflect.DeepEqual(got, want) {
		t.Errorf("KeyShareGroups = %v, want %v", got, want)
	}
}

func TestExtensionBlockWithATruncatedEntry(t *testing.T) {
	// The extension block's own length is honest; the extension inside it
	// claims more bytes than the block has left. A parser that trusted the inner
	// length would read into whatever followed.
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)

	extensions := []byte{0x00, 0x0a, 0x00, 0x05, 0x01, 0x02}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	_, err := ParseClientHello(recordsOf(handshakeMessage(typeClientHello, body)))
	if err == nil || !contains(err.Error(), "malformed extension") {
		t.Fatalf("error = %v, want a malformed-extension complaint", err)
	}
}

func TestUint16VectorRejectsAnOddLength(t *testing.T) {
	// A list of uint16s whose byte length is odd cannot be what it claims.
	hello := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtSupportedGroups, []byte{0x00, 0x03, 0x00, 0x1d, 0x00}).
		records())
	if got := hello.SupportedGroups(); got != nil {
		t.Errorf("SupportedGroups = %v, want nil", got)
	}
}

func TestVectorBodyWithATruncatedOuterPrefix(t *testing.T) {
	hello := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtSupportedGroups, []byte{0xff}).
		withExtension(ExtSupportedVersions, []byte{0xff}).
		withExtension(ExtECPointFormats, []byte{0xff}).
		records())

	if got := hello.SupportedGroups(); got != nil {
		t.Errorf("SupportedGroups = %v, want nil", got)
	}
	if got := hello.SupportedVersions(); got != nil {
		t.Errorf("SupportedVersions = %v, want nil", got)
	}
	if got := hello.ECPointFormats(); got != nil {
		t.Errorf("ECPointFormats = %v, want nil", got)
	}
}
