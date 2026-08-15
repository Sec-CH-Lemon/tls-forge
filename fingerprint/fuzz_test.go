package fingerprint

import (
	"os"
	"testing"
)

// Fuzzing the ClientHello parser.
//
// This is the one place in the project that reads bytes chosen by someone else.
// `tls-forge serve` can be told to listen on a public interface, and everything
// it reports is decoded from whatever the peer put on the wire before any
// handshake completed, so a malformed hello is not a hypothetical.
//
// Statement coverage says nothing about this. The parser's error paths are all
// exercised by the unit tests and still leave the question open: those tests
// only ask about the malformed inputs someone thought of.
//
// The contract is narrow on purpose. The parser may return an error for
// anything, and must return one rather than panic, read past the end of its
// input, or loop forever. Whatever it does return must be self-consistent,
// which the accessors below check by walking it.
func FuzzParseClientHello(f *testing.F) {
	if raw, err := os.ReadFile("../testdata/chrome151-clienthello.bin"); err == nil {
		f.Add(raw)
	}
	// The shapes that break length-prefixed parsers: nothing, a truncated
	// record header, a header claiming more than it carries, and a hello whose
	// extensions run off the end of the record.
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, records []byte) {
		hello, err := ParseClientHello(records)
		if err != nil {
			if hello != nil {
				t.Fatalf("both a hello and an error: %v", err)
			}
			return
		}
		if hello == nil {
			t.Fatal("neither a hello nor an error")
		}

		// Every accessor, on the theory that a parser can produce a value that
		// only falls over when something reads it.
		hello.ExtensionTypes()
		hello.ServerName()
		hello.ALPN()
		hello.SupportedVersions()
		hello.SupportedGroups()
		hello.SignatureAlgorithms()
		hello.CertCompressionAlgorithms()
		hello.KeyShareGroups()

		// And the fingerprints, which are what the parse exists to produce.
		hello.JA3()
		hello.JA3Hash()
		hello.JA4()
		hello.JA4Raw()
		TLSFields(hello)
	})
}
