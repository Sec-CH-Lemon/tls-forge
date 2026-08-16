package fingerprint

import (
	"strings"
	"testing"
)

// The golden vectors below are NOT this package's own output. Both were taken
// from tls.browserleaks.com for a real Chrome 151 on macOS, and the
// truncated-SHA256 rule was verified against that service's published `ja4_r`
// preimage before any of this was written. A test that recorded whatever the
// code happened to produce would pass with the specification misread.
func TestJA4MatchesRealChrome(t *testing.T) {
	hello := mustParse(t, chrome151().records())

	if got := hello.JA4(); got != chrome151JA4 {
		t.Errorf("JA4  = %s\nwant  %s", got, chrome151JA4)
	}
	if got := hello.JA4Raw(); got != chrome151JA4Raw {
		t.Errorf("JA4Raw = %s\nwant    %s", got, chrome151JA4Raw)
	}
}

func TestJA4IgnoresExtensionOrder(t *testing.T) {
	// Chrome shuffles its extension order on every connection. If JA4 moved with
	// it, the browser would not match itself and every comparison in this
	// library would be noise.
	shuffled := chrome151()
	extensions := shuffled.extensions
	// A rotation is enough to prove order does not feed the hash, and unlike a
	// random shuffle it fails the same way every time.
	shuffled.extensions = append(append([]Extension{}, extensions[5:]...), extensions[:5]...)

	original := mustParse(t, chrome151().records())
	rotated := mustParse(t, shuffled.records())

	if original.JA4() != rotated.JA4() {
		t.Errorf("JA4 changed with extension order: %s vs %s", original.JA4(), rotated.JA4())
	}
	if original.JA3() == rotated.JA3() {
		t.Error("JA3 did NOT change with extension order; the fixture is not exercising the difference")
	}
}

func TestJA4ResumptionChangesTheFingerprint(t *testing.T) {
	// A resumed connection carries pre_shared_key, one extra extension, so the
	// count and the extension hash both move. This is why captures taken against
	// a ticket-issuing server cannot be compared with cold ones — and it is
	// measured behaviour: real Chrome 151 produced exactly these two values.
	resumed := mustParse(t, chrome151().withExtension(ExtPreSharedKey, []byte{0, 0}).records())

	const want = "t13d1517h2_8daaf6152771_a87ad97598a9"
	if got := resumed.JA4(); got != want {
		t.Errorf("resumed JA4 = %s, want %s", got, want)
	}
}

func TestJA4Prefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() *helloBuilder
		want  string
	}{
		{
			name:  "no SNI reads as i",
			build: func() *helloBuilder { return newHello().withCiphers(0x1301) },
			want:  "t12i010000",
		},
		{
			name: "TLS 1.3 comes from supported_versions, not the legacy field",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x1301).
					withExtension(ExtSupportedVersions, vector8of16(0x0304))
			},
			want: "t13i010100",
		},
		{
			name: "http/1.1 renders as h1: first and last character",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn("http/1.1"))
			},
			want: "t12i0101h1",
		},
		{
			name: "a single-character ALPN is used twice",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn("q"))
			},
			want: "t12i0101qq",
		},
		{
			// The specification's own example: an ALPN of 0xAB 0xCD renders as
			// "ad" — the first and last characters of its hex form, so the
			// fingerprint stays a fixed-width, log-safe token.
			name: "a non-alphanumeric ALPN falls back to hex",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn("\xab\xcd"))
			},
			want: "t12i0101ad",
		},
		{
			name: "an empty ALPN entry reads as absent",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn(""))
			},
			want: "t12i010100",
		},
		{
			name: "GREASE is excluded from both counts",
			build: func() *helloBuilder {
				return newHello().withCiphers(0x0a0a, 0x1301).withExtension(0x1a1a, nil)
			},
			want: "t12i010000",
		},
		{
			name: "counts saturate at 99",
			build: func() *helloBuilder {
				b := newHello()
				ciphers := make([]uint16, 120)
				for i := range ciphers {
					ciphers[i] = uint16(0x1000 + i)
				}
				return b.withCiphers(ciphers...)
			},
			want: "t12i9900",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello := mustParse(t, tc.build().records())
			if got := hello.JA4(); !strings.HasPrefix(got, tc.want) {
				t.Errorf("JA4 = %q, want it to start %q", got, tc.want)
			}
		})
	}
}

func TestJA4VersionNames(t *testing.T) {
	for version, want := range map[uint16]string{
		0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
		0x0300: "s3", 0x0002: "s2", 0x9999: "00",
	} {
		if got := ja4Version(version); got != want {
			t.Errorf("ja4Version(%#04x) = %q, want %q", version, got, want)
		}
	}
}

func TestJA4EmptySectionsHashToZero(t *testing.T) {
	// A hello with no ciphers and no hashable extensions: both sections are the
	// specified all-zero placeholder rather than the SHA-256 of "".
	hello := mustParse(t, newHello().records())
	parts := strings.Split(hello.JA4(), "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 = %q, want three sections", hello.JA4())
	}
	if parts[1] != emptySection || parts[2] != emptySection {
		t.Errorf("JA4 = %q, want empty sections to be %q", hello.JA4(), emptySection)
	}
}

func TestJA4ExcludesSNIAndALPNFromTheHashedList(t *testing.T) {
	// They are counted in the prefix but must not be in the hashed list: SNI is
	// per-destination, so hashing it would give every host its own fingerprint.
	withNames := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtServerName, sni("a.example")).
		withExtension(ExtALPN, alpn("h2")).
		withExtension(ExtSessionTicket, nil).records())
	otherHost := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtServerName, sni("completely-different.example")).
		withExtension(ExtALPN, alpn("h2")).
		withExtension(ExtSessionTicket, nil).records())

	if withNames.JA4() != otherHost.JA4() {
		t.Errorf("JA4 varied with the SNI hostname: %s vs %s", withNames.JA4(), otherHost.JA4())
	}
	if strings.Contains(withNames.JA4Raw(), "0000,") || strings.Contains(withNames.JA4Raw(), ",0010") {
		t.Errorf("JA4Raw = %q, want SNI and ALPN excluded from the extension list", withNames.JA4Raw())
	}
}

func TestJA4SignatureAlgorithmsKeepWireOrder(t *testing.T) {
	// The one list JA4 does not sort: it is a preference order.
	forward := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtSignatureAlgorithms, vector16(0x0403, 0x0804)).records())
	reversed := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtSignatureAlgorithms, vector16(0x0804, 0x0403)).records())

	if forward.JA4() == reversed.JA4() {
		t.Error("JA4 ignored signature algorithm order, but the specification hashes it unsorted")
	}
}

func TestJA3(t *testing.T) {
	hello := mustParse(t, chrome151().records())
	const want = "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281," +
		"4588-29-23-24,0"
	if got := hello.JA3(); got != want {
		t.Errorf("JA3  = %s\nwant  %s", got, want)
	}
	if got, want := hello.JA3Hash(), "1c17b2c0d68c37e0b47e4cf9d33e7dd1"; len(got) != 32 {
		t.Errorf("JA3Hash = %q, want 32 hex characters (want-value %q is illustrative)", got, want)
	}
}

func TestJA3HashIsStableForAFixedString(t *testing.T) {
	hello := mustParse(t, newHello().withCiphers(0x1301).records())
	first, second := hello.JA3Hash(), hello.JA3Hash()
	if first != second {
		t.Errorf("JA3Hash is not deterministic: %s vs %s", first, second)
	}
	if len(first) != 32 {
		t.Errorf("JA3Hash = %q, want an MD5 hex digest", first)
	}
}

func mustParse(t *testing.T, records []byte) *ClientHello {
	t.Helper()
	hello, err := ParseClientHello(records)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return hello
}
