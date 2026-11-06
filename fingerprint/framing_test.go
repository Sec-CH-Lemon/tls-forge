package fingerprint

import (
	"slices"
	"testing"
)

func TestEachExtensionAFieldReadsIsReadWhole(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint16
		data []byte
		ok   bool
	}{
		{"supported_groups", ExtSupportedGroups, []byte{0, 4, 0, 29, 0, 23}, true},
		{"an empty list", ExtSupportedGroups, []byte{0, 0}, true},
		{"a byte past the list", ExtSupportedGroups, []byte{0, 2, 0, 29, 0}, false},
		{"an odd list", ExtSupportedGroups, []byte{0, 3, 0, 29, 0}, false},
		{"a list longer than its extension", ExtSupportedGroups, []byte{0, 4, 0, 29}, false},
		{"no list at all", ExtSupportedGroups, []byte{0}, false},
		{"signature_algorithms", ExtSignatureAlgorithms, []byte{0, 2, 4, 3, 1}, false},
		{"supported_versions", ExtSupportedVersions, []byte{2, 3, 4}, true},
		{"supported_versions cut", ExtSupportedVersions, []byte{3, 3, 4, 3}, false},
		{"compress_certificate past", ExtCompressCertificate, []byte{2, 0, 2, 0}, false},
		{"ec_point_formats", ExtECPointFormats, []byte{1, 0}, true},
		{"ec_point_formats past", ExtECPointFormats, []byte{1, 0, 0}, false},
		{"psk_key_exchange_modes past", ExtPSKKeyExchangeModes, []byte{1, 1, 9}, false},
		{"alpn", ExtALPN, []byte{0, 3, 2, 'h', '2'}, true},
		{"alpn's name cut", ExtALPN, []byte{0, 3, 3, 'h', '2'}, false},
		{"alpn past", ExtALPN, []byte{0, 3, 2, 'h', '2', 0}, false},
		{"alps past", ExtALPS, []byte{0, 3, 2, 'h', '2', 0}, false},
		{"old alps past", ExtALPSOld, []byte{0, 3, 2, 'h', '2', 0}, false},
		{"key_share", ExtKeyShare, []byte{0, 5, 0x0a, 0x0a, 0, 1, 0}, true},
		{"key_share's key cut", ExtKeyShare, []byte{0, 5, 0x0a, 0x0a, 0, 2, 0}, false},
		{"key_share's key past its list", ExtKeyShare, []byte{0, 4, 0x0a, 0x0a, 0, 9}, false},
		{"key_share past", ExtKeyShare, []byte{0, 5, 0x0a, 0x0a, 0, 1, 0, 7}, false},
		{"trust_anchors past", ExtTrustAnchors, []byte{0, 2, 1, 7, 0}, false},
		{"server_name", ExtServerName, []byte{0, 4, 0, 0, 1, 'a'}, true},
		{"server_name of another type", ExtServerName, []byte{0, 4, 1, 0, 1, 'a'}, false},
		{"server_name of two names", ExtServerName, []byte{0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'}, false},
		{"server_name of no name", ExtServerName, []byte{0, 0}, false},
		{"server_name past", ExtServerName, []byte{0, 4, 0, 0, 1, 'a', 0}, false},
		{"server_name's name cut", ExtServerName, []byte{0, 4, 0, 0, 2, 'a'}, false},
		{"server_name's type alone", ExtServerName, []byte{0, 1, 0}, false},
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(tc.typ, tc.data).records())
		if got := framing(hello); (len(got) == 0) != tc.ok || !tc.ok && !slices.Equal(got, []string{ExtensionName(tc.typ)}) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	// An extension no grammar is had for is the contents' to compare.
	if got := framing(mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtSCT, []byte{9}).records())); got != nil {
		t.Errorf("an extension of no grammar: %q", got)
	}
	// Chrome's own read whole.
	for _, name := range []string{cold, resumed} {
		if got := framing(mustParse(t, fixture(t, name))); got != nil {
			t.Errorf("%s: %q", name, got)
		}
	}
}
