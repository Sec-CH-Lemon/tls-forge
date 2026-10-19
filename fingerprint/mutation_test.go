package fingerprint

import (
	"slices"
	"testing"
)

// change is one edit of a real hello, and the field the comparison must report
// it under, or none for an edit it must not report.
type change struct {
	name  string
	from  string
	field string
	edit  func(t *testing.T, b *helloBuilder)
}

// greaseGroup is the GREASE group a Chrome hello's supported_groups and
// key_share share, so that an edit of one leaves the two agreeing.
func greaseGroup(b *helloBuilder) uint16 {
	for _, ext := range b.extensions {
		if ext.Type == ExtSupportedGroups {
			return uint16(ext.Data[2])<<8 | uint16(ext.Data[3])
		}
	}
	panic("no supported_groups")
}

// TestEveryComparedTLSFieldCatchesAChange holds the comparison to its manifest:
// for every field TLSFields compares, an edit of a real Chrome hello that the
// comparison must report under that field's name. A field added without one
// fails here.
func TestEveryComparedTLSFieldCatchesAChange(t *testing.T) {
	held := map[string]bool{}
	for _, c := range tlsChanges {
		held[c.field] = true
		t.Run(c.name, func(t *testing.T) {
			report := compareAfter(t, c)
			if !slices.ContainsFunc(report.Differences, func(d Difference) bool { return d.Field == c.field }) {
				t.Errorf("%s is not reported under %s:\n%s", c.name, c.field, report)
			}
		})
	}

	// And the manifest has no field without a change of its own.
	heldToEveryField(t, TLSFields(mustParse(t, fixture(t, cold))), held)
}

const cold, resumed = "chrome155-clienthello.bin", "chrome155-clienthello-resumed.bin"

// tlsChanges are one edit of a real Chrome hello for every field TLSFields
// compares, each of which the comparison must report under that field.
var tlsChanges = []change{
	{"a cipher fewer", cold, "ja4", func(_ *testing.T, b *helloBuilder) { b.ciphers = b.ciphers[:len(b.ciphers)-1] }},
	{"a record version of TLS 1.2", cold, "record_version", func(_ *testing.T, b *helloBuilder) { b.recordVersion = 0x0303 }},
	{"two records", cold, "records", func(_ *testing.T, b *helloBuilder) { b.split = 1024 }},
	{"a legacy version of TLS 1.0", cold, "legacy_version", func(_ *testing.T, b *helloBuilder) { b.legacyVersion = 0x0301 }},
	{"a shorter session id", cold, "session_id_length", func(_ *testing.T, b *helloBuilder) { b.sessionID = make([]byte, 16) }},
	{"two ciphers swapped", cold, "cipher_suites", func(_ *testing.T, b *helloBuilder) {
		b.ciphers[1], b.ciphers[2] = b.ciphers[2], b.ciphers[1]
	}},
	{"deflate offered", cold, "compression_methods", func(_ *testing.T, b *helloBuilder) { b.compression = []byte{1, 0} }},
	{"no SCT", cold, "extensions", func(_ *testing.T, b *helloBuilder) {
		b.extensions = slices.DeleteFunc(b.extensions, func(ext Extension) bool { return ext.Type == ExtSCT })
	}},
	{"the second GREASE extension empty", cold, "grease", func(_ *testing.T, b *helloBuilder) {
		b.extensions[len(b.extensions)-1].Data = nil
	}},
	{"no TLS 1.2", cold, "supported_versions", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtSupportedVersions, vector8of16(0x2a2a, 0x0304))
	}},
	{"no P-384", cold, "supported_groups", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtSupportedGroups, vector16(greaseGroup(b), 4588, 29, 23))
	}},
	{"no mldsa87", cold, "signature_algorithms", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtSignatureAlgorithms, vector16(0x4a4a, 0x0904, 0x0905, 0x0403, 0x0804, 0x0401,
			0x0503, 0x0805, 0x0501, 0x0806, 0x0601))
	}},
	{"no X25519 share", cold, "key_share_groups", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtKeyShare, shares(KeyShare{Group: greaseGroup(b), Length: 1}, KeyShare{Group: 4588, Length: 1216}))
	}},
	{"an X25519 key a byte short", cold, "key_share_lengths", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtKeyShare, shares(KeyShare{Group: greaseGroup(b), Length: 1},
			KeyShare{Group: 4588, Length: 1216}, KeyShare{Group: 29, Length: 31}))
	}},
	{"h2 alone", cold, "alpn", func(_ *testing.T, b *helloBuilder) { b.set(ExtALPN, alpn("h2")) }},
	{"ALPS for HTTP/1.1", cold, "application_settings", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtALPS, alpn("http/1.1"))
	}},
	{"two point formats", cold, "ec_point_formats", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtECPointFormats, vector8(0, 1))
	}},
	{"PSK without key exchange", cold, "psk_key_exchange_modes", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtPSKKeyExchangeModes, vector8(0, 1))
	}},
	{"zlib too", cold, "compress_certificate", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtCompressCertificate, vector8of16(2, 1))
	}},
	{"another trust anchor", cold, "trust_anchors", func(t *testing.T, b *helloBuilder) {
		ids := mustParse(t, b.records()).TrustAnchors()
		if ids[len(ids)-1] != "11129.9.15" {
			t.Fatalf("the last trust anchor is %s", ids[len(ids)-1])
		}
		data := slices.Clone(extensionOf(b, ExtTrustAnchors))
		data[len(data)-1] = 14
		b.set(ExtTrustAnchors, data)
	}},
	{"the first trust anchor last", cold, "trust_anchors", func(_ *testing.T, b *helloBuilder) {
		data := extensionOf(b, ExtTrustAnchors)
		// The first ID, 44947.2.1, is six bytes with its length: the same IDs,
		// out of the byte order Chrome 155 sends them in.
		b.set(ExtTrustAnchors, append(append(slices.Clone(data[:2]), data[8:]...), data[2:8]...))
	}},
	{"ChaCha20-Poly1305 for ECH", cold, "ech_grease", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtEncryptedClientHello, echBody(1, 3, 176))
	}},
	{"random bytes for ECH's key", cold, "keys", func(t *testing.T, b *helloBuilder) {
		b.set(ExtEncryptedClientHello, echWith(fromHex(t, reported)))
	}},
	{"the X25519 key of X25519MLKEM768 sent again", cold, "keys", func(_ *testing.T, b *helloBuilder) {
		hybrid := shareOf(4588, 1216)
		b.set(ExtKeyShare, keyShareOf(sharedKey{greaseGroup(b), []byte{0}}, sharedKey{4588, hybrid},
			sharedKey{29, hybrid[1184:]}))
	}},
	{"a 48-byte binder", resumed, "pre_shared_key", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtPreSharedKey, psk([]int{100}, []int{48}))
	}},
	{"OCSP asked with an extension", cold, "extension_contents", func(_ *testing.T, b *helloBuilder) {
		b.set(ExtStatusRequest, []byte{1, 0, 0, 0, 1})
	}},
}

func TestWhatChromeChangesItselfIsNotADifference(t *testing.T) {
	// Every connection draws these anew; the browser would not match itself
	// if the comparison saw them.
	for _, c := range []change{
		{"another ECH payload length", cold, "", func(_ *testing.T, b *helloBuilder) {
			b.set(ExtEncryptedClientHello, echBody(1, 1, 240))
		}},
		{"other GREASE values", cold, "", func(_ *testing.T, b *helloBuilder) {
			b.ciphers[0] = 0x1a1a
			b.extensions[0].Type, b.extensions[len(b.extensions)-1].Type = 0x2a2a, 0x3a3a
			b.set(ExtSupportedGroups, vector16(0x4a4a, 4588, 29, 23, 24))
			b.set(ExtKeyShare, shares(KeyShare{Group: 0x4a4a, Length: 1}, KeyShare{Group: 4588, Length: 1216},
				KeyShare{Group: 29, Length: 32}))
			b.set(ExtSupportedVersions, vector8of16(0x5a5a, 0x0304, 0x0303))
		}},
		{"another session id and site", cold, "", func(_ *testing.T, b *helloBuilder) {
			b.sessionID = make([]byte, 32)
			b.sessionID[0] = 1
			b.set(ExtServerName, sni("example.com"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if report := compareAfter(t, c); !report.OK() {
				t.Errorf("%s was reported:\n%s", c.name, report)
			}
		})
	}
}

// compareAfter compares a fixture, as the builder renders it, with the same
// after the change.
func compareAfter(t *testing.T, c change) Report {
	t.Helper()
	b := builderOf(t, fixture(t, c.from))
	reference := mustParse(t, b.records())
	c.edit(t, b)
	return CompareTLS(reference, mustParse(t, b.records()))
}

// extensionOf is the contents of an extension the builder has.
func extensionOf(b *helloBuilder, typ uint16) []byte {
	for _, ext := range b.extensions {
		if ext.Type == typ {
			return ext.Data
		}
	}
	panic("no such extension")
}
