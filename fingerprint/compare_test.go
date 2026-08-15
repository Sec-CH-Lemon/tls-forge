package fingerprint

import (
	"strings"
	"testing"
)

func TestCompareTLSIdentical(t *testing.T) {
	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, chrome151().records()))
	if !report.OK() {
		t.Errorf("identical helloes reported differences:\n%s", report)
	}
	if got, want := report.String(), "no differences"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCompareTLSIgnoresExtensionOrderAndGREASE(t *testing.T) {
	// Chrome does both on every connection, so a comparison that noticed either
	// would report the browser as differing from itself.
	rotated := chrome151()
	rotated.extensions = append(append([]Extension{}, rotated.extensions[7:]...), rotated.extensions[:7]...)

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, rotated.records()))
	if !report.OK() {
		t.Errorf("reordering extensions was reported as a difference:\n%s", report)
	}
}

func TestCompareTLSNamesTheMissingSignatureAlgorithm(t *testing.T) {
	// The real case this library exists for: a stock TLS profile that is right
	// about everything except the post-quantum signature schemes.
	withoutMLDSA := chrome151()
	for i, ext := range withoutMLDSA.extensions {
		if ext.Type == ExtSignatureAlgorithms {
			withoutMLDSA.extensions[i].Data = vector16(
				0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
		}
	}

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, withoutMLDSA.records()))
	if report.OK() {
		t.Fatal("expected a difference")
	}

	rendered := report.String()
	for _, want := range []string{"ja4", "signature_algorithms", "mldsa44", "mldsa65", "mldsa87", "missing:"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("report does not mention %q:\n%s", want, rendered)
		}
	}
}

func TestCompareTLSDetectsEachField(t *testing.T) {
	reference := chrome151()

	for _, tc := range []struct {
		name  string
		build func() *helloBuilder
		field string
	}{
		{"ciphers", func() *helloBuilder {
			b := chrome151()
			b.ciphers = []uint16{0x1301, 0x1302}
			return b
		}, "cipher_suites"},
		{"a missing extension", func() *helloBuilder {
			b := chrome151()
			b.extensions = b.extensions[:len(b.extensions)-2]
			return b
		}, "extensions"},
		{"groups", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtSupportedGroups, vector16(29, 23))
		}, "supported_groups"},
		{"versions", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtSupportedVersions, vector8of16(0x0303))
		}, "supported_versions"},
		{"key shares", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtKeyShare, keyShare(29))
		}, "key_share_groups"},
		{"ALPN", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtALPN, alpn("http/1.1"))
		}, "alpn"},
		{"ALPS", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtApplicationSettingsOld, alpn("http/1.1"))
		}, "application_settings"},
		{"point formats", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtECPointFormats, vector8(0, 1))
		}, "ec_point_formats"},
		{"PSK modes", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtPSKKeyExchangeModes, vector8(0))
		}, "psk_key_exchange_modes"},
		{"certificate compression", func() *helloBuilder {
			return replaceExtension(chrome151(), ExtCompressCertificate, vector8of16(1))
		}, "compress_certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := CompareTLS(mustParse(t, reference.records()), mustParse(t, tc.build().records()))
			if report.OK() {
				t.Fatalf("expected a difference in %s", tc.field)
			}
			if !strings.Contains(report.String(), tc.field) {
				t.Errorf("report does not name %q:\n%s", tc.field, report)
			}
		})
	}
}

func TestCompareTLSDistinguishesOrderFromContents(t *testing.T) {
	// Same ciphers, different order: the two have completely different fixes, so
	// the report must not describe one as the other.
	//
	// Indices 1 and 2 rather than 0 and 1: index 0 is GREASE, which is filtered
	// before comparison, so swapping it changes nothing at all.
	reordered := chrome151()
	reordered.ciphers[1], reordered.ciphers[2] = reordered.ciphers[2], reordered.ciphers[1]

	report := CompareTLS(mustParse(t, chrome151().records()), mustParse(t, reordered.records()))
	if report.OK() {
		t.Fatal("expected a difference")
	}
	for _, diff := range report.Differences {
		if diff.Field != "cipher_suites" {
			continue
		}
		if len(diff.Missing) != 0 || len(diff.Extra) != 0 {
			t.Errorf("a pure reordering reported missing=%v extra=%v; both should be empty",
				diff.Missing, diff.Extra)
		}
	}
}

func TestCompareTLSCountsDuplicates(t *testing.T) {
	twice := newHello().withCiphers(0x1301, 0x1301)
	once := newHello().withCiphers(0x1301)
	report := CompareTLS(mustParse(t, twice.records()), mustParse(t, once.records()))
	if report.OK() {
		t.Fatal("a cipher sent twice differs from one sent once")
	}
}

func TestCompareHTTP2(t *testing.T) {
	reference := chromeHTTP2()

	if report := CompareHTTP2(reference, chromeHTTP2()); !report.OK() {
		t.Errorf("identical connections reported differences:\n%s", report)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*HTTP2)
		field  string
	}{
		{"settings order", func(h *HTTP2) {
			h.Settings[0], h.Settings[1] = h.Settings[1], h.Settings[0]
		}, "http2_settings"},
		{"window update", func(h *HTTP2) { h.WindowUpdate = 65535 }, "http2_window_update"},
		{"pseudo-header order", func(h *HTTP2) {
			h.Headers[1], h.Headers[2] = h.Headers[2], h.Headers[1]
		}, "pseudo_header_order"},
		{"header order", func(h *HTTP2) {
			h.Headers[4], h.Headers[6] = h.Headers[6], h.Headers[4]
		}, "header_order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := chromeHTTP2()
			tc.mutate(candidate)
			report := CompareHTTP2(reference, candidate)
			if report.OK() {
				t.Fatalf("expected a difference in %s", tc.field)
			}
			if !strings.Contains(report.String(), tc.field) {
				t.Errorf("report does not name %q:\n%s", tc.field, report)
			}
		})
	}
}

func TestDifferenceRendering(t *testing.T) {
	diff := Difference{
		Field:     "supported_groups",
		Reference: "X25519MLKEM768, X25519",
		Candidate: "X25519",
		Missing:   []string{"X25519MLKEM768"},
	}
	rendered := diff.String()
	for _, want := range []string{"supported_groups", "browser:", "client:", "missing:", "X25519MLKEM768"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendering omits %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "extra:") {
		t.Errorf("rendering shows an empty extras line:\n%s", rendered)
	}

	withExtra := Difference{Field: "f", Extra: []string{"unexpected"}}
	if !strings.Contains(withExtra.String(), "extra:   unexpected") {
		t.Errorf("rendering omits extras:\n%s", withExtra)
	}
}

func TestRenderEmptyList(t *testing.T) {
	report := CompareTLS(
		mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtALPN, alpn("h2")).records()),
		mustParse(t, newHello().withCiphers(0x1301).records()),
	)
	if !strings.Contains(report.String(), "(none)") {
		t.Errorf("an absent list should render as (none):\n%s", report)
	}
}

func replaceExtension(b *helloBuilder, typ uint16, data []byte) *helloBuilder {
	for i, ext := range b.extensions {
		if ext.Type == typ {
			b.extensions[i].Data = data
		}
	}
	return b
}
