package profile

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestQUICMigrationRejectsInvalidPinnedData(t *testing.T) {
	original := bytes.Clone(quicMigrationData)
	t.Cleanup(func() { quicMigrationData = original })
	for _, tc := range []struct{ name, data, want string }{
		{"syntax", `{`, "EOF"},
		{"major", strings.Replace(string(original), `"engine_major": 1`, `"engine_major": 2`, 1), "engine_major 2"},
		{"cache source", strings.Replace(string(original), `"tcp-utls-psk"`, `"captured-ticket"`, 1), "cache migration source"},
		{"generation", strings.ReplaceAll(string(original), `"fixed"`, `"unknown"`), "raw TLS generation order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustGet(t, "chrome_155_macos").Clone()
			p.Name, p.UserAgent, p.PerConnection = "archived", "", nil
			quicMigrationData = []byte(tc.data)
			if _, err := p.Migrate("candidate"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v; want %s", err, tc.want)
			}
			quicMigrationData = original
		})
	}
}

func TestQUICMigrationNeedsSourcesAndPreservesExplicitCache(t *testing.T) {
	p := mustGet(t, "chrome_155_macos").Clone()
	delete(p.Behavior, "quic.max_stream_receive_window")
	delete(p.Behavior, "quic.stream_receive_window")
	if err := p.migrateQUICData(false); err == nil || !strings.Contains(err.Error(), "quic.stream_receive_window") {
		t.Fatal("missing copy source accepted", err)
	}
	p = mustGet(t, "chrome_155_macos").Clone()
	delete(p.Behavior, "quic.session_cache")
	p.ClientHello = []byte{1, 2, 3}
	if err := p.migrateQUICData(false); err == nil {
		t.Fatal("invalid source TLS accepted for cache capability selection")
	}
	p = nativeQUICProfile(t).Clone()
	p.Behavior["quic.session_cache"] = json.RawMessage(`true`)
	p.QUICTLSSpec = nil
	if err := p.migrateQUICData(false); err != nil {
		t.Fatal(err)
	}
	if !p.Behavior.Flag("quic.session_cache") || p.QUICTLSSpec == nil {
		t.Fatal("explicit cache lost")
	}
	found := false
	for _, ext := range p.QUICTLSSpec.Hello.Extensions {
		found = found || ext.Type == "pre_shared_key"
	}
	if !found {
		t.Fatal("cached native template has no PSK capability")
	}
}

func TestArchivedSaveMaterializesOnlyLegacyFormatting(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []uint16
	}{{"chrome_archived", []uint16{128, 160, 192, 224}}, {"other_archived", nil}} {
		p := mustGet(t, "chrome_155_macos").Clone()
		p.Name, p.UserAgent, p.Schema, p.EngineMajor, p.PerConnection = tc.name, "", 0, Major(0), nil
		raw, err := p.Save()
		if err != nil {
			t.Fatal(err)
		}
		q, err := Inspect(raw)
		if err != nil {
			t.Fatal(err)
		}
		if q.PerConnection == nil || !slices.Equal(q.PerConnection.ECHPayloadLengths, tc.want) || *q.EngineMajor != 0 || p.PerConnection != nil {
			t.Fatal("archived format changed compatibility or source", q.PerConnection)
		}
		if _, err := Load(raw); err == nil {
			t.Fatal("format save granted execution")
		}
	}
}

func TestNativeQUICCipherSelectionUsesCapabilitiesAndExplicitVectors(t *testing.T) {
	q := nativeQUICProfile(t).QUICTLSSpec
	for _, hasAES := range []bool{false, true} {
		spec, err := q.specWithAES(nil, hasAES)
		if err != nil {
			t.Fatal(err)
		}
		want := q.CipherSuitesWithoutAES
		if hasAES {
			want = q.Hello.CipherSuites
		}
		if !slices.Equal(spec.CipherSuites, want) {
			t.Fatal("capability branch", hasAES, spec.CipherSuites, want)
		}
	}
	p := nativeQUICProfile(t).Clone()
	p.QUICTLSSpec.CipherOrder = "fixed"
	p.QUICTLSSpec.CipherSuitesWithoutAES = nil
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "explicit empty alternate") {
		t.Fatal("absent branch treated as explicit empty", err)
	}
}
