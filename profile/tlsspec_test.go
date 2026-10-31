package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
)

func exportedTLSSpecs(t *testing.T) map[string]*TLSSpec {
	t.Helper()
	data, err := os.ReadFile("testdata/catalogue-tls-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Specs map[string]*TLSSpec `json:"specs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Specs
}

func canonicalExtension(t *testing.T, e tls.TLSExtension) any {
	t.Helper()
	if _, ok := e.(*tls.UtlsPaddingExtension); ok {
		return "parameterized padding"
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if sig, ok := e.(*tls.SignatureAlgorithmsExtension); ok {
		values := slices.Clone(sig.SupportedSignatureAlgorithms)
		for i, n := range values {
			if uint16(n)&0x0f0f == 0x0a0a && byte(n) == byte(n>>8) {
				values[i] = tls.GREASE_PLACEHOLDER
			}
		}
		v["SupportedSignatureAlgorithms"] = values
	}
	if _, ok := e.(*tls.UtlsGREASEExtension); ok {
		if len(e.(*tls.UtlsGREASEExtension).Body) == 0 {
			v["Body"] = nil
		}
	}
	if ext, ok := e.(*tls.GenericExtension); ok && ext.Id == 51764 {
		records, err := splitTrustAnchors(ext.Data)
		if err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(records, bytes.Compare)
		v["Data"] = joinTrustAnchors(records)
	}
	delete(v, "BodySet")
	v["type"] = fmt.Sprintf("%T", e)
	// Typed values added above compare in the same JSON domain as their peers.
	data, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDeclarativeTLSPresetExportAll83(t *testing.T) {
	fixtures := exportedTLSSpecs(t)
	if len(fixtures) != 83 || len(fixtures) != len(profiles.MappedTLSClients) {
		t.Fatalf("catalogue denominator changed: %d/%d", len(fixtures), len(profiles.MappedTLSClients))
	}
	for name, source := range profiles.MappedTLSClients {
		t.Run(name, func(t *testing.T) {
			declared, ok := fixtures[name]
			if !ok {
				t.Fatal("missing export")
			}
			id := source.GetClientHelloId()
			old, err := id.ToSpec()
			if err != nil {
				old, err = tls.UTLSIdToSpec(id)
			}
			if err != nil {
				t.Fatal(err)
			}
			for repeat := 0; repeat < 3; repeat++ {
				got, err := declared.spec()
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(got.CipherSuites, old.CipherSuites) || !slices.Equal(got.CompressionMethods, old.CompressionMethods) || got.TLSVersMin != old.TLSVersMin || got.TLSVersMax != old.TLSVersMax || got.GetSessionID != nil || old.GetSessionID != nil || len(got.Extensions) != len(old.Extensions) {
					t.Fatal("TLS vectors, bounds, session-ID generation or extension count changed")
				}
				if (declared.ExtensionOrder == "utls") != id.RandomExtensionOrder {
					t.Fatal("extension-order rule changed")
				}
				for i, ext := range got.Extensions {
					if psk, ok := old.Extensions[i].(*tls.UtlsPreSharedKeyExtension); ok {
						psk.SetOmitEmptyPsk(true)
					}

					if pad, ok := ext.(*tls.UtlsPaddingExtension); ok {
						oldPad := old.Extensions[i].(*tls.UtlsPaddingExtension)
						for n := 0; n <= 65536; n++ {
							a, x := pad.GetPaddingLen(n)
							b, y := oldPad.GetPaddingLen(n)
							if a != b || x != y {
								t.Fatalf("padding differs at %d", n)
							}
						}
					}
					if grease, ok := old.Extensions[i].(*tls.UtlsGREASEExtension); ok {
						slot := 0
						for j := 0; j < i; j++ {
							if _, ok := old.Extensions[j].(*tls.UtlsGREASEExtension); ok {
								slot++
							}
						}
						if slot == 1 {
							grease.Body = []byte{0}
						}
					}

					if a, b := canonicalExtension(t, ext), canonicalExtension(t, old.Extensions[i]); !reflect.DeepEqual(a, b) {
						t.Fatalf("extension %d:\ngot %v\nold %v", i, a, b)
					}
				}
			}
		})
	}
}

func declarativeTLSProfile(t *testing.T) *Profile {
	t.Helper()
	p := mustGet(t, "chrome_156_macos").Clone()
	p.ClientHello = nil
	p.Base = ""
	p.PerConnection = nil
	p.TLSSpec = exportedTLSSpecs(t)["chrome_133"]
	return p
}

func TestDeclarativeTLSLoadCloneAndSelection(t *testing.T) {
	p := declarativeTLSProfile(t)
	for _, mode := range []string{"fixed", "moving", "utls"} {
		p.TLSSpec.ExtensionOrder = mode
		data, err := p.Save()
		if err != nil {
			t.Fatal(err)
		}
		q, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := json.Marshal(p.TLSSpec)
		after, _ := json.Marshal(q.TLSSpec)
		if !bytes.Equal(before, after) {
			t.Fatal("Save/Load changed TLS descriptor")
		}
		q.Name = "neutral-profile"
		q.UserAgent = "unrelated-agent"
		if q.ShufflesExtensions() != (mode != "fixed") {
			t.Fatal("shuffle rule lost")
		}
		for _, shuffle := range []bool{true, false} {
			cp, err := q.ClientProfileShuffled(shuffle)
			if err != nil {
				t.Fatal(err)
			}
			id := cp.GetClientHelloId()
			if id.RandomExtensionOrder != (shuffle && mode == "utls") {
				t.Fatal("wrong primitive selected")
			}
			if _, err := id.ToSpec(); err != nil {
				t.Fatal(err)
			}
		}
	}
	clone := p.Clone()
	clone.TLSSpec.CipherSuites[0] = 0
	clone.TLSSpec.CompressionMethods[0] = 1
	clone.TLSSpec.Extensions[0].Parameters[0] = '!'
	if p.TLSSpec.CipherSuites[0] == 0 || p.TLSSpec.CompressionMethods[0] == 1 || p.TLSSpec.Extensions[0].Parameters[0] == '!' {
		t.Fatal("Clone shares TLS data")
	}
	for _, edit := range []func(*Profile){func(p *Profile) { p.Base = "chrome_133" }, func(p *Profile) { p.ClientHello = []byte{1} }, func(p *Profile) { p.PerConnection = &PerConnection{} }} {
		q := p.Clone()
		edit(q)
		if err := q.Validate(); err == nil || !strings.Contains(err.Error(), "exclusive") {
			t.Fatal(err)
		}
	}
	p.TLSSpec.SessionID = "captured"
	if _, err := p.Spec(); err == nil || !strings.Contains(err.Error(), p.Name) {
		t.Fatal(err)
	}
}

func TestDeclarativeTLSStrictParameters(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range exportedTLSSpecs(t) {
		for _, ext := range spec.Extensions {
			if seen[ext.Type] {
				continue
			}
			seen[ext.Type] = true
			var params map[string]json.RawMessage
			if err := json.Unmarshal(ext.Parameters, &params); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{"null", "[]", "true", "1", "{", "{} {}", `{"x":0,"X":1}`} {
				e := ext
				e.Parameters = []byte(raw)
				if _, err := e.build(false); err == nil {
					t.Fatalf("%s accepted %s", ext.Type, raw)
				}
			}
			bad := func(v map[string]json.RawMessage) {
				t.Helper()
				e := ext
				e.Parameters, _ = json.Marshal(v)
				if _, err := e.build(false); err == nil {
					t.Fatalf("%s accepted %s", e.Type, e.Parameters)
				}
			}
			params["unknown"] = []byte("0")
			bad(params)
			delete(params, "unknown")
			for k, v := range params {
				delete(params, k)
				bad(params)
				params[k] = []byte("null")
				bad(params)
				delete(params, k)
				params[strings.ToUpper(k)] = v
				bad(params)
				delete(params, strings.ToUpper(k))
				params[k] = []byte("{}")
				bad(params)
				params[k] = v
			}
		}
	}
	if len(seen) != 24 {
		t.Fatalf("extension denominator %d", len(seen))
	}
	data, _ := json.Marshal(declarativeTLSProfile(t))
	for _, raw := range []string{"null", "false", "[]", "0", "\"ignored\""} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(data, &fields)
		fields["tls_spec"] = []byte(raw)
		encoded, _ := json.Marshal(fields)
		if _, err := Load(encoded); err == nil {
			t.Fatal("invalid descriptor object accepted", raw)
		}
	}
	for _, edit := range []func(map[string]any){
		func(m map[string]any) { delete(m, "session_id") }, func(m map[string]any) { m["Session_ID"] = m["session_id"]; delete(m, "session_id") }, func(m map[string]any) { m["extensions"] = nil }, func(m map[string]any) { m["extensions"] = true }, func(m map[string]any) { m["min_version"] = nil }, func(m map[string]any) { m["min_version"] = "0" }, func(m map[string]any) { m["extensions"] = []any{nil} }, func(m map[string]any) { m["extensions"] = []any{true} }, func(m map[string]any) { m["extensions"] = []any{map[string]any{"type": "sni", "parameters": nil}} }, func(m map[string]any) { m["cipher_suites"] = []any{nil} },
	} {
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		edit(fields["tls_spec"].(map[string]any))
		raw, _ := json.Marshal(fields)
		if _, err := Load(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var s TLSSpec
	if err := json.Unmarshal([]byte("null"), &s); err == nil {
		t.Fatal("null TLS spec")
	}
}

func TestDeclarativeTLSInvalidPolicies(t *testing.T) {
	for _, edit := range []func(*TLSSpec){
		func(s *TLSSpec) { s.GREASE = "captured" }, func(s *TLSSpec) { s.SessionID = "captured" }, func(s *TLSSpec) { s.ExtensionOrder = "unknown" }, func(s *TLSSpec) { s.MinVersion = 1 }, func(s *TLSSpec) { s.MaxVersion = 0xffff }, func(s *TLSSpec) { s.MinVersion = tls.VersionTLS13; s.MaxVersion = tls.VersionTLS12 }, func(s *TLSSpec) { s.CipherSuites = nil }, func(s *TLSSpec) { s.CipherSuites = make([]uint16, 32768) }, func(s *TLSSpec) { s.CompressionMethods = nil }, func(s *TLSSpec) { s.CompressionMethods = []uint8{1} }, func(s *TLSSpec) { s.CompressionMethods = make([]uint8, 256) }, func(s *TLSSpec) { s.Extensions = make([]TLSExtension, 257) },
	} {
		s := exportedTLSSpecs(t)["chrome_133"]
		edit(s)
		if _, err := s.spec(); err == nil {
			t.Fatal("accepted invalid policy")
		}
	}
	for _, exts := range [][]TLSExtension{
		{{Type: "sni", Parameters: json.RawMessage(`{"source":"request-host"}`)}, {Type: "sni", Parameters: json.RawMessage(`{"source":"request-host"}`)}},
		{{Type: "grease", Parameters: json.RawMessage(`{"body":""}`)}, {Type: "grease", Parameters: json.RawMessage(`{"body":""}`)}, {Type: "grease", Parameters: json.RawMessage(`{"body":""}`)}},
		{{Type: "pre_shared_key", Parameters: json.RawMessage(`{"source":"session-cache","omit_empty":true}`)}, {Type: "sni", Parameters: json.RawMessage(`{"source":"request-host"}`)}},
	} {
		s := exportedTLSSpecs(t)["chrome_133"]
		s.Extensions = exts
		if _, err := s.spec(); err == nil {
			t.Fatal("illegal extension layout accepted")
		}
	}
	invalidExtension := exportedTLSSpecs(t)["chrome_133"]
	invalidExtension.Extensions[0].Type = "unimplemented"
	if _, err := invalidExtension.spec(); err == nil || !strings.Contains(err.Error(), "extensions[0]") {
		t.Fatal("extension failure lost its location", err)
	}
	for _, tc := range []struct{ typ, params string }{
		{"unknown", "{}"}, {"sni", `{"source":"captured"}`}, {"session_ticket", `{"source":"captured"}`},
		{"supported_groups", `{"values":[]}`}, {"supported_versions", `{"values":[]}`}, {"compress_certificate", `{"values":[0]}`},
		{"point_formats", `{"values":""}`}, {"alpn", `{"protocols":[]}`}, {"alpn", `{"protocols":[""]}`},
		{"point_formats", `{"values":[null]}`},
		{"renegotiation_info", `{"mode":-1}`}, {"renegotiation_info", `{"mode":3}`}, {"record_size_limit", `{"limit":63}`}, {"record_size_limit", `{"limit":16386}`},
		{"padding", `{"algorithm":"script","lower_exclusive":255,"upper_exclusive":512,"target":512,"minimum":1}`}, {"padding", `{"algorithm":"range","lower_exclusive":255,"upper_exclusive":256,"target":255,"minimum":1}`}, {"pre_shared_key", `{"source":"captured","omit_empty":false}`}, {"pre_shared_key", `{"source":"session-cache","omit_empty":false}`},
		{"key_share", `{"shares":[]}`}, {"key_share", `{"shares":[{"group":29,"source":"captured","data":""}]}`}, {"key_share", `{"shares":[{"group":29,"source":"fresh","data":"AQ=="}]}`}, {"key_share", `{"shares":[{"group":1,"source":"fresh","data":""}]}`}, {"key_share", `{"shares":[{"group":29,"source":"fresh","data":""},{"group":29,"source":"fresh","data":""}]}`}, {"key_share", `{"shares":[{"group":2570,"source":"fresh","data":"AA=="}]}`}, {"key_share", `{"shares":[{"group":29,"source":"fresh","data":null}]}`}, {"key_share", `{"shares":[{"group":29,"source":"fresh","data":"","ignored":1}]}`},
		{"grease_ech", `{"cipher_suites":[{"kdf":1,"aead":1}],"config_id":"captured","encapsulated_key":"captured","payload_lengths":[128]}`},
		{"grease_ech", `{"cipher_suites":[],"config_id":"random-byte","encapsulated_key":"hpke-x25519-sha256-aes128gcm","payload_lengths":[128]}`},
		{"grease_ech", `{"cipher_suites":[{"kdf":1,"aead":0}],"config_id":"random-byte","encapsulated_key":"hpke-x25519-sha256-aes128gcm","payload_lengths":[128]}`},
		{"grease_ech", `{"cipher_suites":[{"kdf":1,"aead":1}],"config_id":"random-byte","encapsulated_key":"hpke-x25519-sha256-aes128gcm","payload_lengths":[0]}`},
		{"trust_anchors", `{"data":"AAA=","order":"auto"}`}, {"trust_anchors", `{"data":"","order":"sorted"}`},
	} {
		e := TLSExtension{Type: tc.typ, Parameters: []byte(tc.params)}
		for _, generate := range []bool{false, true} {
			if _, err := e.build(generate); err == nil {
				t.Fatalf("%s accepted %s", tc.typ, tc.params)
			}
		}
	}
	// Resource bounds are exercised without ever starting I/O.
	for _, tc := range []struct {
		typ string
		p   any
	}{
		{"supported_groups", map[string]any{"values": make([]uint16, 128)}}, {"point_formats", map[string]any{"values": make([]uint8, 256)}}, {"alpn", map[string]any{"protocols": []string{strings.Repeat("a", 256)}}}, {"alps", map[string]any{"protocols": slices.Repeat([]string{strings.Repeat("a", 255)}, 256)}}, {"grease", map[string]any{"body": make([]byte, 65536)}}, {"trust_anchors", map[string]any{"data": make([]byte, 65536), "order": "captured"}}, {"key_share", map[string]any{"shares": make([]any, 33)}},
	} {
		raw, _ := json.Marshal(tc.p)
		e := TLSExtension{Type: tc.typ, Parameters: raw}
		if _, err := e.build(false); err == nil {
			t.Fatal(tc.typ)
		}
	}
}
