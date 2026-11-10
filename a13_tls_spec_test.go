package tlsforge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v2/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tls "github.com/igor-lemon/utls"
)

// Only the selected symmetric cipher of GREASE ECH is normalized here, after
// checking the original encoding, allowed cipher set and payload-length set.
// The ordinary manifest still verifies the key and every other TLS field.
func a13NormalizeECH(h *fingerprint.ClientHello, spec *profile.TLSSpec) (*fingerprint.ClientHello, error) {
	for _, ext := range spec.Extensions {
		if ext.Type == "grease_ech" {
			var suites []struct {
				KDF  uint16 `json:"kdf"`
				AEAD uint16 `json:"aead"`
			}
			var lengths []uint16
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(ext.Parameters, &fields); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(fields["cipher_suites"], &suites); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(fields["payload_lengths"], &lengths); err != nil {
				return nil, err
			}
			value, ok := h.EncryptedClientHello()
			if !ok || value.EncLength != 32 || !slices.Contains(lengths, uint16(value.PayloadLength-16)) || !slices.ContainsFunc(suites, func(s struct {
				KDF  uint16 `json:"kdf"`
				AEAD uint16 `json:"aead"`
			}) bool {
				return s.KDF == value.KDF && s.AEAD == value.AEAD
			}) {
				return nil, fmt.Errorf("GREASE ECH is outside the declared cipher/length rules: %+v", value)
			}
			out := *h
			out.Extensions = slices.Clone(h.Extensions)
			for i, e := range out.Extensions {
				if e.Type == fingerprint.ExtEncryptedClientHello {
					out.Extensions[i].Data = bytes.Clone(e.Data)
					binary.BigEndian.PutUint16(out.Extensions[i].Data[1:3], suites[0].KDF)
					binary.BigEndian.PutUint16(out.Extensions[i].Data[3:5], suites[0].AEAD)
				}
			}
			return &out, nil
		}
	}
	return h, nil
}

func TestA13ECHNormalizationNegativeControls(t *testing.T) {
	data, err := os.ReadFile("profile/testdata/catalogue-tls-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Specs map[string]*profile.TLSSpec `json:"specs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	p := policyFile(t, nil)
	p.ClientHello = nil
	p.PerConnection = nil
	p.TLSSpec = fixture.Specs["firefox_132"]
	cp, err := p.ClientProfile()
	if err != nil {
		t.Fatal(err)
	}
	c := tls.UClient(nil, &tls.Config{ServerName: "a13.test", OmitEmptyPsk: true}, cp.GetClientHelloId(), false, false, false)
	if err := c.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	msg := c.HandshakeState.Hello.Raw
	h, err := fingerprint.ParseClientHello(append([]byte{22, 3, 1, byte(len(msg) >> 8), byte(len(msg))}, msg...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a13NormalizeECH(h, p.TLSSpec); err != nil {
		t.Fatal("positive control", err)
	}
	for _, edit := range []func([]byte) []byte{
		func(b []byte) []byte { b[4] = 9; return b },
		func(b []byte) []byte { b[2] = 2; return b },
		func(b []byte) []byte { b[7] = 31; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
	} {
		bad := *h
		bad.Extensions = slices.Clone(h.Extensions)
		for i, e := range bad.Extensions {
			if e.Type == fingerprint.ExtEncryptedClientHello {
				bad.Extensions[i].Data = edit(bytes.Clone(e.Data))
			}
		}
		if _, err := a13NormalizeECH(&bad, p.TLSSpec); err == nil {
			t.Fatal("normalizer hid an illegal ECH value")
		}
	}
	badPolicy := p.Clone()
	for i, e := range badPolicy.TLSSpec.Extensions {
		if e.Type == "grease_ech" {
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(e.Parameters, &fields)
			fields["payload_lengths"] = json.RawMessage(`[1]`)
			badPolicy.TLSSpec.Extensions[i].Parameters, _ = json.Marshal(fields)
		}
	}
	if _, err := a13NormalizeECH(h, badPolicy.TLSSpec); err == nil {
		t.Fatal("normalizer ignored payload-length rules")
	}
}

func TestA13TLSJSONMutationReachesWire(t *testing.T) {
	data, err := os.ReadFile("profile/testdata/catalogue-tls-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Specs map[string]*profile.TLSSpec `json:"specs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"original", "renamed", "cipher-order", "alpn", "record-limit", "grease-body", "padding"} {
		t.Run(variant, func(t *testing.T) {
			p := policyFile(t, nil)
			p.ClientHello = nil
			p.PerConnection = nil
			p.TLSSpec = fixture.Specs["firefox_132"]
			if variant == "grease-body" || variant == "padding" {
				p.TLSSpec = fixture.Specs["chrome_103"]
			}
			encoded, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			spec := fields["tls_spec"].(map[string]any)
			if variant == "renamed" {
				fields["name"] = "unrelated-identity"
				fields["user_agent"] = "new metadata"
			}
			if variant == "cipher-order" {
				values := spec["cipher_suites"].([]any)
				values[0], values[1] = values[1], values[0]
			}
			greaseSlot := 0
			for _, v := range spec["extensions"].([]any) {
				e := v.(map[string]any)
				if variant == "grease-body" && e["type"] == "grease" {
					if greaseSlot == 1 {
						e["parameters"] = map[string]any{"body": "AQID"}
					}
					greaseSlot++
				}
				if variant == "padding" && e["type"] == "padding" {
					e["parameters"] = map[string]any{"algorithm": "range", "lower_exclusive": 0, "upper_exclusive": 4096, "target": 4096, "minimum": 1}
				}
				if variant == "alpn" && e["type"] == "alpn" {
					e["parameters"] = map[string]any{"protocols": []string{"http/1.1"}}
				}
				if variant == "record-limit" && e["type"] == "record_size_limit" {
					e["parameters"] = map[string]any{"limit": 4096}
				}
			}
			encoded, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			p, err = profile.Load(encoded)
			if err != nil {
				t.Fatal(err)
			}
			server := startEchoWithTickets(t)
			client := newTestClient(t, WithProfileValue(p), WithFixedExtensionOrder())
			seen := measure(t, client, server)
			hello, err := seen.Hello()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(slices.DeleteFunc(slices.Clone(hello.CipherSuites), fingerprint.IsGREASE), slices.DeleteFunc(slices.Clone(p.TLSSpec.CipherSuites), fingerprint.IsGREASE)) {
				t.Fatal("cipher vector did not reach wire")
			}
			if variant == "alpn" {
				if seen.Negotiated != "http/1.1" || !slices.Equal(hello.ALPN(), []string{"http/1.1"}) {
					t.Fatal("ALPN JSON ignored")
				}
			} else if seen.Negotiated != "h2" {
				t.Fatal("protocol changed", seen.Negotiated)
			}
			if variant == "grease-body" {
				var last []byte
				for _, e := range hello.Extensions {
					if fingerprint.IsGREASE(e.Type) {
						last = e.Data
					}
				}
				if !bytes.Equal(last, []byte{1, 2, 3}) {
					t.Fatal("explicit GREASE JSON ignored", last)
				}
				return
			}
			if variant == "padding" {
				if len(hello.Raw) != 4101 {
					t.Fatal("padding JSON ignored", len(hello.Raw))
				}
				return
			}
			limit, ok := hello.Extension(28)
			want := uint16(16385)
			if variant == "record-limit" {
				want = 4096
			}
			if !ok || len(limit) != 2 || binary.BigEndian.Uint16(limit) != want {
				t.Fatal("record limit JSON ignored", limit)
			}
		})
	}
}

// This is a TLS-adapter comparison, not acceptance of historical browsers or
// their whole catalogue transport. Both sides explicitly use the same H2 and
// persistent-session policy; only their source of ClientHello data differs.
func TestA13DeclarativeTLSProduction(t *testing.T) {
	data, err := os.ReadFile("profile/testdata/catalogue-tls-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Specs map[string]*profile.TLSSpec `json:"specs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(fixture.Specs))
	for name := range fixture.Specs {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) != 83 {
		t.Fatal("catalogue denominator changed", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			server := startEchoWithTickets(t)
			var before [3]*capture.Capture
			var beforeResume [3]bool
			for _, declarative := range []bool{false, true} {
				p := policyFile(t, nil)
				p.ClientHello = nil
				p.PerConnection = nil
				p.Base = name
				if declarative {
					p.Base = ""
					p.TLSSpec = fixture.Specs[name]
				}
				encoded, err := p.Save()
				if err != nil {
					t.Fatal(err)
				}
				p, err = profile.Load(encoded)
				if err != nil {
					t.Fatal(err)
				}
				client := newTestClient(t, WithProfileValue(p), WithFixedExtensionOrder())
				for i := range 3 {
					if i == 2 {
						client.CloseIdleConnections()
					}
					got, conn := measuredOn(t, client, server)
					if dir := os.Getenv("TLSFORGE_A13_EVIDENCE_DIR"); dir != "" {
						kind := "before"
						if declarative {
							kind = "after"
						}
						dir = filepath.Join(dir, name, kind)
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						raw, err := json.MarshalIndent(got, "", "  ")
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(dir, []string{"cold.json", "reused.json", "new-connection.json"}[i]), raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if conn.Reused != (i == 1) || conn.Resumed != got.TLS.Resumed {
						t.Fatalf("request %d: connection lifecycle %+v, resumed=%v", i, conn, got.TLS.Resumed)
					}
					if !declarative {
						before[i] = got
						beforeResume[i] = conn.Resumed
					} else {
						if conn.Resumed != beforeResume[i] || got.Negotiated != before[i].Negotiated {
							t.Fatalf("request %d: resumption/protocol changed", i)
						}
						if i == 0 {
							a, err := before[i].Hello()
							if err != nil {
								t.Fatal(err)
							}
							b, err := got.Hello()
							if err != nil {
								t.Fatal(err)
							}
							a, err = a13NormalizeECH(a, fixture.Specs[name])
							if err != nil {
								t.Fatal(err)
							}
							b, err = a13NormalizeECH(b, fixture.Specs[name])
							if err != nil {
								t.Fatal(err)
							}
							if report := fingerprint.CompareTLS(a, b); !report.OK() {
								t.Fatalf("TLS wire changed: %+v", report)
							}
							if bytes.Equal(a.Random, b.Random) {
								t.Fatal("random replayed across clients")
							}
						}
					}

				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
