package profile

import (
	"bytes"
	"encoding/json"
	tls "github.com/igor-lemon/utls"
	"slices"
	"strings"
	"testing"
)

func nativeQUICProfile(t *testing.T) *Profile {
	t.Helper()
	p, err := Get("firefox_148")
	if err != nil {
		t.Fatal(err)
	}
	if p.QUICTLSSpec == nil {
		t.Fatal("missing independent descriptor")
	}
	return p
}
func TestIndependentQUICTLSDescriptorRoundTripAndLiveValues(t *testing.T) {
	p := nativeQUICProfile(t)
	raw, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	clone := loaded.Clone()
	clone.QUICTLSSpec.Hello.CipherSuites[0] = 4867
	clone.QUICTLSSpec.CipherSuitesWithoutAES[0] = 4865
	clone.QUICTLSSpec.Hello.Extensions[0].Parameters = []byte(`{"source":"changed"}`)
	if p.QUICTLSSpec.Hello.CipherSuites[0] != 4865 || loaded.QUICTLSSpec.CipherSuitesWithoutAES[0] != 4867 || bytes.Contains(loaded.QUICTLSSpec.Hello.Extensions[0].Parameters, []byte("changed")) {
		t.Fatal("clone mutated source")
	}
	cp, err := loaded.ClientProfile()
	if err != nil {
		t.Fatal(err)
	}
	factory := cp.GetQUICClientHelloSpec()
	if factory == nil {
		t.Fatal("transport factory missing")
	}
	params := []byte{15, 0}
	spec, err := factory(params)
	if err != nil {
		t.Fatal(err)
	}
	params[0] = 99
	want := []uint16{4865, 4866, 4867}
	if !tls.AESGCMHardwareSupport() {
		want = []uint16{4867, 4865, 4866}
	}
	if !slices.Equal(spec.CipherSuites, want) {
		t.Fatal(spec.CipherSuites, want)
	}
	found := false
	for _, ext := range spec.Extensions {
		if ext, ok := ext.(*tls.GenericExtension); ok && ext.Id == 57 {
			found = true
			if !bytes.Equal(ext.Data, []byte{15, 0}) {
				t.Fatal("TP aliases live input")
			}
		}
	}
	if !found {
		t.Fatal("no TP")
	}
	for _, order := range []string{"fixed", "moving", "utls"} {
		q := p.QUICTLSSpec.clone()
		q.Hello.ExtensionOrder = order
		if err := q.validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := q.spec(nil); err != nil {
			t.Fatal(err)
		}
	}
	q := p.QUICTLSSpec.clone()
	q.CipherOrder = "fixed"
	q.CipherSuitesWithoutAES = []uint16{}
	if err := q.validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.spec(nil); err != nil {
		t.Fatal(err)
	}
	var missing *QUICTLSSpec
	if missing.clone() != nil {
		t.Fatal("nil clone")
	}
}

func TestIndependentQUICTLSDescriptorRejectsUnsupportedOrAmbiguousData(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*QUICTLSSpec)
		want string
	}{
		{"missing hello", func(q *QUICTLSSpec) { q.Hello = nil }, "requires hello"},
		{"unknown cipher algorithm", func(q *QUICTLSSpec) { q.CipherOrder = "browser-name" }, "cipher_order"},
		{"low TLS", func(q *QUICTLSSpec) { q.Hello.MinVersion = 771 }, "exact TLS1.3"},
		{"high TLS", func(q *QUICTLSSpec) { q.Hello.MaxVersion = 773 }, "exact TLS1.3"},
		{"wrong session", func(q *QUICTLSSpec) { q.Hello.SessionID = "random" }, "session_id=empty"},
		{"empty ciphers", func(q *QUICTLSSpec) { q.Hello.CipherSuites = nil }, "vectors"},
		{"unknown cipher", func(q *QUICTLSSpec) { q.Hello.CipherSuites[0] = 1234 }, "distinct supported"},
		{"duplicate cipher", func(q *QUICTLSSpec) { q.Hello.CipherSuites[0] = 4866 }, "distinct supported"},
		{"unused branch", func(q *QUICTLSSpec) { q.CipherOrder = "fixed" }, "unused AES"},
		{"different cipher sets", func(q *QUICTLSSpec) { q.CipherSuitesWithoutAES = []uint16{4867} }, "same cipher set"},
		{"no TP", func(q *QUICTLSSpec) {
			q.Hello.Extensions = slices.DeleteFunc(q.Hello.Extensions, func(e TLSExtension) bool { return e.Type == "quic_transport_parameters" })
		}, "requires live transport"},
		{"no versions", func(q *QUICTLSSpec) {
			for i, e := range q.Hello.Extensions {
				if e.Type == "supported_versions" {
					q.Hello.Extensions[i].Parameters = []byte(`{"values":[771]}`)
				}
			}
		}, "requires live transport"},
		{"wrong ALPN", func(q *QUICTLSSpec) {
			for i, e := range q.Hello.Extensions {
				if e.Type == "alpn" {
					q.Hello.Extensions[i].Parameters = []byte(`{"protocols":["h2"]}`)
				}
			}
		}, "requires live transport"},
		{"captured TP", func(q *QUICTLSSpec) {
			for i, e := range q.Hello.Extensions {
				if e.Type == "quic_transport_parameters" {
					q.Hello.Extensions[i].Parameters = []byte(`{"source":"capture"}`)
				}
			}
		}, "quic-connection source"},
		{"unknown TP field", func(q *QUICTLSSpec) {
			for i, e := range q.Hello.Extensions {
				if e.Type == "quic_transport_parameters" {
					q.Hello.Extensions[i].Parameters = []byte(`{"source":"quic-connection","bytes":""}`)
				}
			}
		}, "unknown field"},
		{"missing hybrid source", func(q *QUICTLSSpec) {
			for i, e := range q.Hello.Extensions {
				if e.Type == "key_share" {
					q.Hello.Extensions[i].Parameters = []byte(`{"shares":[{"group":29,"source":"fresh-mlkem768-component","data":[]}]}`)
				}
			}
		}, "fresh MLKEM768 source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := nativeQUICProfile(t).QUICTLSSpec.clone()
			tc.edit(q)
			if err := q.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v want %s", err, tc.want)
			}
		})
	}
	p := nativeQUICProfile(t)
	p.Behavior["quic.tls_source"] = json.RawMessage(`"tcp-adapter"`)
	if err := p.Validate(); err == nil {
		t.Fatal("factory/source conflict accepted")
	}
	p = nativeQUICProfile(t)
	p.QUICTLSSpec = nil
	if err := p.Validate(); err == nil {
		t.Fatal("missing factory accepted")
	}
	q := nativeQUICProfile(t).QUICTLSSpec
	if _, err := q.spec(make([]byte, 65536)); err == nil {
		t.Fatal("oversized live TP accepted")
	}
	h := q.Hello.clone()
	h.SessionID = "random"
	if _, err := h.compile(false); err == nil {
		t.Fatal("TCP descriptor accepted QUIC live TP source")
	}
}

func TestIndependentQUICTLSJSONRequiresEveryExactField(t *testing.T) {
	p := nativeQUICProfile(t)
	raw, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`null`, `[]`, `{}`, `{"hello":null,"cipher_order":"fixed","cipher_suites_without_aes":[]}`, `{"hello":{},"Cipher_order":"fixed","cipher_suites_without_aes":[]}`} {
		fields["quic_tls_spec"] = json.RawMessage(value)
		data, _ := json.Marshal(fields)
		if _, err := Load(data); err == nil {
			t.Fatal("ambiguous descriptor accepted", value)
		}
	}
}
