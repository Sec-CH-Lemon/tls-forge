package profile

import (
	"fmt"
	tls "github.com/igor-lemon/utls"
	"slices"
)

// QUICTLSSpec independently describes QUIC TLS. CipherSuites in Hello is the
// fixed vector or the hardware-AES branch; neither branch is a browser constant.
type QUICTLSSpec struct {
	Hello                  *TLSSpec `json:"hello"`
	CipherOrder            string   `json:"cipher_order"`
	CipherSuitesWithoutAES []uint16 `json:"cipher_suites_without_aes"`
}

// UnmarshalJSON requires an exact, complete declarative QUIC TLS descriptor.
func (q *QUICTLSSpec) UnmarshalJSON(data []byte) error {
	type plain QUICTLSSpec
	return decodeDescriptorData(data, (*plain)(q))
}
func (q *QUICTLSSpec) clone() *QUICTLSSpec {
	if q == nil {
		return nil
	}
	out := *q
	out.Hello = q.Hello.clone()
	out.CipherSuitesWithoutAES = slices.Clone(q.CipherSuitesWithoutAES)
	return &out
}
func (q *QUICTLSSpec) validate() error {
	if q.Hello == nil {
		return fmt.Errorf("quic_tls_spec requires hello")
	}
	if q.CipherOrder != "fixed" && q.CipherOrder != "hardware-aes" {
		return fmt.Errorf("quic_tls_spec cipher_order requires fixed or hardware-aes")
	}
	h := q.Hello
	if h.MinVersion != tls.VersionTLS13 || h.MaxVersion != tls.VersionTLS13 {
		return fmt.Errorf("quic_tls_spec requires exact TLS1.3 bounds")
	}
	compiled, err := h.compileContext(false, true, nil)
	if err != nil {
		return err
	}
	for _, vector := range [][]uint16{h.CipherSuites, q.CipherSuitesWithoutAES} {
		for i, id := range vector {
			if id < 4865 || id > 4867 || slices.Contains(vector[:i], id) {
				return fmt.Errorf("quic_tls_spec requires distinct supported TLS1.3 ciphers")
			}
		}
	}
	if q.CipherOrder == "fixed" && q.CipherSuitesWithoutAES == nil {
		return fmt.Errorf("fixed cipher order requires an explicit empty alternate vector")
	}
	if q.CipherOrder == "fixed" && len(q.CipherSuitesWithoutAES) != 0 {
		return fmt.Errorf("fixed cipher order must not declare an unused AES branch")
	}
	if q.CipherOrder == "hardware-aes" {
		a, b := slices.Clone(h.CipherSuites), slices.Clone(q.CipherSuitesWithoutAES)
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			return fmt.Errorf("hardware-aes branches must offer the same cipher set")
		}
	}
	params, versions, alpn := false, false, false
	for _, e := range compiled.Extensions {
		switch e := e.(type) {
		case *tls.GenericExtension:
			params = params || e.Id == 57
		case *tls.SupportedVersionsExtension:
			versions = slices.Equal(e.Versions, []uint16{tls.VersionTLS13})
		case *tls.ALPNExtension:
			alpn = slices.Equal(e.AlpnProtocols, []string{"h3"})
		}
	}
	if !params || !versions || !alpn {
		return fmt.Errorf("quic_tls_spec requires live transport parameters, TLS1.3 supported_versions and h3 ALPN")
	}
	return nil
}
func (q *QUICTLSSpec) spec(params []byte) (tls.ClientHelloSpec, error) {
	return q.specWithAES(params, tls.AESGCMHardwareSupport())
}

func (q *QUICTLSSpec) specWithAES(params []byte, hardwareAES bool) (tls.ClientHelloSpec, error) {
	h := q.Hello.clone()
	if q.CipherOrder == "hardware-aes" && !hardwareAES {
		h.CipherSuites = slices.Clone(q.CipherSuitesWithoutAES)
	}
	out, err := h.compileContext(true, true, params)
	if err != nil {
		return out, err
	}
	switch h.ExtensionOrder {
	case "moving":
		shuffleExtensions(out.Extensions, extensionShuffle)
	case "utls":
		out.Extensions = tls.ShuffleChromeTLSExtensions(out.Extensions)
	}
	return out, nil
}
