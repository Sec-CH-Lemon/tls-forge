package profile

import (
	"encoding/binary"
	tls "github.com/igor-lemon/utls"
	"io"
	"slices"
)

// settingsForALPN binds settings to this connection's ALPN extension. The
// transport's WithForceHttp1 edits ALPN after the factory has returned, so a
// factory-time filter would still offer h2 settings on an HTTP/1.1-only hello.
func settingsForALPN(spec tls.ClientHelloSpec) tls.ClientHelloSpec {
	var alpn *tls.ALPNExtension
	for _, e := range spec.Extensions {
		if a, ok := e.(*tls.ALPNExtension); ok {
			alpn = a
			break
		}
	}
	for i, e := range spec.Extensions {
		var protocols []string
		var code uint16
		switch e := e.(type) {
		case *tls.ApplicationSettingsExtension:
			protocols = e.SupportedProtocols
			code = 17513
		case *tls.ApplicationSettingsExtensionNew:
			protocols = e.SupportedProtocols
			code = 17613
		default:
			continue
		}
		spec.Extensions[i] = &alpnSettings{TLSExtension: e, alpn: alpn, protocols: protocols, code: code}
	}
	return spec
}

// Embed the original extension's uTLS configuration hook (a no-op for ALPS).
// Len/Read use the same live ALPN pointer uTLS updates before serializing.
// Each Spec builds new extensions, so no connection shares this state.
type alpnSettings struct {
	tls.TLSExtension
	alpn      *tls.ALPNExtension
	protocols []string
	code      uint16
}

// Unwrap is the ALPS extension itself, for a hello made of the spec that
// offers ALPS for other protocols than this connection's (QUIC's, for h3:
// tls-client's profileQUICSpec).
func (e *alpnSettings) Unwrap() tls.TLSExtension { return e.TLSExtension }

func (e *alpnSettings) offered() []string {
	var out []string
	if e.alpn != nil {
		for _, p := range e.protocols {
			if slices.Contains(e.alpn.AlpnProtocols, p) {
				out = append(out, p)
			}
		}
	}
	return out
}
func (e *alpnSettings) Len() int {
	ps := e.offered()
	if len(ps) == 0 {
		return 0
	}
	n := 6
	for _, p := range ps {
		n += 1 + len(p)
	}
	return n
}
func (e *alpnSettings) Read(b []byte) (int, error) {
	n := e.Len()
	if n == 0 {
		return 0, io.EOF
	}
	if len(b) < n {
		return 0, io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(b, e.code)
	binary.BigEndian.PutUint16(b[2:], uint16(n-4))
	binary.BigEndian.PutUint16(b[4:], uint16(n-6))
	i := 6
	for _, p := range e.offered() {
		b[i] = byte(len(p))
		i++
		i += copy(b[i:], p)
	}
	return n, io.EOF
}
