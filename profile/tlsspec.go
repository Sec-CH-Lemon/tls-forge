package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	tls "github.com/igor-lemon/utls"
)

// TLSSpec is declarative input, not a recorded handshake. Generated and session
// values have named sources; a profile cannot supply keys, randoms or binders.
type TLSSpec struct {
	MinVersion         uint16         `json:"min_version"`
	MaxVersion         uint16         `json:"max_version"`
	CipherSuites       []uint16       `json:"cipher_suites"`
	CompressionMethods []uint8        `json:"compression_methods"`
	SessionID          string         `json:"session_id"`
	GREASE             string         `json:"grease"`
	ExtensionOrder     string         `json:"extension_order"`
	Extensions         []TLSExtension `json:"extensions"`
}

// TLSExtension selects a supported protocol primitive and its data. Parameters
// are strictly typed by that primitive, including for programmatic profiles.
type TLSExtension struct {
	Type       string          `json:"type"`
	Parameters json.RawMessage `json:"parameters"`
}

func (s *TLSSpec) clone() *TLSSpec {
	if s == nil {
		return nil
	}
	out := *s
	out.CipherSuites = slices.Clone(s.CipherSuites)
	out.CompressionMethods = slices.Clone(s.CompressionMethods)
	out.Extensions = slices.Clone(s.Extensions)
	for i := range out.Extensions {
		out.Extensions[i].Parameters = slices.Clone(s.Extensions[i].Parameters)
	}
	return &out
}

// decodeTLSData rejects omitted, null, misspelled and unknown parameters rather
// than letting encoding/json's case folding and zero defaults choose behavior.
func decodeTLSData(data []byte, target any) error {
	if err := validateProfileJSON(data); err != nil {
		return err
	}
	if err := checkTLSShape(data, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func checkTLSShape(data []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("TLS data must not be null")
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil // The extension primitive checks its own parameter object.
	}
	if t.Kind() == reflect.Slice {
		if t.Elem().Kind() == reflect.Uint8 && bytes.HasPrefix(bytes.TrimSpace(data), []byte(`"`)) {
			return nil
		} // encoding/json accepts base64 byte strings.
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, raw := range values {
			if err := checkTLSShape(raw, t.Elem()); err != nil {
				return err
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil || len(fields) != t.NumField() {
		return fmt.Errorf("requires every declared parameter exactly once")
	}
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Tag.Get("json")
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("requires non-null %s", name)
		}
		if err := checkTLSShape(raw, t.Field(i).Type); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// UnmarshalJSON requires the complete, unambiguous declarative representation.
func (s *TLSSpec) UnmarshalJSON(data []byte) error {
	type plain TLSSpec
	return decodeTLSData(data, (*plain)(s))
}

func (s *TLSSpec) validate() error {
	_, err := s.compile(false)
	return err
}

func (s *TLSSpec) spec() (tls.ClientHelloSpec, error) { return s.compile(true) }

func (s *TLSSpec) compile(generate bool) (tls.ClientHelloSpec, error) {
	invalid := func(err error) (tls.ClientHelloSpec, error) { return tls.ClientHelloSpec{}, err }
	if s.SessionID != "random" || s.GREASE != "boringssl" {
		return invalid(fmt.Errorf("tls_spec requires session_id=random and grease=boringssl (implemented generation primitives)"))
	}
	if s.ExtensionOrder != "fixed" && s.ExtensionOrder != "utls" && s.ExtensionOrder != "moving" {
		return invalid(fmt.Errorf("tls_spec.extension_order requires fixed, utls or moving"))
	}
	validVersion := func(v uint16) bool { return v == 0 || v >= tls.VersionTLS10 && v <= tls.VersionTLS13 }
	if !validVersion(s.MinVersion) || !validVersion(s.MaxVersion) || s.MinVersion != 0 && s.MaxVersion != 0 && s.MinVersion > s.MaxVersion {
		return invalid(fmt.Errorf("tls_spec requires ordered TLS 1.0..1.3 bounds, or explicit 0 for extension-derived bounds"))
	}
	if len(s.CipherSuites) == 0 || len(s.CipherSuites) > 32767 || len(s.CompressionMethods) == 0 || len(s.CompressionMethods) > 255 || s.Extensions == nil || len(s.Extensions) > 256 {
		return invalid(fmt.Errorf("tls_spec vectors exceed protocol/engine bounds or are empty"))
	}
	if len(s.CompressionMethods) != 1 || s.CompressionMethods[0] != 0 {
		return invalid(fmt.Errorf("tls_spec.compression_methods requires the implemented null-compression method [0]"))
	}
	out := tls.ClientHelloSpec{TLSVersMin: s.MinVersion, TLSVersMax: s.MaxVersion,
		CipherSuites: slices.Clone(s.CipherSuites), CompressionMethods: slices.Clone(s.CompressionMethods)}
	seen := map[string]bool{}
	greaseSlots := 0
	for i, e := range s.Extensions {
		if e.Type == "grease" {
			greaseSlots++
			if greaseSlots > 2 {
				return invalid(fmt.Errorf("tls_spec.extensions[%d]: engine supports at most two GREASE slots", i))
			}
		} else {
			if seen[e.Type] {
				return invalid(fmt.Errorf("tls_spec.extensions[%d]: duplicate %s extension", i, e.Type))
			}
			seen[e.Type] = true
		}
		if e.Type == "pre_shared_key" && i != len(s.Extensions)-1 {
			return invalid(fmt.Errorf("tls_spec.extensions[%d]: pre_shared_key must be last", i))
		}
		ext, err := e.build(generate)
		if err != nil {
			return invalid(fmt.Errorf("tls_spec.extensions[%d] (%s): %w", i, e.Type, err))
		}
		out.Extensions = append(out.Extensions, ext)
	}
	return out, nil
}

func (e TLSExtension) build(generate bool) (tls.TLSExtension, error) {
	bad := func(err error) (tls.TLSExtension, error) { return nil, err }
	switch e.Type {
	case "sni", "session_ticket":
		var p struct {
			Source string `json:"source"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if e.Type == "sni" && p.Source == "request-host" {
			return &tls.SNIExtension{}, nil
		}
		if e.Type == "session_ticket" && p.Source == "session-cache" {
			return &tls.SessionTicketExtension{}, nil
		}
		return bad(fmt.Errorf("unsupported source %q", p.Source))
	case "status_request", "extended_master_secret", "sct":
		if err := decodeTLSData(e.Parameters, &struct{}{}); err != nil {
			return bad(err)
		}
		switch e.Type {
		case "status_request":
			return &tls.StatusRequestExtension{}, nil
		case "extended_master_secret":
			return &tls.ExtendedMasterSecretExtension{}, nil
		default:
			return &tls.SCTExtension{}, nil
		}
	case "supported_groups", "signature_algorithms", "delegated_credentials", "supported_versions", "compress_certificate":
		var p struct {
			Values []uint16 `json:"values"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if len(p.Values) == 0 || len(p.Values) > 127 {
			return bad(fmt.Errorf("values requires 1..127 entries"))
		}
		switch e.Type {
		case "supported_groups":
			v := make([]tls.CurveID, len(p.Values))
			for i, n := range p.Values {
				v[i] = tls.CurveID(n)
			}
			return &tls.SupportedCurvesExtension{Curves: v}, nil
		case "supported_versions":
			return &tls.SupportedVersionsExtension{Versions: p.Values}, nil
		case "compress_certificate":
			v := make([]tls.CertCompressionAlgo, len(p.Values))
			for i, n := range p.Values {
				if n < 1 || n > 3 {
					return bad(fmt.Errorf("unsupported certificate compression algorithm %d", n))
				}
				v[i] = tls.CertCompressionAlgo(n)
			}
			return &tls.UtlsCompressCertExtension{Algorithms: v}, nil
		default:
			v := make([]tls.SignatureScheme, len(p.Values))
			for i, n := range p.Values {
				v[i] = tls.SignatureScheme(n)
			}
			if e.Type == "signature_algorithms" {
				return &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: v}, nil
			}
			return &tls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: v}, nil
		}
	case "point_formats", "psk_modes":
		var p struct {
			Values []uint8 `json:"values"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if len(p.Values) == 0 || len(p.Values) > 255 {
			return bad(fmt.Errorf("values requires 1..255 entries"))
		}
		if e.Type == "point_formats" {
			return &tls.SupportedPointsExtension{SupportedPoints: p.Values}, nil
		}
		return &tls.PSKKeyExchangeModesExtension{Modes: p.Values}, nil
	case "alpn", "alps", "alps_new":
		var p struct {
			Protocols []string `json:"protocols"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		n := 0
		for _, v := range p.Protocols {
			if len(v) == 0 || len(v) > 255 {
				return bad(fmt.Errorf("protocol names require 1..255 bytes"))
			}
			n += 1 + len(v)
		}
		if n > 65533 {
			return bad(fmt.Errorf("protocol vector is too long"))
		}
		if e.Type == "alpn" {
			if n == 0 {
				return bad(fmt.Errorf("ALPN requires a protocol"))
			}
			return &tls.ALPNExtension{AlpnProtocols: p.Protocols}, nil
		}
		if e.Type == "alps" {
			return &tls.ApplicationSettingsExtension{SupportedProtocols: p.Protocols}, nil
		}
		return &tls.ApplicationSettingsExtensionNew{SupportedProtocols: p.Protocols}, nil
	case "renegotiation_info":
		var p struct {
			Mode int `json:"mode"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.Mode < 0 || p.Mode > 2 {
			return bad(fmt.Errorf("mode requires 0..2"))
		}
		return &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiationSupport(p.Mode)}, nil
	case "record_size_limit":
		var p struct {
			Limit uint16 `json:"limit"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.Limit < 64 || p.Limit > 16385 {
			return bad(fmt.Errorf("limit requires 64..16385"))
		}
		return &tls.FakeRecordSizeLimitExtension{Limit: p.Limit}, nil
	case "grease":
		var p struct {
			Body []byte `json:"body"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if len(p.Body) > 65535 {
			return bad(fmt.Errorf("GREASE body is too long"))
		}
		return &tls.UtlsGREASEExtension{Body: p.Body, BodySet: true}, nil
	case "padding":
		var p struct {
			Algorithm string `json:"algorithm"`
			Lower     int    `json:"lower_exclusive"`
			Upper     int    `json:"upper_exclusive"`
			Target    int    `json:"target"`
			Minimum   int    `json:"minimum"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.Algorithm != "range" {
			return bad(fmt.Errorf("unsupported padding algorithm %q", p.Algorithm))
		}
		if p.Lower < 0 || p.Upper <= p.Lower || p.Upper > p.Target || p.Target > 32767 || p.Minimum < 1 || p.Minimum > p.Target {
			return bad(fmt.Errorf("padding requires 0<=lower<upper<=target<=32767 and 1<=minimum<=target"))
		}
		return &tls.UtlsPaddingExtension{GetPaddingLen: func(n int) (int, bool) {
			if n > p.Lower && n < p.Upper {
				return max(p.Target-n-4, p.Minimum), true
			}
			return 0, false
		}}, nil
	case "pre_shared_key":
		var p struct {
			Source    string `json:"source"`
			OmitEmpty bool   `json:"omit_empty"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.Source != "session-cache" {
			return bad(fmt.Errorf("PSK requires session-cache source"))
		}
		if !p.OmitEmpty {
			return bad(fmt.Errorf("the implemented transport requires omit_empty=true; empty PSK identities must not be sent"))
		}
		psk := &tls.UtlsPreSharedKeyExtension{}
		psk.SetOmitEmptyPsk(p.OmitEmpty)
		return psk, nil
	case "key_share":
		var p struct {
			Shares []struct {
				Group  uint16 `json:"group"`
				Source string `json:"source"`
				Data   []byte `json:"data"`
			} `json:"shares"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if len(p.Shares) == 0 || len(p.Shares) > 32 {
			return bad(fmt.Errorf("shares requires 1..32 entries"))
		}
		out := &tls.KeyShareExtension{}
		seen := map[uint16]bool{}
		for _, v := range p.Shares {
			if seen[v.Group] {
				return bad(fmt.Errorf("duplicate key share group %d", v.Group))
			}
			seen[v.Group] = true
			if v.Group == tls.GREASE_PLACEHOLDER {
				if v.Source != "grease" || len(v.Data) > 255 {
					return bad(fmt.Errorf("GREASE share requires grease source and at most 255 data bytes"))
				}
			} else {
				if v.Source != "fresh" || len(v.Data) != 0 {
					return bad(fmt.Errorf("key shares require fresh keys; captured key data is forbidden"))
				}
				switch tls.CurveID(v.Group) {
				case tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519, tls.X25519MLKEM768, tls.X25519Kyber768Draft00:
				default:
					return bad(fmt.Errorf("unsupported fresh key share group %d", v.Group))
				}
			}
			out.KeyShares = append(out.KeyShares, tls.KeyShare{Group: tls.CurveID(v.Group), Data: v.Data})
		}
		return out, nil
	case "grease_ech":
		var p struct {
			CipherSuites []struct {
				KDF  uint16 `json:"kdf"`
				AEAD uint16 `json:"aead"`
			} `json:"cipher_suites"`
			ConfigID       string   `json:"config_id"`
			Key            string   `json:"encapsulated_key"`
			PayloadLengths []uint16 `json:"payload_lengths"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.ConfigID != "random-byte" || p.Key != "hpke-x25519-sha256-aes128gcm" {
			return bad(fmt.Errorf("requires fresh random-byte config ID and HPKE encapsulated key"))
		}
		if len(p.CipherSuites) == 0 || len(p.CipherSuites) > 127 || len(p.PayloadLengths) == 0 || len(p.PayloadLengths) > 256 {
			return bad(fmt.Errorf("ECH selection vectors are empty or exceed bounds"))
		}
		out := &tls.GREASEEncryptedClientHelloExtension{CandidatePayloadLens: p.PayloadLengths}
		for _, v := range p.CipherSuites {
			if v.KDF != 1 || v.AEAD < 1 || v.AEAD > 3 {
				return bad(fmt.Errorf("unsupported HPKE symmetric suite"))
			}
			out.CandidateCipherSuites = append(out.CandidateCipherSuites, tls.HPKESymmetricCipherSuite{KdfId: v.KDF, AeadId: v.AEAD})
		}
		for _, n := range p.PayloadLengths {
			if n == 0 || n > maxECHPayloadLength {
				return bad(fmt.Errorf("ECH payload length requires 1..%d", maxECHPayloadLength))
			}
		}
		return out, nil
	case "trust_anchors":
		var p struct {
			Data  []byte `json:"data"`
			Order string `json:"order"`
		}
		if err := decodeTLSData(e.Parameters, &p); err != nil {
			return bad(err)
		}
		if p.Order != "captured" && p.Order != "sorted" && p.Order != "process-shuffle" {
			return bad(fmt.Errorf("unsupported trust anchor order %q", p.Order))
		}
		if len(p.Data) > 65535 {
			return bad(fmt.Errorf("trust anchors payload is too long"))
		}
		data := p.Data
		if generate {
			var err error
			data, err = processTrustAnchors.payload(data, p.Order)
			if err != nil {
				return bad(err)
			}
		} else if _, err := splitTrustAnchors(data); err != nil {
			return bad(err)
		}
		return &tls.GenericExtension{Id: 51764, Data: data}, nil
	case "encrypt_then_mac":
		if err := decodeTLSData(e.Parameters, &struct{}{}); err != nil {
			return bad(err)
		}
		return &tls.GenericExtension{Id: 22}, nil
	default:
		return bad(fmt.Errorf("unsupported TLS extension primitive %q", e.Type))
	}
}
