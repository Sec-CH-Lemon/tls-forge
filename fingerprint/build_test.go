package fingerprint

import "encoding/binary"

// A ClientHello builder for tests.
//
// Tests need helloes that no browser would send — an empty extension block, a
// truncated vector, a duplicate extension — and the only way to get those is to
// write the bytes. Everything here is the wire format spelled out; nothing is
// shared with the parser, so a mistake in the parser cannot cancel out a
// matching mistake in the fixtures.

type helloBuilder struct {
	legacyVersion uint16
	sessionID     []byte
	ciphers       []uint16
	compression   []byte
	extensions    []Extension
}

func newHello() *helloBuilder {
	return &helloBuilder{
		legacyVersion: 0x0303,
		compression:   []byte{0},
	}
}

func (b *helloBuilder) withCiphers(ciphers ...uint16) *helloBuilder {
	b.ciphers = ciphers
	return b
}

func (b *helloBuilder) withExtension(typ uint16, data []byte) *helloBuilder {
	b.extensions = append(b.extensions, Extension{Type: typ, Data: data})
	return b
}

// vector16 is a two-byte-length-prefixed list of uint16s: supported_groups,
// signature_algorithms, ALPN's outer frame.
func vector16(values ...uint16) []byte {
	body := make([]byte, 0, len(values)*2)
	for _, v := range values {
		body = binary.BigEndian.AppendUint16(body, v)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

// vector8of16 is a one-byte-length-prefixed list of uint16s: supported_versions,
// compress_certificate.
func vector8of16(values ...uint16) []byte {
	body := make([]byte, 0, len(values)*2)
	for _, v := range values {
		body = binary.BigEndian.AppendUint16(body, v)
	}
	return append([]byte{byte(len(body))}, body...)
}

// vector8 is a one-byte-length-prefixed list of bytes: ec_point_formats,
// psk_key_exchange_modes.
func vector8(values ...byte) []byte {
	return append([]byte{byte(len(values))}, values...)
}

// sni builds a server_name extension body.
func sni(host string) []byte {
	entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(host)))...)
	entry = append(entry, host...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(entry))), entry...)
}

// alpn builds an application_layer_protocol_negotiation body.
func alpn(protocols ...string) []byte {
	var list []byte
	for _, protocol := range protocols {
		list = append(list, byte(len(protocol)))
		list = append(list, protocol...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// keyShare builds a key_share body with one empty share per group.
func keyShare(groups ...uint16) []byte {
	var list []byte
	for _, group := range groups {
		list = binary.BigEndian.AppendUint16(list, group)
		list = binary.BigEndian.AppendUint16(list, 0) // zero-length key
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// body renders the handshake message body.
func (b *helloBuilder) body() []byte {
	out := binary.BigEndian.AppendUint16(nil, b.legacyVersion)
	out = append(out, make([]byte, 32)...) // random
	out = append(out, byte(len(b.sessionID)))
	out = append(out, b.sessionID...)

	ciphers := make([]byte, 0, len(b.ciphers)*2)
	for _, c := range b.ciphers {
		ciphers = binary.BigEndian.AppendUint16(ciphers, c)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(ciphers)))
	out = append(out, ciphers...)

	out = append(out, byte(len(b.compression)))
	out = append(out, b.compression...)

	if b.extensions == nil {
		return out
	}
	var extensions []byte
	for _, ext := range b.extensions {
		extensions = binary.BigEndian.AppendUint16(extensions, ext.Type)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(ext.Data)))
		extensions = append(extensions, ext.Data...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(extensions)))
	return append(out, extensions...)
}

// records wraps the message in a handshake header and a single TLS record.
func (b *helloBuilder) records() []byte {
	return recordsOf(handshakeMessage(typeClientHello, b.body()))
}

func handshakeMessage(msgType byte, body []byte) []byte {
	out := []byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func recordsOf(handshake []byte) []byte {
	out := []byte{recordTypeHandshake, 0x03, 0x01}
	out = binary.BigEndian.AppendUint16(out, uint16(len(handshake)))
	return append(out, handshake...)
}

// splitRecords fragments a handshake message across records of at most n bytes,
// which is legal and which some clients do.
func splitRecords(handshake []byte, n int) []byte {
	var out []byte
	for len(handshake) > 0 {
		chunk := handshake
		if len(chunk) > n {
			chunk = chunk[:n]
		}
		handshake = handshake[len(chunk):]
		out = append(out, recordTypeHandshake, 0x03, 0x01)
		out = binary.BigEndian.AppendUint16(out, uint16(len(chunk)))
		out = append(out, chunk...)
	}
	return out
}

// chrome151 is the extension set, cipher list and signature algorithms measured
// from a real Chrome 151, in a shape the builder can render.
//
// The expected JA4 alongside it is not this package's own output: it was taken
// independently from tls.browserleaks.com for the same browser, and the hashing
// rule was checked against that service's published ja4_r preimage. A test that
// compared this package against itself would pass with the formula wrong.
func chrome151() *helloBuilder {
	return newHello().
		withCiphers(0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035).
		withExtension(0x1a1a, nil).
		withExtension(ExtServerName, sni("tls.browserleaks.com")).
		withExtension(ExtStatusRequest, []byte{1, 0, 0, 0, 0}).
		withExtension(ExtSupportedGroups, vector16(0x8a8a, 4588, 29, 23, 24)).
		withExtension(ExtECPointFormats, vector8(0)).
		withExtension(ExtSignatureAlgorithms, vector16(
			0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)).
		withExtension(ExtALPN, alpn("h2", "http/1.1")).
		withExtension(ExtSCT, nil).
		withExtension(ExtExtendedMasterSecret, nil).
		withExtension(ExtCompressCertificate, vector8of16(2)).
		withExtension(ExtSessionTicket, nil).
		withExtension(ExtSupportedVersions, vector8of16(0xeaea, 0x0304, 0x0303)).
		withExtension(ExtPSKKeyExchangeModes, vector8(1)).
		withExtension(ExtKeyShare, keyShare(0xfafa, 4588, 29)).
		withExtension(ExtApplicationSettingsOld, alpn("h2")).
		withExtension(ExtEncryptedClientHello, []byte{0, 0, 1, 0, 1}).
		withExtension(ExtRenegotiationInfo, []byte{0}).
		withExtension(0xaaaa, nil)
}

const (
	chrome151JA4    = "t13d1516h2_8daaf6152771_806a8c22fdea"
	chrome151JA4Raw = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9" +
		"_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01" +
		"_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
)
