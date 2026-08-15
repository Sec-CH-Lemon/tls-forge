// Package fingerprint turns the bytes a TLS client actually put on the wire
// into the hashes a fingerprinting service would compute from them.
//
// It exists so that "does our handshake match the browser's?" can be answered
// locally, from the raw ClientHello, instead of by asking a third-party service
// and trusting its answer. That matters for three reasons: the tests can be
// hermetic, the comparison keeps working when the service is down or changes
// its output, and a mismatch can be reported as a structural diff — this
// extension, that signature algorithm — rather than as two hashes that differ
// for reasons nobody can see.
package fingerprint

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Extension numbers this package reads by name. The full registry is large and
// mostly irrelevant here; these are the ones that feed a fingerprint.
const (
	ExtServerName             uint16 = 0
	ExtStatusRequest          uint16 = 5
	ExtSupportedGroups        uint16 = 10
	ExtECPointFormats         uint16 = 11
	ExtSignatureAlgorithms    uint16 = 13
	ExtALPN                   uint16 = 16
	ExtSCT                    uint16 = 18
	ExtPadding                uint16 = 21
	ExtExtendedMasterSecret   uint16 = 23
	ExtCompressCertificate    uint16 = 27
	ExtSessionTicket          uint16 = 35
	ExtPreSharedKey           uint16 = 41
	ExtSupportedVersions      uint16 = 43
	ExtPSKKeyExchangeModes    uint16 = 45
	ExtKeyShare               uint16 = 51
	ExtApplicationSettings    uint16 = 17513
	ExtApplicationSettingsOld uint16 = 17613
	ExtEncryptedClientHello   uint16 = 65037
	ExtRenegotiationInfo      uint16 = 65281
)

const (
	recordTypeHandshake = 0x16
	typeClientHello     = 0x01

	// A ClientHello larger than this is not a browser; it is either a bug or
	// somebody probing. Bounding the reassembly keeps a malicious peer from
	// making the echo server buffer without limit.
	maxHandshakeSize = 1 << 17
)

// ErrNotClientHello reports bytes that are syntactically fine as far as they go
// but are not the message this package parses — a ServerHello, an alert, or
// plain HTTP sent to a TLS port.
var ErrNotClientHello = errors.New("fingerprint: not a ClientHello")

// Extension is one entry of the ClientHello's extension block, kept in the
// order the client sent it and with its body intact.
//
// The body is kept because the extension TYPE alone is not the whole story: two
// clients can both send supported_groups and disagree about every group in it.
// The structural diff reads the bodies.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is a parsed TLS ClientHello, in wire order.
type ClientHello struct {
	// Raw is the exact record-layer prefix this hello was parsed from, with
	// whatever followed it on the wire trimmed off. A recorder that saved "the
	// bytes it happened to have read" would store a different number of bytes
	// depending on how the kernel split the stream; this is reproducible, which
	// makes it safe to write into a capture file and re-parse later.
	Raw []byte

	LegacyVersion      uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []Extension
}

// ParseClientHello reads a ClientHello out of raw TLS record-layer bytes — the
// first thing a server reads off an accepted connection.
//
// It takes records rather than a bare handshake message because that is the
// shape the bytes arrive in, and because a ClientHello may be split across
// several records. Chrome's is close to 2 KB once the post-quantum key share is
// in it, which is still one record; other clients fragment, and a parser that
// assumed one record would report those as malformed.
func ParseClientHello(records []byte) (*ClientHello, error) {
	body, consumed, err := handshakeBody(records)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(body)
	hello := &ClientHello{Raw: records[:consumed]}
	if !s.ReadUint16(&hello.LegacyVersion) {
		return nil, fmt.Errorf("fingerprint: truncated at legacy_version")
	}
	if !s.ReadBytes(&hello.Random, 32) {
		return nil, fmt.Errorf("fingerprint: truncated at random")
	}
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, fmt.Errorf("fingerprint: truncated at session_id")
	}
	hello.SessionID = sessionID

	var ciphers cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ciphers) || len(ciphers)%2 != 0 {
		return nil, fmt.Errorf("fingerprint: malformed cipher_suites")
	}
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		hello.CipherSuites = append(hello.CipherSuites, c)
	}

	var compression cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compression) {
		return nil, fmt.Errorf("fingerprint: truncated at compression_methods")
	}
	hello.CompressionMethods = compression

	// TLS 1.2 made the extension block optional. Nothing that matters here omits
	// it, but a ClientHello without one is legal and must not read as an error.
	if s.Empty() {
		return hello, nil
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, fmt.Errorf("fingerprint: truncated at extensions")
	}
	for !extensions.Empty() {
		var ext Extension
		var data cryptobyte.String
		if !extensions.ReadUint16(&ext.Type) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, fmt.Errorf("fingerprint: malformed extension")
		}
		ext.Data = data
		hello.Extensions = append(hello.Extensions, ext)
	}
	return hello, nil
}

// handshakeBody reassembles the ClientHello body from one or more records and
// reports how many bytes of the input it consumed.
func handshakeBody(records []byte) (body []byte, consumed int, err error) {
	var handshake []byte
	s := cryptobyte.String(records)
	for !s.Empty() {
		var recordType uint8
		var version uint16
		var payload cryptobyte.String
		if !s.ReadUint8(&recordType) || !s.ReadUint16(&version) || !s.ReadUint16LengthPrefixed(&payload) {
			return nil, 0, fmt.Errorf("fingerprint: truncated TLS record")
		}
		if recordType != recordTypeHandshake {
			return nil, 0, ErrNotClientHello
		}
		handshake = append(handshake, payload...)
		// Checked as soon as one byte exists rather than after reassembly: a
		// ServerHello reflected by a misconfigured proxy is also a handshake
		// record, and length-prefix parsing it as a ClientHello would produce a
		// plausible, wrong answer instead of an error.
		if handshake[0] != typeClientHello {
			return nil, 0, ErrNotClientHello
		}
		if len(handshake) > maxHandshakeSize {
			return nil, 0, fmt.Errorf("fingerprint: handshake exceeds %d bytes", maxHandshakeSize)
		}
		// Stop as soon as the message is complete rather than draining every
		// record: whatever follows belongs to the rest of the handshake.
		if body, ok := completeHandshake(handshake); ok {
			return body, len(records) - len(s), nil
		}
	}
	if len(handshake) == 0 {
		return nil, 0, fmt.Errorf("fingerprint: no TLS records")
	}
	return nil, 0, fmt.Errorf("fingerprint: incomplete ClientHello")
}

// completeHandshake reports whether the accumulated bytes hold a whole
// handshake message, and returns its body if so.
func completeHandshake(handshake []byte) ([]byte, bool) {
	if len(handshake) < 4 {
		return nil, false
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+length {
		return nil, false
	}
	return handshake[4 : 4+length], true
}

// Extension returns the body of the first extension of the given type.
//
// "First" rather than "only" because a duplicate extension is malformed but not
// unparseable, and the fingerprint of a malformed hello is still worth having:
// refusing to describe it would hide exactly the client worth looking at.
func (c *ClientHello) Extension(typ uint16) ([]byte, bool) {
	for _, ext := range c.Extensions {
		if ext.Type == typ {
			return ext.Data, true
		}
	}
	return nil, false
}

// ExtensionTypes lists the extension numbers in the order they were sent.
func (c *ClientHello) ExtensionTypes() []uint16 {
	out := make([]uint16, len(c.Extensions))
	for i, ext := range c.Extensions {
		out[i] = ext.Type
	}
	return out
}

// ServerName returns the SNI hostname.
func (c *ClientHello) ServerName() (string, bool) {
	data, ok := c.Extension(ExtServerName)
	if !ok {
		return "", false
	}
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return "", false
	}
	for !list.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
			return "", false
		}
		if nameType == 0 {
			return string(name), true
		}
	}
	return "", false
}

// ALPN returns the advertised application protocols, in order.
func (c *ClientHello) ALPN() []string {
	data, ok := c.Extension(ExtALPN)
	if !ok {
		return nil
	}
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []string
	for !list.Empty() {
		var proto cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&proto) {
			return out
		}
		out = append(out, string(proto))
	}
	return out
}

// SupportedVersions returns the versions from the supported_versions extension,
// GREASE included, in the order sent.
func (c *ClientHello) SupportedVersions() []uint16 {
	return c.uint16Vector(ExtSupportedVersions, uint8Prefixed)
}

// SupportedGroups returns the named groups (curves), GREASE included.
func (c *ClientHello) SupportedGroups() []uint16 {
	return c.uint16Vector(ExtSupportedGroups, uint16Prefixed)
}

// SignatureAlgorithms returns the signature schemes, in the order sent.
//
// Order is load-bearing: JA4 hashes this list unsorted, precisely because it is
// a preference list and clients disagree about the preference.
func (c *ClientHello) SignatureAlgorithms() []uint16 {
	return c.uint16Vector(ExtSignatureAlgorithms, uint16Prefixed)
}

// CertCompressionAlgorithms returns the certificate compression algorithms.
func (c *ClientHello) CertCompressionAlgorithms() []uint16 {
	return c.uint16Vector(ExtCompressCertificate, uint8Prefixed)
}

// KeyShareGroups returns the groups the client actually sent a key share for,
// which is a subset of SupportedGroups and a fingerprint in its own right: a
// client that offers X25519MLKEM768 but only ships an X25519 share is not the
// browser it claims to be.
func (c *ClientHello) KeyShareGroups() []uint16 {
	data, ok := c.Extension(ExtKeyShare)
	if !ok {
		return nil
	}
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []uint16
	for !list.Empty() {
		var group uint16
		var key cryptobyte.String
		if !list.ReadUint16(&group) || !list.ReadUint16LengthPrefixed(&key) {
			return out
		}
		out = append(out, group)
	}
	return out
}

// ECPointFormats returns the elliptic curve point formats. JA3 hashes them.
func (c *ClientHello) ECPointFormats() []uint8 {
	return c.uint8Vector(ExtECPointFormats)
}

// PSKKeyExchangeModes returns the offered PSK modes.
func (c *ClientHello) PSKKeyExchangeModes() []uint8 {
	return c.uint8Vector(ExtPSKKeyExchangeModes)
}

// ApplicationSettings returns the ALPS protocol list. Chrome sends this
// extension under two different numbers depending on version, and which one it
// picks is itself a version signal, so both are read.
func (c *ClientHello) ApplicationSettings() []string {
	for _, typ := range []uint16{ExtApplicationSettings, ExtApplicationSettingsOld} {
		data, ok := c.Extension(typ)
		if !ok {
			continue
		}
		s := cryptobyte.String(data)
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) {
			continue
		}
		var out []string
		for !list.Empty() {
			var proto cryptobyte.String
			if !list.ReadUint8LengthPrefixed(&proto) {
				break
			}
			out = append(out, string(proto))
		}
		return out
	}
	return nil
}

// The extensions above are all "length prefix, then a vector", and differ only
// in the width of the prefix. Naming the two shapes keeps nine accessors from
// being nine copies of the same nine lines.
type prefix int

const (
	uint8Prefixed prefix = iota
	uint16Prefixed
)

func (c *ClientHello) uint16Vector(typ uint16, p prefix) []uint16 {
	body, ok := c.vectorBody(typ, p)
	if !ok || len(body)%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, len(body)/2)
	for !body.Empty() {
		var v uint16
		body.ReadUint16(&v)
		out = append(out, v)
	}
	return out
}

func (c *ClientHello) uint8Vector(typ uint16) []uint8 {
	body, ok := c.vectorBody(typ, uint8Prefixed)
	if !ok {
		return nil
	}
	return append([]uint8(nil), body...)
}

func (c *ClientHello) vectorBody(typ uint16, p prefix) (cryptobyte.String, bool) {
	data, ok := c.Extension(typ)
	if !ok {
		return nil, false
	}
	s := cryptobyte.String(data)
	var body cryptobyte.String
	if p == uint8Prefixed {
		ok = s.ReadUint8LengthPrefixed(&body)
	} else {
		ok = s.ReadUint16LengthPrefixed(&body)
	}
	if !ok {
		return nil, false
	}
	return body, true
}
