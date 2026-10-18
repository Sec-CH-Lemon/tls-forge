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
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Extension numbers this package reads by name. The full registry is large and
// mostly irrelevant here; these are the ones that feed a fingerprint.
const (
	ExtServerName           uint16 = 0
	ExtStatusRequest        uint16 = 5
	ExtSupportedGroups      uint16 = 10
	ExtECPointFormats       uint16 = 11
	ExtSignatureAlgorithms  uint16 = 13
	ExtALPN                 uint16 = 16
	ExtSCT                  uint16 = 18
	ExtPadding              uint16 = 21
	ExtExtendedMasterSecret uint16 = 23
	ExtCompressCertificate  uint16 = 27
	ExtSessionTicket        uint16 = 35
	ExtPreSharedKey         uint16 = 41
	ExtSupportedVersions    uint16 = 43
	ExtPSKKeyExchangeModes  uint16 = 45
	ExtKeyShare             uint16 = 51
	ExtTrustAnchors         uint16 = 51764
	ExtEncryptedClientHello uint16 = 65037
	ExtRenegotiationInfo    uint16 = 65281

	// ExtALPS is application_settings, ALPS, under the codepoint BoringSSL
	// gives it now, 17613 (0x44cd), which Chrome 155 sends; ExtALPSOld is the
	// one it had first, 17513 (0x4469), which older Chrome sends. The names
	// are BoringSSL's.
	ExtALPS    uint16 = 17613
	ExtALPSOld uint16 = 17513

	// ExtApplicationSettings is 17513, the codepoint BoringSSL calls
	// application_settings_old: this name says the other.
	//
	// Deprecated: use ExtALPSOld, of the same value.
	ExtApplicationSettings uint16 = 17513
	// ExtApplicationSettingsOld is 17613, the codepoint BoringSSL calls
	// application_settings, which Chrome sends now: this name says the other.
	//
	// Deprecated: use ExtALPS, of the same value.
	ExtApplicationSettingsOld uint16 = 17613
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

	// RecordVersion is the version the record layer was written with, which
	// is not the hello's: TLS 1.3 asks for 0x0301 there on a first hello.
	// Records is how many records the hello came in, which says where the
	// client cut it; a browser's fits in one, however long.
	RecordVersion uint16
	Records       int

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
	message, err := handshakeBody(records)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(message.body)
	hello := &ClientHello{Raw: records[:message.consumed], RecordVersion: message.version, Records: message.records}
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

// reassembled is a ClientHello body put back together from its records: how
// many bytes of the input they took, the version the first was written with,
// and how many there were.
type reassembled struct {
	body     []byte
	consumed int
	version  uint16
	records  int
}

// handshakeBody reassembles the ClientHello body from one or more records and
// reports how many bytes of the input it consumed.
func handshakeBody(records []byte) (reassembled, error) {
	var out reassembled
	var handshake []byte
	s := cryptobyte.String(records)
	for !s.Empty() {
		var recordType uint8
		var version uint16
		var payload cryptobyte.String
		if !s.ReadUint8(&recordType) || !s.ReadUint16(&version) || !s.ReadUint16LengthPrefixed(&payload) {
			return reassembled{}, fmt.Errorf("fingerprint: truncated TLS record")
		}
		if recordType != recordTypeHandshake {
			return reassembled{}, ErrNotClientHello
		}
		if out.records == 0 {
			out.version = version
		}
		out.records++
		handshake = append(handshake, payload...)
		if len(handshake) == 0 {
			// A record carrying an empty payload. Legal framing, and it
			// contributes no byte to judge, so there is nothing to do but read
			// the next record. Indexing here instead is a panic reachable by
			// any peer that can open a socket.
			continue
		}
		// Checked as soon as one byte exists rather than after reassembly: a
		// ServerHello reflected by a misconfigured proxy is also a handshake
		// record, and length-prefix parsing it as a ClientHello would produce a
		// plausible, wrong answer instead of an error.
		if handshake[0] != typeClientHello {
			return reassembled{}, ErrNotClientHello
		}
		if len(handshake) > maxHandshakeSize {
			return reassembled{}, fmt.Errorf("fingerprint: handshake exceeds %d bytes", maxHandshakeSize)
		}
		// Stop as soon as the message is complete rather than draining every
		// record: whatever follows belongs to the rest of the handshake.
		if body, ok := completeHandshake(handshake); ok {
			out.body, out.consumed = body, len(records)-len(s)
			return out, nil
		}
	}
	if len(handshake) == 0 {
		return reassembled{}, fmt.Errorf("fingerprint: no TLS records")
	}
	return reassembled{}, fmt.Errorf("fingerprint: incomplete ClientHello")
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
	var out []uint16
	for _, share := range c.KeyShares() {
		out = append(out, share.Group)
	}
	return out
}

// KeyShare is one entry of key_share: its group, and how long its key is. The
// key itself is fresh for every connection, and only its length says anything
// about the client: 1216 bytes for X25519MLKEM768, 32 for X25519, one for a
// GREASE group's.
type KeyShare struct {
	Group  uint16
	Length int
}

// KeyShares returns the entries of key_share in the order sent, GREASE
// included, as far as they parse.
func (c *ClientHello) KeyShares() []KeyShare {
	data, ok := c.Extension(ExtKeyShare)
	if !ok {
		return nil
	}
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []KeyShare
	for !list.Empty() {
		var share KeyShare
		var key cryptobyte.String
		if !list.ReadUint16(&share.Group) || !list.ReadUint16LengthPrefixed(&key) {
			return out
		}
		share.Length = len(key)
		out = append(out, share)
	}
	return out
}

// TrustAnchors returns the IDs of trust_anchors in the order sent, each as the
// relative object identifier it is, dotted (44947.2.1), or in hex when it is
// not one. Chrome 154 and later send them sorted by their bytes; an older
// Chrome drew their order once for each process it ran. The IDs say which root
// store sent them.
func (c *ClientHello) TrustAnchors() []string {
	body, ok := c.vectorBody(ExtTrustAnchors, uint16Prefixed)
	if !ok {
		return nil
	}
	var out []string
	for !body.Empty() {
		var id cryptobyte.String
		if !body.ReadUint8LengthPrefixed(&id) {
			return out
		}
		out = append(out, relativeOID(id))
	}
	return out
}

// trustAnchorsInByteOrder reports trust_anchors' IDs sorted by their bytes, as
// Chrome 154 and later send them, the length each leads with aside; so too when
// there are none, or when a malformed one ends what can be read.
func (c *ClientHello) trustAnchorsInByteOrder() bool {
	body, ok := c.vectorBody(ExtTrustAnchors, uint16Prefixed)
	if !ok {
		return true
	}
	var previous cryptobyte.String
	for !body.Empty() {
		var id cryptobyte.String
		if !body.ReadUint8LengthPrefixed(&id) {
			return true
		}
		if bytes.Compare(previous, id) > 0 {
			return false
		}
		previous = id
	}
	return true
}

// relativeOID reads a relative object identifier: arcs in base 128, the high
// bit set on every byte of an arc but its last. Anything else is said in hex,
// as is an arc with a needless leading zero, which is not the same ID written
// another way but another ID.
func relativeOID(b []byte) string {
	var arcs []string
	var arc uint64
	for i, octet := range b {
		if arc == 0 && octet == 0x80 || arc > 1<<56 {
			return fmt.Sprintf("%x", b)
		}
		arc = arc<<7 | uint64(octet&0x7f)
		if octet&0x80 == 0 {
			arcs = append(arcs, fmt.Sprint(arc))
			arc = 0
			continue
		}
		if i == len(b)-1 {
			return fmt.Sprintf("%x", b)
		}
	}
	if len(arcs) == 0 {
		return "(empty)"
	}
	return strings.Join(arcs, ".")
}

// PSK is what a server can read of pre_shared_key without its keys: how many
// identities it offers, and how long each binder is. The identities are
// tickets the server issued, and the binders are fresh for every hello.
type PSK struct {
	Identities int
	Binders    []int
}

// PreSharedKey returns the shape of pre_shared_key, or false for a hello
// without one, or with one that does not parse.
func (c *ClientHello) PreSharedKey() (PSK, bool) {
	data, ok := c.Extension(ExtPreSharedKey)
	if !ok {
		return PSK{}, false
	}
	s := cryptobyte.String(data)
	var identities, binders cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&identities) || !s.ReadUint16LengthPrefixed(&binders) || !s.Empty() {
		return PSK{}, false
	}
	var out PSK
	for !identities.Empty() {
		var identity cryptobyte.String
		var age uint32
		if !identities.ReadUint16LengthPrefixed(&identity) || !identities.ReadUint32(&age) {
			return PSK{}, false
		}
		out.Identities++
	}
	for !binders.Empty() {
		var binder cryptobyte.String
		if !binders.ReadUint8LengthPrefixed(&binder) {
			return PSK{}, false
		}
		out.Binders = append(out.Binders, len(binder))
	}
	return out, true
}

// ECPointFormats returns the elliptic curve point formats. JA3 hashes them.
func (c *ClientHello) ECPointFormats() []uint8 {
	return c.uint8Vector(ExtECPointFormats)
}

// PSKKeyExchangeModes returns the offered PSK modes.
func (c *ClientHello) PSKKeyExchangeModes() []uint8 {
	return c.uint8Vector(ExtPSKKeyExchangeModes)
}

// ECH is what a server can read of the encrypted_client_hello extension of a
// hello to it when it published no ECH configuration, which is every server a
// browser has not been told about: GREASE, the shape of a real one with random
// contents, so that servers cannot come to depend on its absence. Its cipher
// suite, the length of its encapsulated key and the length of its payload.
type ECH struct {
	KDF, AEAD     uint16
	ConfigID      uint8
	EncLength     int
	PayloadLength int
}

// EncryptedClientHello returns the encrypted_client_hello extension of an outer
// ClientHello, or false for a hello without one, or with one that is an inner
// hello's or does not parse.
func (c *ClientHello) EncryptedClientHello() (ECH, bool) {
	data, ok := c.Extension(ExtEncryptedClientHello)
	if !ok {
		return ECH{}, false
	}
	s := cryptobyte.String(data)
	var out ECH
	var outer uint8
	var enc, payload cryptobyte.String
	if !s.ReadUint8(&outer) || outer != 0 || !s.ReadUint16(&out.KDF) || !s.ReadUint16(&out.AEAD) ||
		!s.ReadUint8(&out.ConfigID) || !s.ReadUint16LengthPrefixed(&enc) ||
		!s.ReadUint16LengthPrefixed(&payload) || !s.Empty() {
		return ECH{}, false
	}
	out.EncLength, out.PayloadLength = len(enc), len(payload)
	return out, true
}

// ApplicationSettings returns the ALPS protocol list. Chrome sends this
// extension under two different numbers depending on version, and which one it
// picks is itself a version signal, so both are read, the current one first.
func (c *ClientHello) ApplicationSettings() []string {
	for _, typ := range []uint16{ExtALPS, ExtALPSOld} {
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
