package pcapng

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

// What a client's key log says of an ECH offer, as NSS and uTLS write it
// (draft-ietf-tls-keylogfile): the KEM's shared secret (ECH_SECRET) and the
// ECHConfig offered (ECH_CONFIG), both by the random of the outer hello. With
// them the inner hello is opened, as Wireshark opens it, and its random is
// what the handshake's secrets are written by when the server accepted it.

// ECH labels of a key log.
const (
	ECHSecretLabel = "ECH_SECRET"
	ECHConfigLabel = "ECH_CONFIG"
)

// extensionECH is encrypted_client_hello's code point.
const extensionECH = 0xfe0d

// ECHInnerRandom is the random, in hex, of the inner hello that hello, a
// ClientHello message whose header is included, carries in its ECH offer:
// opened with the offer's shared secret and config, by RFC 9180's key
// schedule in its base mode, HKDF-SHA256 (uTLS's KDF, and BoringSSL's), the
// info and AAD of the ECH draft. False for a hello of no offer, one that does
// not read, or a payload they do not open: the AEAD holds the offer to the
// whole hello and the config, so a kind, a suite or a config other than the
// client's opens nothing.
func ECHInnerRandom(hello, secret, config []byte) (string, bool) {
	if len(hello) < 4 || hello[0] != 1 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return "", false
	}
	body := hello[4:]
	ext, at, ok := extensionOf(body, extensionECH)
	if !ok {
		return "", false
	}
	s := cryptobyte.String(ext)
	var kdf, aeadID uint16
	var enc, payload cryptobyte.String
	if !s.Skip(1) || !s.ReadUint16(&kdf) || !s.ReadUint16(&aeadID) || !s.Skip(1) ||
		!s.ReadUint16LengthPrefixed(&enc) || !s.ReadUint16LengthPrefixed(&payload) {
		return "", false
	}
	kem, ok := kemOf(config)
	if !ok {
		return "", false
	}
	newHash := sha256.New
	suite := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(
		binary.BigEndian.AppendUint16([]byte("HPKE"), kem), kdf), aeadID)
	info := append([]byte("tls ech\x00"), config...)
	context := append([]byte{0}, labeledExtract(newHash, suite, nil, "psk_id_hash", nil)...)
	context = append(context, labeledExtract(newHash, suite, nil, "info_hash", info)...)
	prk := labeledExtract(newHash, suite, secret, "secret", nil)
	aead, ok := aeadOf(aeadID, func(n int) []byte { return labeledExpand(newHash, suite, prk, "key", context, n) })
	if !ok {
		return "", false
	}
	nonce := labeledExpand(newHash, suite, prk, "base_nonce", context, aead.NonceSize())
	aad := append([]byte(nil), body...)
	start := at + len(ext) - len(payload)
	clear(aad[start : start+len(payload)])
	inner, err := aead.Open(nil, nonce, payload, aad)
	if err != nil || len(inner) < 34 {
		return "", false
	}
	return hex.EncodeToString(inner[2:34]), true
}

// extensionOf is the data of a ClientHello's extension of a code point, and
// where it begins in body, the message's body.
func extensionOf(body []byte, code uint16) ([]byte, int, bool) {
	s := cryptobyte.String(body)
	var session, suites, compression, exts cryptobyte.String
	if !s.Skip(2+32) || !s.ReadUint8LengthPrefixed(&session) ||
		!s.ReadUint16LengthPrefixed(&suites) || !s.ReadUint8LengthPrefixed(&compression) ||
		!s.ReadUint16LengthPrefixed(&exts) {
		return nil, 0, false
	}
	for !exts.Empty() {
		var id uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, 0, false
		}
		if id == code {
			return data, len(body) - len(exts) - len(data), true
		}
	}
	return nil, 0, false
}

// kemOf is the KEM an ECHConfig names (draft-ietf-tls-esni): after its
// version, its length and its config ID.
func kemOf(config []byte) (uint16, bool) {
	s := cryptobyte.String(config)
	var kem uint16
	if !s.Skip(2+2+1) || !s.ReadUint16(&kem) {
		return 0, false
	}
	return kem, true
}

// aeadOf is an HPKE AEAD of its key, which key gives of the length it asks:
// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, those uTLS offers ECH with.
func aeadOf(id uint16, key func(int) []byte) (cipher.AEAD, bool) {
	switch id {
	case 0x0001, 0x0002:
		// 16 or 32 bytes, neither of which is refused.
		block, _ := aes.NewCipher(key(16 * int(id)))
		aead, _ := cipher.NewGCM(block)
		return aead, true
	case 0x0003:
		aead, _ := chacha20poly1305.New(key(chacha20poly1305.KeySize))
		return aead, true
	}
	return nil, false
}

// labeledExtract and labeledExpand are RFC 9180's (section 4).
func labeledExtract(h func() hash.Hash, suite, salt []byte, label string, ikm []byte) []byte {
	in := append(append(append([]byte("HPKE-v1"), suite...), label...), ikm...)
	prk, _ := hkdf.Extract(h, in, salt)
	return prk
}

func labeledExpand(h func() hash.Hash, suite, prk []byte, label string, info []byte, length int) []byte {
	in := binary.BigEndian.AppendUint16(nil, uint16(length))
	in = append(append(append(append(in, "HPKE-v1"...), suite...), label...), info...)
	out, _ := hkdf.Expand(h, prk, string(in), length)
	return out
}
