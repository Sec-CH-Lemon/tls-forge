package pcapng

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// QUICClientRandom is the random of the ClientHello a QUIC client began a
// connection with, in hex, read from the Initial packets of the datagrams it
// sent, in order: their keys come from the connection ID each names (RFC
// 9001, section 5.2; after a Retry the one it gave), so whoever sees them
// reads them. False when the datagrams hold no ClientHello's first 38 bytes,
// in whatever order its CRYPTO frames came, or are not QUIC version 1's.
func QUICClientRandom(sent [][]byte) (string, bool) {
	var hello []byte // the ClientHello's start, as far as it is whole
	pieces := map[uint64][]byte{}
	var largest uint64
	for _, datagram := range sent {
		for len(datagram) > 0 {
			p, rest, ok := longHeader(datagram)
			if !ok {
				break
			}
			datagram = rest
			if p.kind != initialPacket {
				continue
			}
			payload, number, ok := clientInitialKeys(p.dcid).open(p, largest)
			if !ok {
				continue
			}
			largest = max(largest, number)
			for offset, data := range cryptoFrames(payload) {
				pieces[offset] = data
			}
			hello = joined(pieces)
			if len(hello) >= 38 {
				if hello[0] != 1 {
					return "", false
				}
				return hex.EncodeToString(hello[6:38]), true
			}
		}
	}
	return "", false
}

// quicVersion1 is the version an Initial packet is read for.
const quicVersion1 = 0x00000001

// initialPacket is the type a version 1 long header gives an Initial packet.
const initialPacket = 0

// longPacket is a long header packet of version 1 as it came: its type, the
// connection ID it was sent to, where its packet number begins in it, and
// where its packet ends.
type longPacket struct {
	kind   byte
	dcid   []byte
	raw    []byte
	number int
}

// longHeader reads the long header packet at the start of a datagram, and
// what follows it there: false for a short header packet, another version's
// or one cut short.
func longHeader(b []byte) (longPacket, []byte, bool) {
	if len(b) < 7 || b[0]&0x80 == 0 || binary.BigEndian.Uint32(b[1:5]) != quicVersion1 {
		return longPacket{}, nil, false
	}
	p := longPacket{kind: b[0] >> 4 & 3}
	i := 5
	dcid := int(b[i])
	i++
	if dcid > 20 || i+dcid+1 > len(b) {
		return longPacket{}, nil, false
	}
	p.dcid = b[i : i+dcid]
	i += dcid
	scid := int(b[i])
	i++
	if scid > 20 || i+scid > len(b) {
		return longPacket{}, nil, false
	}
	i += scid
	if p.kind == initialPacket {
		token, n := varint(b[i:])
		if n == 0 || uint64(len(b)-i-n) < token {
			return longPacket{}, nil, false
		}
		i += n + int(token)
	}
	length, n := varint(b[i:])
	if n == 0 || uint64(len(b)-i-n) < length {
		return longPacket{}, nil, false
	}
	i += n
	end := i + int(length)
	p.raw, p.number = b[:end], i
	return p, b[end:], true
}

// varint is a QUIC variable-length integer at the start of b and its length,
// 0 when b is too short for it.
func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// initialKeys protect a client's Initial packets.
type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// initialSalt is version 1's (RFC 9001, section 5.2).
var initialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
	0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// clientInitialKeys are the keys of a client's Initial packets to a
// connection ID.
func clientInitialKeys(dcid []byte) *initialKeys {
	initial, _ := hkdf.Extract(sha256.New, dcid, initialSalt)
	secret := expandLabel(initial, "client in", 32)
	block, _ := aes.NewCipher(expandLabel(secret, "quic key", 16))
	aead, _ := cipher.NewGCM(block)
	hp, _ := aes.NewCipher(expandLabel(secret, "quic hp", 16))
	return &initialKeys{aead: aead, iv: expandLabel(secret, "quic iv", 12), hp: hp}
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with no context.
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := append(binary.BigEndian.AppendUint16(nil, uint16(length)), byte(len(full)))
	info = append(append(info, full...), 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), length)
	return out
}

// open takes a packet's protection off and decrypts it: its payload and its
// packet number, read near the largest one before it. False when it does not
// decrypt.
func (k *initialKeys) open(p longPacket, largest uint64) ([]byte, uint64, bool) {
	if p.number+4+16 > len(p.raw) {
		return nil, 0, false
	}
	header := append([]byte{}, p.raw[:p.number+4]...)
	mask := make([]byte, 16)
	k.hp.Encrypt(mask, p.raw[p.number+4:p.number+4+16])
	header[0] ^= mask[0] & 0x0f
	size := int(header[0]&3) + 1
	var truncated uint64
	for i := range size {
		header[p.number+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(header[p.number+i])
	}
	header = header[:p.number+size]
	number := packetNumber(largest, truncated, size*8)
	nonce := append([]byte{}, k.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(number >> (8 * i))
	}
	payload, err := k.aead.Open(nil, nonce, p.raw[p.number+size:], header)
	return payload, number, err == nil
}

// packetNumber is a packet number of bits bits read near the one after
// largest (RFC 9000, appendix A.3).
func packetNumber(largest, truncated uint64, bits int) uint64 {
	expected := largest + 1
	window := uint64(1) << bits
	half := window / 2
	candidate := expected&^(window-1) | truncated
	switch {
	case candidate+half <= expected && candidate < 1<<62-window:
		return candidate + window
	case candidate > expected+half && candidate >= window:
		return candidate - window
	}
	return candidate
}

// cryptoFrames are the CRYPTO frames of an Initial packet's payload, their
// data by offset, as far as frames an Initial packet may hold are read:
// PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE.
func cryptoFrames(payload []byte) map[uint64][]byte {
	out := map[uint64][]byte{}
	for len(payload) > 0 {
		kind := payload[0]
		payload = payload[1:]
		switch kind {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, with ECN counts for 0x03
			// Largest acknowledged, delay, range count, first range; then
			// each range's gap and length; then three counts.
			fields := 4
			count := uint64(0)
			for i := 0; i < fields; i++ {
				v, n := varint(payload)
				if n == 0 {
					return out
				}
				payload = payload[n:]
				if i == 2 {
					count = v
					fields += int(min(count, 1<<10)) * 2
				}
			}
			if kind == 0x03 {
				for range 3 {
					_, n := varint(payload)
					if n == 0 {
						return out
					}
					payload = payload[n:]
				}
			}
		case 0x06: // CRYPTO
			offset, n := varint(payload)
			if n == 0 {
				return out
			}
			length, m := varint(payload[n:])
			if m == 0 || uint64(len(payload)-n-m) < length {
				return out
			}
			out[offset] = payload[n+m : n+m+int(length)]
			payload = payload[n+m+int(length):]
		default: // CONNECTION_CLOSE, or what an Initial packet cannot hold
			return out
		}
	}
	return out
}

// joined is the data from offset 0 the pieces cover without a gap.
func joined(pieces map[uint64][]byte) []byte {
	var out []byte
	for {
		next := -1
		for offset, data := range pieces {
			end := offset + uint64(len(data))
			if offset <= uint64(len(out)) && end > uint64(len(out)) {
				if next < 0 || end > uint64(next) {
					next = int(end)
				}
			}
		}
		if next < 0 {
			return out
		}
		for offset, data := range pieces {
			if offset <= uint64(len(out)) && offset+uint64(len(data)) == uint64(next) {
				out = append(out, data[uint64(len(out))-offset:]...)
				break
			}
		}
	}
}
