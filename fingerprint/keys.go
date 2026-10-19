package fingerprint

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// What a server can check of the keys a hello carries, and no fingerprint
// shows: that each is a public key of its kind, as the browser's always is,
// since the browser made it; and that two keys of one kind are not one key.
// Bytes of the right length in a key's place match every other field and fail
// this one. tls-forge's GREASE ECH key was such bytes before 6f819a7: about
// half of them have their top bit set, and few of the rest are in the group of
// prime order, which every key X25519 gives is in.

// keyPart is a key of one kind: its name, its length, and what keeps bytes of
// that length from being one, or nothing when they are one.
type keyPart struct {
	kind  string
	size  int
	check func([]byte) string
}

var (
	x25519Key    = keyPart{"X25519", 32, x25519Problem}
	p256Key      = keyPart{"P-256", 65, pointProblem(ecdh.P256())}
	p384Key      = keyPart{"P-384", 97, pointProblem(ecdh.P384())}
	p521Key      = keyPart{"P-521", 133, pointProblem(ecdh.P521())}
	mlkem768Key  = keyPart{"ML-KEM-768", mlkem.EncapsulationKeySize768, mlkem768Problem}
	mlkem1024Key = keyPart{"ML-KEM-1024", mlkem.EncapsulationKeySize1024, mlkem1024Problem}
	// kyber768Key is the draft hybrid's, written as an ML-KEM-768 key is.
	kyber768Key = keyPart{"Kyber768", mlkem.EncapsulationKeySize768, mlkem768Problem}
)

// keyParts is what the key share of each group known is made of, in order.
var keyParts = map[uint16][]keyPart{
	0x001d: {x25519Key},
	0x0017: {p256Key},
	0x0018: {p384Key},
	0x0019: {p521Key},
	0x11ec: {mlkem768Key, x25519Key}, // X25519MLKEM768
	0x11eb: {p256Key, mlkem768Key},   // SecP256r1MLKEM768
	0x11ed: {p384Key, mlkem1024Key},  // SecP384r1MLKEM1024
	0x6399: {x25519Key, kyber768Key}, // X25519Kyber768Draft00
}

// echKeys is the kind of an ECH key by its length. The extension does not
// name its KEM, which the server's config does, and a GREASE one has none.
var echKeys = map[int]keyPart{32: x25519Key, 65: p256Key, 97: p384Key, 133: p521Key}

// keys says of each key the hello carries, the key shares' and then ECH's,
// whether it is a public key of its kind, and of each kind with more than one
// key whether they are each their own. GREASE key shares carry none.
func keys(hello *ClientHello) []string {
	var out []string
	held := map[string][][]byte{}
	var kinds []string
	say := func(part keyPart, key []byte) string {
		if problem := part.check(key); problem != "" {
			return "no " + part.kind + " key: " + problem
		}
		if held[part.kind] == nil {
			kinds = append(kinds, part.kind)
		}
		held[part.kind] = append(held[part.kind], key)
		return part.kind + " key"
	}
	for _, share := range keyShareData(hello) {
		if IsGREASE(share.group) {
			continue
		}
		parts, known := keyParts[share.group]
		name := GroupName(share.group) + ": "
		switch {
		case !known:
			out = append(out, name+"not checked")
			continue
		case len(share.key) != partsSize(parts):
			out = append(out, name+fmt.Sprintf("%d bytes, not %d", len(share.key), partsSize(parts)))
			continue
		}
		var said []string
		key := share.key
		for _, part := range parts {
			said = append(said, say(part, key[:part.size]))
			key = key[part.size:]
		}
		out = append(out, name+strings.Join(said, " and "))
	}
	if enc, ok := echKey(hello); ok {
		name := ExtensionName(ExtEncryptedClientHello) + ": "
		if part, known := echKeys[len(enc)]; known {
			out = append(out, name+say(part, enc))
		} else {
			out = append(out, name+fmt.Sprintf("a key of %d bytes, which no KEM has", len(enc)))
		}
	}
	for _, kind := range kinds {
		if n := len(held[kind]); n > 1 {
			if eachItsOwn(held[kind]) {
				out = append(out, fmt.Sprintf("%d %s keys, each its own", n, kind))
			} else {
				out = append(out, fmt.Sprintf("%d %s keys, not each its own", n, kind))
			}
		}
	}
	return out
}

func partsSize(parts []keyPart) int {
	n := 0
	for _, part := range parts {
		n += part.size
	}
	return n
}

func eachItsOwn(keys [][]byte) bool {
	for i, key := range keys {
		if slices.ContainsFunc(keys[i+1:], func(other []byte) bool { return string(other) == string(key) }) {
			return false
		}
	}
	return true
}

// sharedKey is an entry of key_share with its key.
type sharedKey struct {
	group uint16
	key   []byte
}

// keyShareData is the entries of key_share with their keys, as far as they
// parse, as KeyShares reads them.
func keyShareData(hello *ClientHello) []sharedKey {
	data, _ := hello.Extension(ExtKeyShare)
	s := cryptobyte.String(data)
	var list cryptobyte.String
	s.ReadUint16LengthPrefixed(&list)
	var out []sharedKey
	for !list.Empty() {
		var share sharedKey
		var key cryptobyte.String
		if !list.ReadUint16(&share.group) || !list.ReadUint16LengthPrefixed(&key) {
			break
		}
		share.key = key
		out = append(out, share)
	}
	return out
}

// echKey is the key of an outer encrypted_client_hello, as
// EncryptedClientHello reads it.
func echKey(hello *ClientHello) ([]byte, bool) {
	if _, ok := hello.EncryptedClientHello(); !ok {
		return nil, false
	}
	data, _ := hello.Extension(ExtEncryptedClientHello)
	s := cryptobyte.String(data[1+2+2+1:])
	var enc cryptobyte.String
	s.ReadUint16LengthPrefixed(&enc)
	return enc, true
}

// pointProblem is what keeps bytes from being a point of curve, uncompressed,
// which every browser writes: crypto/ecdh refuses any other.
func pointProblem(curve ecdh.Curve) func([]byte) string {
	return func(key []byte) string {
		if _, err := curve.NewPublicKey(key); err != nil {
			return "not a point of the curve"
		}
		return ""
	}
}

// mlkem768Problem and mlkem1024Problem are FIPS 203's check of an
// encapsulation key: every coefficient below q.
func mlkem768Problem(key []byte) string {
	if _, err := mlkem.NewEncapsulationKey768(key); err != nil {
		return "fails FIPS 203's check"
	}
	return ""
}

func mlkem1024Problem(key []byte) string {
	if _, err := mlkem.NewEncapsulationKey1024(key); err != nil {
		return "fails FIPS 203's check"
	}
	return ""
}

var (
	// curve25519P is the field Curve25519 is over, and curve25519L the order
	// of its base point, and of every point X25519 gives.
	curve25519P    = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curve25519L, _ = new(big.Int).SetString(
		"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
)

// x25519Problem is what keeps 32 bytes from being what X25519 gives of a
// private key: the u-coordinate, below p and with its top bit clear, of a
// point of the curve rather than of its twist, in the group of prime order l,
// which is an eighth of the curve. crypto/ecdh takes any 32 bytes as a peer's
// key, as RFC 7748 says a receiver must, so it cannot tell.
func x25519Problem(key []byte) string {
	if key[31]&0x80 != 0 {
		return "its top bit set"
	}
	bigEndian := slices.Clone(key)
	slices.Reverse(bigEndian)
	u := new(big.Int).SetBytes(bigEndian)
	if u.Cmp(curve25519P) >= 0 {
		return "not below 2^255-19"
	}
	// v^2 = u^3 + 486662u^2 + u: a square for a point of the curve.
	v2 := new(big.Int).Add(u, big.NewInt(486662))
	v2.Mul(v2, u).Add(v2, big.NewInt(1)).Mul(v2, u).Mod(v2, curve25519P)
	switch big.Jacobi(v2, curve25519P) {
	case -1:
		return "a point of the twist"
	case 0:
		return "the point of order 2"
	}
	if !neutralAfter(u, curve25519L) {
		return "outside the group of prime order"
	}
	return ""
}

// neutralAfter says whether k times the point whose u-coordinate is u, which
// is not zero, is the neutral element: Montgomery's ladder as RFC 7748 writes
// it, on (X:Z), over every bit of k, which is not clamped.
func neutralAfter(u, k *big.Int) bool {
	p := curve25519P
	mod := func(n *big.Int) *big.Int { return n.Mod(n, p) }
	add := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
	sub := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	x2, z2, x3, z3 := big.NewInt(1), big.NewInt(0), new(big.Int).Set(u), big.NewInt(1)
	for i := k.BitLen() - 1; i >= 0; i-- {
		bit := k.Bit(i) == 1
		if bit {
			x2, x3, z2, z3 = x3, x2, z3, z2
		}
		a, b := add(x2, z2), sub(x2, z2)
		aa, bb := mul(a, a), mul(b, b)
		e := sub(aa, bb)
		da, cb := mul(sub(x3, z3), a), mul(add(x3, z3), b)
		x3, z3 = mul(add(da, cb), add(da, cb)), mul(u, mul(sub(da, cb), sub(da, cb)))
		x2, z2 = mul(aa, bb), mul(e, add(aa, mul(big.NewInt(121665), e)))
		if bit {
			x2, x3, z2, z3 = x3, x2, z3, z2
		}
	}
	return z2.Sign() == 0
}
