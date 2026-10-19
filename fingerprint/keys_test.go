package fingerprint

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// freshKey is a public key of a kind, made as a browser makes one.
func freshKey(kind string) []byte {
	curves := map[string]ecdh.Curve{"X25519": ecdh.X25519(), "P-256": ecdh.P256(), "P-384": ecdh.P384(),
		"P-521": ecdh.P521()}
	if curve, ok := curves[kind]; ok {
		private, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		return private.PublicKey().Bytes()
	}
	if kind == "ML-KEM-1024" {
		private, err := mlkem.GenerateKey1024()
		if err != nil {
			panic(err)
		}
		return private.EncapsulationKey().Bytes()
	}
	private, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	return private.EncapsulationKey().Bytes()
}

// shareOf is a key share of group of n bytes: fresh keys of the group's parts
// where n is the length of its key share, as a browser sends, else zeros.
func shareOf(group uint16, n int) []byte {
	parts, known := keyParts[group]
	if !known || partsSize(parts) != n {
		return make([]byte, n)
	}
	var key []byte
	for _, part := range parts {
		key = append(key, freshKey(part.kind)...)
	}
	return key
}

// keyShareOf is a key_share body of the keys given, by group.
func keyShareOf(entries ...sharedKey) []byte {
	var list []byte
	for _, entry := range entries {
		list = binary.BigEndian.AppendUint16(list, entry.group)
		list = binary.BigEndian.AppendUint16(list, uint16(len(entry.key)))
		list = append(list, entry.key...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// echWith is an outer encrypted_client_hello as Chrome writes its GREASE one,
// with the key given.
func echWith(enc []byte) []byte {
	out := []byte{0, 0, 1, 0, 1, 0x42}
	out = binary.BigEndian.AppendUint16(out, uint16(len(enc)))
	out = append(out, enc...)
	out = binary.BigEndian.AppendUint16(out, 144)
	return append(out, make([]byte, 144)...)
}

// cutShort is a key_share body of the entries given and a P-256 one that
// ends a byte into its key.
func cutShort(entries []byte) []byte {
	list := append(slices.Clone(entries), 0, 23, 0, 65, 4)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// littleEndian is n as 32 bytes, least significant first, as X25519 writes u.
func littleEndian(t *testing.T, n *big.Int) []byte {
	t.Helper()
	out := n.FillBytes(make([]byte, 32))
	slices.Reverse(out)
	return out
}

func decimal(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("not a number: %s", s)
	}
	return n
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reported is the ECH key the user reported, of a client that is not Chrome:
// testdata/ech-m-tf-enc.json.
const reported = "63e70ff6d234f8a456244d2878d3b7f98e71a4bd8022af25436db22fcc00fea5"

func TestAnX25519KeyIsAPointOfPrimeOrder(t *testing.T) {
	p := curve25519P
	masked := fromHex(t, reported)
	masked[31] &= 0x7f
	cases := []struct {
		name string
		key  []byte
		want string
	}{
		{"the base point", littleEndian(t, big.NewInt(9)), ""},
		// RFC 7748, section 6.1: Alice's public key.
		{"Alice's", fromHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), ""},
		{"the reported key", fromHex(t, reported), "its top bit set"},
		{"p, which is 0", littleEndian(t, p), "not below 2^255-19"},
		{"2^255-1", littleEndian(t, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))),
			"not below 2^255-19"},
		{"2, of the twist", littleEndian(t, big.NewInt(2)), "a point of the twist"},
		{"p-1, of the twist", littleEndian(t, new(big.Int).Sub(p, big.NewInt(1))), "a point of the twist"},
		{"0", make([]byte, 32), "the point of order 2"},
		{"1, of order 4", littleEndian(t, big.NewInt(1)), "outside the group of prime order"},
		{"one of order 8", littleEndian(t, decimal(t,
			"325606250916557431795983626356110631294008115727848805560023387167927233504")),
			"outside the group of prime order"},
		{"the other of order 8", littleEndian(t, decimal(t,
			"39382357235489614581723060781553021112529911719440698176882885853963445705823")),
			"outside the group of prime order"},
		// Of order 4l: a key of the group with one of order 4 added.
		{"the reported key without its top bit", masked, "outside the group of prime order"},
	}
	for range 16 {
		cases = append(cases, struct {
			name string
			key  []byte
			want string
		}{"one crypto/ecdh made", freshKey("X25519"), ""})
	}
	for _, tc := range cases {
		if got := x25519Problem(tc.key); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTheLadderGoesOverEveryBitOfItsScalar(t *testing.T) {
	order4 := big.NewInt(1)
	for _, tc := range []struct {
		name string
		u, k *big.Int
		want bool
	}{
		{"l times the base point", big.NewInt(9), curve25519L, true},
		{"8 times the base point", big.NewInt(9), big.NewInt(8), false},
		{"l+1 times the base point", big.NewInt(9), new(big.Int).Add(curve25519L, big.NewInt(1)), false},
		{"4 times one of order 4", order4, big.NewInt(4), true},
		{"2 times one of order 4", order4, big.NewInt(2), false},
		{"l times one of order 4", order4, curve25519L, false},
		// A bit past the 255 an X25519 scalar has: 8l is 2^255 and more.
		{"8l times one of order 4", order4, new(big.Int).Mul(curve25519L, big.NewInt(8)), true},
		{"0 times the base point", big.NewInt(9), big.NewInt(0), true},
		// Its bit 255 alone: a ladder that stopped short would take it as 0.
		{"2^255 times the base point", big.NewInt(9), new(big.Int).Lsh(big.NewInt(1), 255), false},
	} {
		if got := neutralAfter(tc.u, tc.k); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOtherKeysAreHeldToTheirKinds(t *testing.T) {
	for _, part := range []keyPart{p256Key, p384Key, p521Key, mlkem768Key, mlkem1024Key, kyber768Key} {
		key := freshKey(part.kind)
		if len(key) != part.size {
			t.Fatalf("%s: a key of %d bytes, the kind's are %d", part.kind, len(key), part.size)
		}
		if got := part.check(key); got != "" {
			t.Errorf("%s: a fresh key is %q", part.kind, got)
		}
		broken := slices.Clone(key)
		if strings.HasPrefix(part.kind, "P-") {
			// Off the curve: the last byte of y changed.
			broken[len(broken)-1] ^= 1
		} else {
			// Its first coefficient q, one past the largest.
			broken[0], broken[1] = 0x01, broken[1]&0xf0|0x0d
		}
		want := map[bool]string{true: "not a point of the curve", false: "fails FIPS 203's check"}[strings.HasPrefix(part.kind, "P-")]
		if got := part.check(broken); got != want {
			t.Errorf("%s: a broken key is %q, want %q", part.kind, got, want)
		}
	}
}

func TestKeysSaysWhatEachKeyIs(t *testing.T) {
	x := freshKey("X25519")
	hybrid := shareOf(0x11ec, 1216)
	unique := []string{"X25519MLKEM768: ML-KEM-768 key and X25519 key", "X25519: X25519 key",
		"encrypted_client_hello: X25519 key", "3 X25519 keys, each its own"}
	for _, tc := range []struct {
		name     string
		share    []byte
		ech      []byte
		withECH  bool
		want     []string
		wantNone bool
	}{
		{name: "Chrome's keys", share: keyShareOf(sharedKey{0x2a2a, []byte{0}}, sharedKey{0x11ec, hybrid},
			sharedKey{29, x}), ech: freshKey("X25519"), withECH: true, want: unique},
		{name: "the X25519 key of the hybrid sent again", share: keyShareOf(sharedKey{0x11ec, hybrid},
			sharedKey{29, hybrid[1184:]}), want: []string{"X25519MLKEM768: ML-KEM-768 key and X25519 key",
			"X25519: X25519 key", "2 X25519 keys, not each its own"}},
		{name: "ECH's key one of key_share's", share: keyShareOf(sharedKey{29, x}), ech: x, withECH: true,
			want: []string{"X25519: X25519 key", "encrypted_client_hello: X25519 key", "2 X25519 keys, not each its own"}},
		{name: "a bad key is not counted", share: keyShareOf(sharedKey{29, x}), ech: fromHex(t, reported),
			withECH: true, want: []string{"X25519: X25519 key", "encrypted_client_hello: no X25519 key: its top bit set"}},
		{name: "every group known", share: keyShareOf(sharedKey{23, shareOf(23, 65)}, sharedKey{24, shareOf(24, 97)},
			sharedKey{25, shareOf(25, 133)}, sharedKey{0x11eb, shareOf(0x11eb, 1249)},
			sharedKey{0x11ed, shareOf(0x11ed, 1665)}, sharedKey{0x6399, shareOf(0x6399, 1216)}),
			ech: freshKey("P-256"), withECH: true, want: []string{"P-256: P-256 key", "P-384: P-384 key",
				"P-521: P-521 key", "SecP256r1MLKEM768: P-256 key and ML-KEM-768 key",
				"SecP384r1MLKEM1024: P-384 key and ML-KEM-1024 key", "X25519Kyber768Draft00: X25519 key and Kyber768 key",
				"encrypted_client_hello: P-256 key", "3 P-256 keys, each its own", "2 P-384 keys, each its own"}},
		{name: "a group no rule reads", share: keyShareOf(sharedKey{30, make([]byte, 56)}), want: []string{"X448: not checked"}},
		{name: "a key share of another length", share: keyShareOf(sharedKey{29, x[:31]}, sharedKey{0x11ec, hybrid[:1215]}),
			want: []string{"X25519: 31 bytes, not 32", "X25519MLKEM768: 1215 bytes, not 1216"}},
		{name: "ECH's key of a length no KEM has", ech: make([]byte, 48), withECH: true,
			want: []string{"encrypted_client_hello: a key of 48 bytes, which no KEM has"}},
		{name: "no keys", wantNone: true},
		{name: "key_share cut short", share: keyShareOf(sharedKey{29, x})[:20], wantNone: true},
		{name: "key_share whose second entry is cut short", share: cutShort(keyShareOf(sharedKey{29, x})[2:]),
			want: []string{"X25519: X25519 key"}},
	} {
		b := newHello().withCiphers(0x1301)
		if tc.share != nil {
			b.withExtension(ExtKeyShare, tc.share)
		}
		if tc.withECH {
			b.withExtension(ExtEncryptedClientHello, echWith(tc.ech))
		}
		got := keys(mustParse(t, b.records()))
		if tc.wantNone && got != nil || !tc.wantNone && !slices.Equal(got, tc.want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
	// An encrypted_client_hello that is not an outer one says nothing of a key.
	inner := append([]byte{1}, echWith(freshKey("X25519"))[1:]...)
	if got := keys(mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtEncryptedClientHello, inner).records())); got != nil {
		t.Errorf("an inner one: %q", got)
	}
}

func TestChromesKeysAreKeys(t *testing.T) {
	// Chrome 155's own hellos, cold and resumed: every key a key of its kind,
	// the three X25519 keys each its own.
	want := []string{"X25519MLKEM768: ML-KEM-768 key and X25519 key", "X25519: X25519 key",
		"encrypted_client_hello: X25519 key", "3 X25519 keys, each its own"}
	for _, name := range []string{cold, resumed} {
		if got := keys(mustParse(t, fixture(t, name))); !slices.Equal(got, want) {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestTheComparisonFindsTheECHKeyTLSForgeSentBeforeItsFix(t *testing.T) {
	// tls-forge d5ed306, before 6f819a7, sent random bytes for its GREASE ECH
	// key: a hello of it, as the echo server took it, differs from Chrome's in
	// keys alone, where every other field matches.
	report := CompareTLS(mustParse(t, fixture(t, cold)), mustParse(t, fixture(t, "tlsforge-d5ed306-clienthello.bin")))
	if len(report.Differences) != 1 || report.Differences[0].Field != "keys" || len(report.Unchecked) != 0 ||
		!slices.Equal(report.Differences[0].Extra, []string{"encrypted_client_hello: no X25519 key: its top bit set",
			"2 X25519 keys, each its own"}) {
		t.Errorf("the hello of d5ed306:\n%s", report)
	}
}
