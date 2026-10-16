package fingerprint

import (
	"encoding/binary"
	"os"
	"testing"
)

// echBody is the body of an outer hello's encrypted_client_hello extension as
// Chrome writes its GREASE one: HKDF-SHA256 with AES-128-GCM, a config id, a
// 32-byte encapsulated key and a payload of the length given.
func echBody(kdf, aead uint16, payload int) []byte {
	out := []byte{0}
	out = binary.BigEndian.AppendUint16(out, kdf)
	out = binary.BigEndian.AppendUint16(out, aead)
	out = append(out, 0x42)
	out = binary.BigEndian.AppendUint16(out, 32)
	out = append(out, make([]byte, 32)...)
	out = binary.BigEndian.AppendUint16(out, uint16(payload))
	return append(out, make([]byte, payload)...)
}

func TestEncryptedClientHelloOfChrome155(t *testing.T) {
	raw, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ech, ok := mustParse(t, raw).EncryptedClientHello()
	if !ok {
		t.Fatal("Chrome's hello has a GREASE ECH extension")
	}
	if ech.KDF != 1 || ech.AEAD != 1 || ech.EncLength != 32 || ech.PayloadLength != 176 {
		t.Errorf("ECH = %+v", ech)
	}
}

func TestEncryptedClientHelloThatIsNotOne(t *testing.T) {
	whole := echBody(1, 1, 144)
	ech, ok := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtEncryptedClientHello, whole).records()).
		EncryptedClientHello()
	if !ok || ech != (ECH{KDF: 1, AEAD: 1, ConfigID: 0x42, EncLength: 32, PayloadLength: 144}) {
		t.Fatalf("a whole one parsed as %+v, %v", ech, ok)
	}
	for name, body := range map[string][]byte{
		"an inner hello's":    append([]byte{1}, whole[1:]...),
		"cut short":           whole[:len(whole)-1],
		"with bytes to spare": append(append([]byte(nil), whole...), 0),
		"empty":               {},
		"without its payload": whole[:len(whole)-144-2],
		"without its key":     whole[:6],
		"without its config":  whole[:5],
		"without its AEAD":    whole[:3],
		"without its KDF":     whole[:1],
	} {
		hello := mustParse(t, newHello().withCiphers(0x1301).withExtension(ExtEncryptedClientHello, body).records())
		if ech, ok := hello.EncryptedClientHello(); ok {
			t.Errorf("%s parsed as %+v", name, ech)
		}
	}
	if _, ok := mustParse(t, newHello().withCiphers(0x1301).records()).EncryptedClientHello(); ok {
		t.Error("a hello without the extension has one")
	}
}
