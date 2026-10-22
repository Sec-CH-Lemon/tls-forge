package tlsforge

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/fingerprint"
	"golang.org/x/crypto/cryptobyte"
)

// These diagnostics apply only to our generated public keys, never to peer
// inputs. RFC 7748 requires masking and accepting non-canonical peer inputs.
var curve25519Prime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
var curve25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func littleInteger(b []byte) *big.Int {
	b = slices.Clone(b)
	slices.Reverse(b)
	return new(big.Int).SetBytes(b)
}

// multiplyU is an unclamped Montgomery ladder. Unlike X25519, it preserves
// the supplied scalar, including bit 255 of 8*l. nil denotes infinity; a
// finite u=0 is a distinct result. All arithmetic is test-only and variable time.
func multiplyU(u, scalar *big.Int) *big.Int {
	mod := func(n *big.Int) *big.Int { return n.Mod(n, curve25519Prime) }
	add := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
	sub := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	x2, z2 := big.NewInt(1), big.NewInt(0)
	x3, z3 := new(big.Int).Set(u), big.NewInt(1)
	swap := uint(0)
	for bit := scalar.BitLen() - 1; bit >= 0; bit-- {
		k := scalar.Bit(bit)
		if swap != k {
			x2, x3, z2, z3 = x3, x2, z3, z2
		}
		swap = k
		a, b := add(x2, z2), sub(x2, z2)
		aa, bb := mul(a, a), mul(b, b)
		e := sub(aa, bb)
		c, d := add(x3, z3), sub(x3, z3)
		da, cb := mul(d, a), mul(c, b)
		x3 = mul(add(da, cb), add(da, cb))
		z3 = mul(u, mul(sub(da, cb), sub(da, cb)))
		x2 = mul(aa, bb)
		z2 = mul(e, add(aa, mul(big.NewInt(121665), e)))
	}
	if swap != 0 {
		x2, z2 = x3, z3
	}
	if z2.Sign() == 0 {
		return nil
	}
	return mul(x2, new(big.Int).ModInverse(z2, curve25519Prime))
}

func x25519OutputProblem(key []byte) string {
	if len(key) != 32 {
		return "length is not 32"
	}
	if key[31]&0x80 != 0 {
		return "bit 255 is set"
	}
	u := littleInteger(key)
	if u.Cmp(curve25519Prime) >= 0 {
		return "non-canonical field encoding"
	}
	// v^2 = u^3 + 486662*u^2 + u; reject the twist and finite torsion.
	rhs := new(big.Int).Mul(u, u)
	rhs.Mul(rhs, new(big.Int).Add(u, big.NewInt(486662)))
	rhs.Add(rhs, u).Mod(rhs, curve25519Prime)
	if rhs.Sign() == 0 || new(big.Int).ModSqrt(rhs, curve25519Prime) == nil {
		return "not a non-torsion point on the main curve"
	}
	if multiplyU(u, curve25519Order) != nil {
		return "not in the subgroup of order l"
	}
	return ""
}

func TestX25519OutputDiagnostics(t *testing.T) {
	// Keep the reported bytes intact as a negative control, independently of
	// whether the full original M_TF.json is available on this machine.
	raw, err := os.ReadFile("testdata/ech-m-tf-enc.json")
	if err != nil {
		t.Fatal(err)
	}
	var sample struct{ Enc string }
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(sample.Enc)
	if err != nil {
		t.Fatal(err)
	}
	if got := x25519OutputProblem(key); got != "bit 255 is set" {
		t.Fatalf("original enc: %s", got)
	}
	masked := slices.Clone(key)
	masked[31] &= 0x7f
	if got := x25519OutputProblem(masked); got != "not in the subgroup of order l" {
		t.Fatalf("masked enc: %s", got)
	}
	u := littleInteger(masked)
	for _, check := range []struct {
		factor int64
		want   *big.Int
	}{{1, big.NewInt(1)}, {2, big.NewInt(0)}, {4, nil}, {8, nil}} {
		scalar := new(big.Int).Mul(curve25519Order, big.NewInt(check.factor))
		got := multiplyU(u, scalar)
		if (got == nil) != (check.want == nil) || (got != nil && got.Cmp(check.want) != 0) {
			t.Errorf("[%dl]P = %v, want %v (nil is infinity)", check.factor, got, check.want)
		}
	}
	if multiplyU(u, big.NewInt(4)) == nil {
		t.Error("the mixed-order point was mistaken for a small-order point")
	}
	// Dropping bit 255 would change the diagnostic's result.
	truncated := new(big.Int).Mul(curve25519Order, big.NewInt(8))
	truncated.SetBit(truncated, 255, 0)
	if multiplyU(u, truncated) == nil {
		t.Error("the 256-bit scalar control did not distinguish a truncated ladder")
	}
	for range 8 {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if problem := x25519OutputProblem(private.PublicKey().Bytes()); problem != "" {
			t.Fatal(problem)
		}
	}
	// RFC 7748 section 6.1 Alice's public key, independent of our generator.
	alice, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	if problem := x25519OutputProblem(alice); problem != "" {
		t.Fatal(problem)
	}
}

func TestOutgoingECHUsesX25519Keys(t *testing.T) {
	server := startEchoWithTickets(t)
	for _, resume := range []bool{false, true} {
		t.Run(fmt.Sprintf("resumption=%v", resume), func(t *testing.T) {
			opts := []Option{WithProfile("chrome_155_macos")}
			if !resume {
				opts = append(opts, WithoutSessionResumption())
			}
			client := newTestClient(t, opts...)
			keys, payloads := map[string]bool{}, map[string]bool{}
			for connection := range 16 {
				measured, _ := measuredOn(t, client, server)
				client.CloseIdleConnections()
				hello, err := measured.Hello() // server-captured wire bytes, after JSON round trip
				if err != nil {
					t.Fatal(err)
				}
				if measured.TLS.Resumed != (resume && connection > 0) {
					t.Fatalf("connection %d: resumed %v", connection, measured.TLS.Resumed)
				}
				data, ok := hello.Extension(fingerprint.ExtEncryptedClientHello)
				if !ok {
					t.Fatal("no ECH extension (65037)")
				}
				s := cryptobyte.String(data)
				var outer, config uint8
				var kdf, aead uint16
				var enc, payload cryptobyte.String
				if !s.ReadUint8(&outer) || outer != 0 || !s.ReadUint16(&kdf) || !s.ReadUint16(&aead) ||
					!s.ReadUint8(&config) || !s.ReadUint16LengthPrefixed(&enc) ||
					!s.ReadUint16LengthPrefixed(&payload) || !s.Empty() || kdf != 1 || aead != 1 ||
					!slices.Contains([]int{144, 176, 208, 240}, len(payload)) {
					t.Fatalf("malformed or unexpected ECH: %x", data)
				}
				if problem := x25519OutputProblem(enc); problem != "" {
					t.Fatalf("connection %d ECH enc %x: %s", connection, enc, problem)
				}
				if keys[string(enc)] || payloads[string(payload)] {
					t.Fatal("ECH key or payload reused across connections")
				}
				keys[string(enc)], payloads[string(payload)] = true, true
				checkOutgoingKeyShares(t, hello)
				if connection == 0 {
					t.Logf("wire ECH enc=%x payload=%d: canonical, main curve, [l]P=infinity; both key_share X25519 components pass", enc, len(payload))
				}
			}
		})
	}
}

func checkOutgoingKeyShares(t *testing.T, hello *fingerprint.ClientHello) {
	t.Helper()
	data, _ := hello.Extension(fingerprint.ExtKeyShare)
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		t.Fatal("bad key_share vector")
	}
	checked := 0
	for !list.Empty() {
		var group uint16
		var key cryptobyte.String
		if !list.ReadUint16(&group) || !list.ReadUint16LengthPrefixed(&key) {
			t.Fatal("bad key_share entry")
		}
		switch group {
		case 0x11ec: // X25519MLKEM768: 1184-byte ML-KEM key, then X25519.
			if len(key) != 1216 {
				t.Fatalf("hybrid key length %d", len(key))
			}
			key = key[1184:]
		case 29:
		default:
			continue
		}
		if problem := x25519OutputProblem(key); problem != "" {
			t.Fatalf("key_share group %x: %s", group, problem)
		}
		checked++
	}
	if checked != 2 {
		t.Fatalf("checked %d X25519 key_share components, want 2", checked)
	}
}

func TestRequestKindSelectsNavigationOrScriptHeaders(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t, WithProfile("chrome_155_macos"))
	for _, kind := range []RequestKind{"", KindNavigation, KindFetch, KindXHR} {
		t.Run(string(kind), func(t *testing.T) {
			req := &Request{URL: server.URL() + "/api/all"}
			if kind != "" {
				req.Browser = &BrowserContext{Kind: kind}
				if kind == KindFetch || kind == KindXHR {
					req.Browser.Initiator = server.URL() + "/page"
				}
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				HTTP2 struct {
					Headers []struct{ Name, Value string }
				}
			}
			if err := json.Unmarshal(res.Body, &got); err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{}
			for _, h := range got.HTTP2.Headers {
				headers[strings.ToLower(h.Name)] = h.Value
			}
			want := map[string]string{"sec-fetch-site": "none", "sec-fetch-mode": "navigate",
				"sec-fetch-user": "?1", "sec-fetch-dest": "document", "priority": "u=0, i", "referer": ""}
			if kind == KindFetch || kind == KindXHR {
				want = map[string]string{"sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
					"sec-fetch-user": "", "sec-fetch-dest": "empty", "priority": "u=1, i", "referer": server.URL() + "/page"}
			}
			for name, value := range want {
				if headers[name] != value {
					t.Errorf("%s = %q, want %q", name, headers[name], value)
				}
			}
			client.CloseIdleConnections()
		})
	}
}
