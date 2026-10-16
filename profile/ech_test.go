package profile

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	tls "github.com/bogdanfinn/utls"
)

// greaseECH is the GREASE encrypted_client_hello extension of a spec.
func greaseECH(t *testing.T, spec tls.ClientHelloSpec) *tls.GREASEEncryptedClientHelloExtension {
	t.Helper()
	for _, extension := range spec.Extensions {
		if ech, ok := extension.(*tls.GREASEEncryptedClientHelloExtension); ok {
			return ech
		}
	}
	t.Fatal("the spec has no GREASE ECH extension")
	return nil
}

// helloFrom is the ClientHello a profile would open a connection with, made
// without one: what goes on the wire, in a record, as a server reads it. The
// spec ends with the pre_shared_key slot, which utls leaves out of a hello
// with no session to resume only when told to.
func helloFrom(t *testing.T, p *Profile) *fingerprint.ClientHello {
	t.Helper()
	spec, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	config := &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, OmitEmptyPsk: true}
	conn := tls.UClient(nil, config, tls.HelloCustom, false, false, false)
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	message := conn.HandshakeState.Hello.Raw
	record := append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
	hello, err := fingerprint.ParseClientHello(record)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return hello
}

// capturedECH is the GREASE ECH of a captured hello.
func capturedECH(t *testing.T, raw []byte) fingerprint.ECH {
	t.Helper()
	hello, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	ech, ok := hello.EncryptedClientHello()
	if !ok {
		t.Fatal("the capture has no GREASE ECH")
	}
	return ech
}

// measuredECH is testdata/chrome155-ech.json: the GREASE ECH Chrome 155 sent,
// over every connection of every series.
type measuredECH struct {
	Series []struct {
		Connections    int            `json:"connections"`
		PayloadLengths map[string]int `json:"payload_lengths"`
	} `json:"series"`
	Connections    int            `json:"connections"`
	PayloadLengths map[string]int `json:"payload_lengths"`
	KDF            uint16         `json:"kdf"`
	AEAD           uint16         `json:"aead"`
	EncLength      int            `json:"enc_length"`
}

func chromeECH(t *testing.T) measuredECH {
	t.Helper()
	raw, err := os.ReadFile("../testdata/chrome155-ech.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var measured measuredECH
	if err := json.Unmarshal(raw, &measured); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return measured
}

// lengths are the payload lengths of a measurement, as numbers, with how
// often each was seen.
func lengths(t *testing.T, counts map[string]int) map[int]int {
	t.Helper()
	out := map[int]int{}
	for length, count := range counts {
		n, err := strconv.Atoi(length)
		if err != nil {
			t.Fatalf("fixture: a length %q", length)
		}
		out[n] = count
	}
	return out
}

// onTheWire are the payload lengths the spec draws from as they are sent:
// each with the 16-byte tag every AEAD of ECH adds.
func onTheWire() []int {
	var out []int
	for _, length := range chromeECHPayloadLengths {
		out = append(out, int(length)+16)
	}
	return out
}

// chiSquare is how far counts are from all being equal: Pearson's statistic
// over the given lengths, each expected total/len(lengths) times.
func chiSquare(counts map[int]int, of []int) float64 {
	total := 0
	for _, length := range of {
		total += counts[length]
	}
	expected := float64(total) / float64(len(of))
	sum := 0.0
	for _, length := range of {
		d := float64(counts[length]) - expected
		sum += d * d / expected
	}
	return sum
}

func TestChromeDrawsTheECHLengthFromFourAsOftenAsEachOther(t *testing.T) {
	measured := chromeECH(t)
	total := lengths(t, measured.PayloadLengths)
	// The four lengths the spec draws from are the ones Chrome was seen
	// sending, and none other.
	if got := slices.Sorted(maps.Keys(total)); !reflect.DeepEqual(got, onTheWire()) {
		t.Errorf("Chrome was measured sending %v, the spec draws from %v", got, onTheWire())
	}
	// The totals are the series added up.
	sum, connections := map[int]int{}, 0
	for _, series := range measured.Series {
		seen := 0
		for length, count := range lengths(t, series.PayloadLengths) {
			sum[length] += count
			seen += count
		}
		if seen != series.Connections {
			t.Errorf("a series of %d connections counted %d", series.Connections, seen)
		}
		connections += series.Connections
	}
	if !reflect.DeepEqual(sum, total) || connections != measured.Connections {
		t.Errorf("the series add up to %v over %d, the fixture says %v over %d",
			sum, connections, total, measured.Connections)
	}
	// Each as likely as the others: with three degrees of freedom, a chi-square
	// over 16.27 would come by chance once in a thousand.
	if chi := chiSquare(total, onTheWire()); chi > 16.27 {
		t.Errorf("Chrome's lengths %v are not drawn alike: chi-square %.2f", total, chi)
	}
}

// shipped are the profiles that ship, each as loaded.
func shipped(t *testing.T) []*Profile {
	t.Helper()
	paths, err := fs.Glob(embedded, "data/*/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("shipped profiles: %v, %v", paths, err)
	}
	var out []*Profile
	for _, path := range paths {
		data, err := embedded.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		p, err := Load(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, p)
	}
	return out
}

func TestEveryShippedProfileDrawsTheECHLengthAsChromeDoes(t *testing.T) {
	for _, p := range shipped(t) {
		// What was captured is one draw of the four: HKDF-SHA256 always,
		// AES-128-GCM where the machine has AES in hardware and else
		// ChaCha20-Poly1305, as BoringSSL picks, and an X25519 key.
		captured := capturedECH(t, p.ClientHello)
		if !slices.Contains(onTheWire(), captured.PayloadLength) || captured.KDF != 1 ||
			(captured.AEAD != 1 && captured.AEAD != 3) || captured.EncLength != 32 {
			t.Errorf("%s was captured with ECH %+v", p.Name, captured)
		}
		spec, err := p.Spec()
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if got := greaseECH(t, spec).CandidatePayloadLens; !reflect.DeepEqual(got, chromeECHPayloadLengths) {
			t.Errorf("%s draws from %v, want %v", p.Name, got, chromeECHPayloadLengths)
		}
	}
}

func TestHelloAfterHelloDrawsItsOwnECH(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	measured := chromeECH(t)
	captured := capturedECH(t, p.ClientHello)

	// 256 hellos of one profile, as 256 connections would send them.
	const hellos = 256
	counts := map[int]int{}
	configs := map[uint8]bool{}
	keys, payloads := map[string]bool{}, map[string]bool{}
	for range hellos {
		hello := helloFrom(t, p)
		ech, ok := hello.EncryptedClientHello()
		if !ok {
			t.Fatal("a hello went out without GREASE ECH")
		}
		// The cipher suite is the capture's and the measurement's; the key is
		// X25519's 32 bytes; the length is one of the four.
		if ech.KDF != captured.KDF || ech.AEAD != captured.AEAD || ech.KDF != measured.KDF ||
			ech.AEAD != measured.AEAD || ech.EncLength != measured.EncLength ||
			!slices.Contains(onTheWire(), ech.PayloadLength) {
			t.Fatalf("a hello went out with ECH %+v, which Chrome does not send", ech)
		}
		counts[ech.PayloadLength]++
		configs[ech.ConfigID] = true
		// type, KDF, AEAD, config id and the key's length come first: 8 bytes.
		data, _ := hello.Extension(fingerprint.ExtEncryptedClientHello)
		keys[string(data[8:8+ech.EncLength])] = true
		payloads[string(data[len(data)-ech.PayloadLength:])] = true
	}
	// Each length as likely as the others. With three degrees of freedom a
	// chi-square over 45 comes by chance about once in a billion runs; a draw
	// that left one length out would score over 80 here, a constant one 768.
	if chi := chiSquare(counts, onTheWire()); chi > 45 {
		t.Errorf("%d hellos drew the lengths %v: chi-square %.1f", hellos, counts, chi)
	}
	// Nothing random is kept from one hello to the next: every key and every
	// payload is new, and the config id is a fresh byte. 256 draws of a byte
	// give about 162 values; under 64 does not happen by chance.
	if len(keys) != hellos || len(payloads) != hellos || len(configs) < 64 {
		t.Errorf("%d hellos had %d keys, %d payloads and %d config ids", hellos, len(keys), len(payloads), len(configs))
	}
}

func TestAnotherBrowserKeepsTheECHLengthItWasCapturedWith(t *testing.T) {
	// Only Chromium was measured. A hello captured from another browser, or
	// from anything on an iPhone, keeps the one length it was captured with
	// until that browser is.
	raw, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, p := range []*Profile{
		{Name: "firefox_148", ClientHello: raw},
		{Name: "chrome_155_ios", ClientHello: raw},
		{Name: "custom", ClientHello: raw, UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/155.0.0.0"},
	} {
		spec, err := p.Spec()
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		want := []uint16{uint16(capturedECH(t, raw).PayloadLength - 16)}
		if got := greaseECH(t, spec).CandidatePayloadLens; !reflect.DeepEqual(got, want) {
			t.Errorf("%s draws from %v, want the captured %v alone", p.Name, got, want)
		}
	}
}

func TestASpecsECHLengthsAreItsOwn(t *testing.T) {
	// A caller may change the spec it was given; the next one is untouched.
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	first, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	lens := greaseECH(t, first).CandidatePayloadLens
	for i := range lens {
		lens[i] = 1
	}
	second, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if got := greaseECH(t, second).CandidatePayloadLens; !reflect.DeepEqual(got, []uint16{128, 160, 192, 224}) {
		t.Errorf("the next spec draws from %v", got)
	}
}
