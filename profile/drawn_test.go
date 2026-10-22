package profile

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	tls "github.com/igor-lemon/utls"

	"github.com/Sec-CH-Lemon/tls-forge/v4/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v4/fingerprint"
)

// earlyData is early_data, which a browser offers resuming a session whose
// ticket allows it.
const earlyData uint16 = 42

// rawHelloOf is the record of the hello p would open a connection with, made
// without one, its extensions in an order drawn for it when shuffled.
func rawHelloOf(t *testing.T, p *Profile, shuffled bool) []byte {
	t.Helper()
	spec, err := p.Spec()
	if shuffled {
		spec, err = p.shuffledSpec()
	}
	if err != nil {
		t.Fatalf("spec: %v", err)
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
	return append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
}

// hellosOf are n of them.
func hellosOf(t *testing.T, p *Profile, shuffled bool, n int) [][]byte {
	t.Helper()
	out := make([][]byte, n)
	for i := range out {
		out[i] = rawHelloOf(t, p, shuffled)
	}
	return out
}

func TestWhatABrowserDrawsForEveryConnectionIsMeasured(t *testing.T) {
	chrome, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	// Chrome's: an order drawn for each, and BoringSSL's four lengths, said
	// all four however many of them a page's hellos show.
	d, err := DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, chrome, true), Connections: hellosOf(t, chrome, true, 26)})
	if err != nil || d == nil || d.Hellos != 27 || !d.Order || d.Sometimes != nil || len(d.ECH) < 2 ||
		slices.ContainsFunc(d.ECH, func(l int) bool { return !slices.Contains([]int{144, 176, 208, 240}, l) }) {
		t.Fatalf("Chrome's: %+v, %v", d, err)
	}
	if got := d.perConnection(); !reflect.DeepEqual(got, chromiumPerConnection()) {
		t.Errorf("Chrome's per connection: %+v", got)
	}
	// One that keeps its order and its length draws nothing, from the
	// fewest hellos it is measured from; with fewer, it is not measured.
	fixed := chrome.Clone()
	fixed.PerConnection = &PerConnection{}
	d, err = DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, fixed, false), Connections: hellosOf(t, fixed, false, minDrawn-1)})
	if err != nil || d == nil || d.Hellos != minDrawn || d.Order || len(d.ECH) != 1 || d.Sometimes != nil ||
		!reflect.DeepEqual(d.perConnection(), &PerConnection{}) {
		t.Fatalf("kept: %+v, %v", d, err)
	}
	if d, err := DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, fixed, false), Connections: hellosOf(t, fixed, false, minDrawn-2)}); d != nil || err != nil {
		t.Errorf("too few: %+v, %v", d, err)
	}
	// An extension one carries and the others do not is said, and its place
	// moves no order.
	connections := hellosOf(t, fixed, false, 20)
	connections[7] = withExtension(t, connections[7], earlyData, nil)
	d, err = DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, fixed, false), Connections: connections})
	if err != nil || d.Order || !slices.Equal(d.Sometimes, []uint16{earlyData}) {
		t.Errorf("sometimes: %+v, %v", d, err)
	}
	// Padding the length of a hello decides, and a ticket's pre_shared_key,
	// are none of what is drawn.
	connections = hellosOf(t, fixed, false, 20)
	connections[2] = withExtension(t, connections[2], fingerprint.ExtPadding, make([]byte, 9))
	connections[5] = withExtension(t, connections[5], fingerprint.ExtPreSharedKey, pskOf(1))
	d, err = DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, fixed, false), Connections: connections})
	if err != nil || d.Order || d.Sometimes != nil {
		t.Errorf("padding and a ticket: %+v, %v", d, err)
	}
	// A hello that does not parse is said by its place.
	connections[3] = []byte{1, 2, 3}
	if _, err := DrawnOf(&capture.Capture{RawClientHello: rawHelloOf(t, fixed, false), Connections: connections}); err == nil ||
		!strings.Contains(err.Error(), "the hello of connection 4") {
		t.Errorf("a broken one: %v", err)
	}
}

func TestTheLengthsDrawnAreSaidBeforeTheTag(t *testing.T) {
	for _, tc := range []struct {
		seen []int
		want []uint16
	}{
		{[]int{144, 176}, []uint16{128, 160, 192, 224}},
		{[]int{144, 300}, []uint16{128, 284}},
		{[]int{100, 300}, []uint16{84, 284}},
		{[]int{16, 144}, nil},
		{[]int{208}, nil},
		{nil, nil},
	} {
		if got := (&Drawn{ECH: tc.seen}).perConnection().ECHPayloadLengths; !slices.Equal(got, tc.want) {
			t.Errorf("%v: %v, want %v", tc.seen, got, tc.want)
		}
	}
}

func TestAProfileOfAMeasuredCaptureDrawsWhatWasMeasured(t *testing.T) {
	// Measured, whatever its name says: an order drawn, under Firefox's user
	// agent, and a hello that does not parse refuses the profile.
	chrome, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	measured := &capture.Capture{
		RawClientHello: rawHelloOf(t, chrome, true), Connections: hellosOf(t, chrome, true, 20),
		Navigator: &capture.Navigator{UserAgent: "Mozilla/5.0 (Macintosh) Gecko/20100101 Firefox/148.0"},
		HTTP2: &capture.HTTP2{PseudoHeaderOrder: []string{"m", "p", "a", "s"},
			Headers: []capture.HeaderField{{Name: ":method", Value: "GET"}}},
	}
	built, err := FromCapture("firefox_148", measured)
	if err != nil || !built.PerConnection.ShufflesExtensions || len(built.PerConnection.ECHPayloadLengths) != 4 {
		t.Fatalf("%+v, %v", built.PerConnection, err)
	}
	measured.Connections[0] = []byte{1}
	if _, err := FromCapture("firefox_148", measured); err == nil || !strings.Contains(err.Error(), "connection 1") {
		t.Errorf("a broken hello: %v", err)
	}
}

// pskOf is a pre_shared_key of n identities, each with a binder of 32 bytes.
func pskOf(n int) []byte {
	var identities, binders []byte
	for range n {
		identities = append(identities, 0, 4, 1, 2, 3, 4, 0, 0, 0, 9)
		binders = append(append(binders, 32), make([]byte, 32)...)
	}
	out := append([]byte{byte(len(identities) >> 8), byte(len(identities))}, identities...)
	return append(append(out, byte(len(binders)>>8), byte(len(binders))), binders...)
}

func TestAResumedHelloIsHeldToTheColdOne(t *testing.T) {
	cold, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := os.ReadFile("../testdata/chrome155-clienthello-resumed.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		cold, resumed []byte
		want          Resumption
	}{
		{"Chrome 155's, as tls-forge resumes", cold, resumed, Resumption{Measured: true, Identities: 1}},
		{"none", cold, nil, Resumption{}},
		{"early_data added", cold, withExtension(t, withExtension(t, cold, earlyData, nil), fingerprint.ExtPreSharedKey, pskOf(1)),
			Resumption{Measured: true, Added: []uint16{earlyData}, Identities: 1}},
		{"one missing", withExtension(t, cold, earlyData, nil), resumed,
			Resumption{Measured: true, Missing: []uint16{earlyData}, Identities: 1}},
		{"pre_shared_key not last", cold, withExtension(t, resumed, earlyData, nil),
			Resumption{Measured: true, Added: []uint16{earlyData}, NotLast: true, Identities: 1}},
		{"two tickets", cold, withExtension(t, cold, fingerprint.ExtPreSharedKey, pskOf(2)),
			Resumption{Measured: true, Identities: 2}},
		{"one that does not parse", cold, withExtension(t, cold, fingerprint.ExtPreSharedKey, []byte{0xff}),
			Resumption{Measured: true}},
	} {
		got, err := ResumptionOf(&capture.Capture{RawClientHello: tc.cold, ResumedClientHello: tc.resumed})
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, %v", tc.name, got, err)
		}
		if got.AsTLSForge() != (tc.name == "Chrome 155's, as tls-forge resumes") {
			t.Errorf("%s: as tls-forge resumes: %v", tc.name, got.AsTLSForge())
		}
	}
	if (Resumption{Measured: true, Identities: 1, NotLast: true}).AsTLSForge() {
		t.Error("pre_shared_key not last is as tls-forge resumes")
	}
	if _, err := ResumptionOf(&capture.Capture{RawClientHello: []byte{1}, ResumedClientHello: resumed}); err == nil {
		t.Error("a cold hello that does not parse")
	}
	if _, err := ResumptionOf(&capture.Capture{RawClientHello: cold, ResumedClientHello: []byte{1}}); err == nil ||
		!strings.Contains(err.Error(), "the resumed hello") {
		t.Errorf("a resumed hello that does not parse: %v", err)
	}
}
