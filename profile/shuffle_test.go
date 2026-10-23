package profile

import (
	rand "math/rand/v2"
	"reflect"
	"slices"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v6/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/v6/internal/harness"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
)

// orderOf is the extensions' code points of the ClientHello id opens a
// connection with, made without one; the transport draws their order itself
// when shuffle says, as it does when told WithRandomTLSExtensionOrder.
func orderOf(t *testing.T, id tls.ClientHelloID, shuffle bool) []uint16 {
	t.Helper()
	config := &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, OmitEmptyPsk: true}
	conn := tls.UClient(nil, config, id, shuffle, false, false)
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	message := conn.HandshakeState.Hello.Raw
	hello, err := fingerprint.ParseClientHello(append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	codes := make([]uint16, len(hello.Extensions))
	for i, extension := range hello.Extensions {
		codes[i] = extension.Type
	}
	return codes
}

// withoutGREASE is order with every GREASE code point said as one, which
// each hello draws afresh.
func withoutGREASE(order []uint16) []uint16 {
	out := slices.Clone(order)
	for i, code := range out {
		if code&0x0f0f == 0x0a0a {
			out[i] = 0x0a0a
		}
	}
	return out
}

// idOf is the ClientHelloID of p's transport, its order drawn when shuffle
// says.
func idOf(t *testing.T, p *Profile, shuffle bool) tls.ClientHelloID {
	t.Helper()
	built, err := p.ClientProfileShuffled(shuffle)
	if err != nil {
		t.Fatalf("ClientProfileShuffled: %v", err)
	}
	return built.GetClientHelloId()
}

// orders are n hellos of id.
func orders(t *testing.T, id tls.ClientHelloID, shuffle bool, n int) [][]uint16 {
	t.Helper()
	out := make([][]uint16, n)
	for i := range out {
		out[i] = orderOf(t, id, shuffle)
	}
	return out
}

func TestTheExtensionsAreInAnyOrderAsLikelyAsChromeDrawsThem(t *testing.T) {
	// Drawn as the client draws them, 10,000 hellos are held to the rule
	// Chrome's were: every order of those that move as likely as any other,
	// against the capture's, GREASE first and last.
	old := extensionShuffle
	extensionShuffle = rand.New(rand.NewPCG(1, 2)).Shuffle
	t.Cleanup(func() { extensionShuffle = old })
	p := mustGet(t, "chrome_155_macos")
	reference := orderOf(t, idOf(t, p, false), false)
	stats, err := harness.OrderStatsOf(orders(t, idOf(t, p, true), false, 10000), reference)
	if err != nil || stats.Movable != 17 || len(stats.Problems()) > 0 {
		t.Errorf("drawn %+v: %v %q", stats, err, stats.Problems())
	}
}

func TestChromeDrewEveryOrderAsLikelyAsAnyOther(t *testing.T) {
	// The rule decided before measuring, on each launch of
	// testdata/chrome155-hellos.json, against the capture's order.
	fixture, err := harness.LoadHellos("../testdata/chrome155-hellos.json")
	if err != nil {
		t.Fatalf("LoadHellos: %v", err)
	}
	if len(fixture.Launches) != 2 {
		t.Fatalf("%d launches", len(fixture.Launches))
	}
	reference := orderOf(t, idOf(t, mustGet(t, "chrome_155_macos"), false), false)
	for i, launch := range fixture.Launches {
		var drawn [][]uint16
		for _, order := range launch {
			codes, err := harness.ParseOrder(order)
			if err != nil {
				t.Fatalf("launch %d: %v", i+1, err)
			}
			drawn = append(drawn, codes)
		}
		stats, err := harness.OrderStatsOf(drawn, reference)
		if err != nil || stats.Hellos != 200 || len(stats.Problems()) > 0 {
			t.Errorf("launch %d: %+v, %v %q", i+1, stats, err, stats.Problems())
		}
	}
}

func TestTheTransportsOwnShuffleIsNotChromes(t *testing.T) {
	// It passes over a swap with GREASE, which keeps an extension in the
	// capture's place about twice as often: 2,000 hellos drawn its way fail
	// the rule Chrome's passed. Were they ever to pass, the transport's own
	// shuffle could be Chrome's again.
	id := idOf(t, mustGet(t, "chrome_155_macos"), false)
	stats, err := harness.OrderStatsOf(orders(t, id, true, 2000), orderOf(t, id, false))
	if err != nil || stats.FixedPoints < 1.5 || len(stats.Problems()) == 0 {
		t.Errorf("the transport drew %+v: %v", stats, err)
	}
}

func TestTheClientDrawsWithTheStandardLibrarysShuffle(t *testing.T) {
	// math/rand/v2's, every order as likely as any other, until a test says
	// otherwise.
	if reflect.ValueOf(extensionShuffle).Pointer() != reflect.ValueOf(rand.Shuffle).Pointer() {
		t.Error("the extensions are drawn otherwise")
	}
}

func TestOnlyTheExtensionsThatMoveAreDrawn(t *testing.T) {
	first, last := &tls.UtlsGREASEExtension{}, &tls.UtlsGREASEExtension{}
	padding, psk := &tls.UtlsPaddingExtension{}, &tls.UtlsPreSharedKeyExtension{}
	a, b, c := &tls.SNIExtension{}, &tls.SupportedPointsExtension{}, &tls.SessionTicketExtension{}
	extensions := []tls.TLSExtension{first, a, padding, b, c, last, psk}
	asked := -1
	shuffleExtensions(extensions, func(n int, swap func(i, j int)) {
		asked = n
		swap(0, 2)
	})
	if want := []tls.TLSExtension{first, c, padding, b, a, last, psk}; asked != 3 || !slices.Equal(extensions, want) {
		t.Errorf("asked to draw %d, drew %v", asked, extensions)
	}
	// Nothing that moves: nothing to draw.
	shuffleExtensions([]tls.TLSExtension{first, psk}, func(n int, _ func(i, j int)) { asked = n })
	if asked != 0 {
		t.Errorf("asked to draw %d", asked)
	}
}

func TestAProfileDrawsItsOrderWhenAskedAndOnlyThen(t *testing.T) {
	p := mustGet(t, "chrome_155_macos")
	reference := orderOf(t, idOf(t, p, false), false)
	distinct := func(drawn [][]uint16) int {
		var seen [][]uint16
		for _, order := range drawn {
			order = withoutGREASE(order)
			if !slices.ContainsFunc(seen, func(s []uint16) bool { return slices.Equal(s, order) }) {
				seen = append(seen, order)
			}
		}
		return len(seen)
	}
	// Not asked: the capture's order, every time; asked, and as its browser
	// does by default, one drawn for each.
	if got := orders(t, idOf(t, p, false), false, 20); distinct(got) != 1 ||
		!slices.Equal(withoutGREASE(got[0]), withoutGREASE(reference)) {
		t.Errorf("not asked: %d orders", distinct(got))
	}
	if got := orders(t, idOf(t, p, true), false, 20); distinct(got) < 2 {
		t.Errorf("asked: %d orders", distinct(got))
	}
	built, err := p.ClientProfile()
	if err != nil {
		t.Fatalf("ClientProfile: %v", err)
	}
	if got := orders(t, built.GetClientHelloId(), false, 20); distinct(got) < 2 {
		t.Errorf("by default: %d orders", distinct(got))
	}
	// A bare base is the transport's own, asked or not.
	bare := &Profile{EngineMajor: Major(6), Name: "firefox_148", Base: "firefox_148"}
	for _, shuffle := range []bool{true, false} {
		built, err := bare.ClientProfileShuffled(shuffle)
		if err != nil {
			t.Fatalf("ClientProfileShuffled(%v): %v", shuffle, err)
		}
		got, want := built.GetClientHelloId(), profiles.MappedTLSClients["firefox_148"].GetClientHelloId()
		if got.Str() != want.Str() || (got.SpecFactory == nil) != (want.SpecFactory == nil) {
			t.Errorf("a bare base asked %v was made %s", shuffle, got.Str())
		}
	}
}

func TestABareBaseIsOneWithNothingOfItsOwn(t *testing.T) {
	for _, tc := range []struct {
		p    Profile
		want bool
	}{
		{Profile{EngineMajor: Major(6), Base: "firefox_148"}, true},
		{Profile{EngineMajor: Major(6)}, false},
		{Profile{EngineMajor: Major(6), Base: "firefox_148", ClientHello: []byte{1}}, false},
		{Profile{EngineMajor: Major(6), Base: "firefox_148", HTTP2: HTTP2{Settings: []Setting{{ID: 1, Value: 65536}}}}, false},
	} {
		if got := tc.p.BareBase(); got != tc.want {
			t.Errorf("%+v: %v", tc.p, got)
		}
	}
}
