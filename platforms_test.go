package tlsforge

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/Sec-CH-Lemon/tls-forge/v5/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v5/profile"
)

// chromePlatforms are the Chrome 155 profiles shipped for each platform, which
// the replays wear in turn. The fixtures were measured on macOS: what Chrome's
// network stack does, one code on each platform, is held to them, and what
// the platform and the machine decide, the platform's name in
// sec-ch-ua-platform and the client hints, to each profile's own (diffRequest).
var chromePlatforms = []string{"chrome_155_macos", "chrome_155_linux", "chrome_155_windows"}

// onEveryPlatform runs replay wearing each of them, a subtest each, named by
// its platform.
func onEveryPlatform(t *testing.T, replay func(t *testing.T, p *profile.Profile)) {
	t.Helper()
	for _, name := range chromePlatforms {
		p, err := profile.Get(name)
		if err != nil {
			t.Fatalf("profile: %v", err)
		}
		_, platform := profile.Split(name)
		t.Run(platform, func(t *testing.T) { replay(t, p) })
	}
}

// askedHint says a field is a client hint a browser sends only when a server
// asks for it.
func askedHint(name string) bool {
	return slices.Contains(profile.AskedClientHints(), strings.ToLower(name))
}

// platformDecided says a field's value is the platform's or the machine's, not
// the network stack's: sec-ch-ua-platform and every client hint a server asks
// for. A replay holds it to the profile's own.
func platformDecided(name string) bool {
	return strings.EqualFold(name, "sec-ch-ua-platform") || askedHint(name)
}

// ownValue is the value p sends of a field, as its headers or its client
// hints say it, and whether they say one.
func ownValue(p *profile.Profile, name string) (string, bool) {
	for _, field := range slices.Concat(p.Headers, p.ClientHints) {
		if strings.EqualFold(field.Name, name) {
			return field.Value, true
		}
	}
	return "", false
}

// codedWearing is a field of a header block as the bench reads one, "name:
// how it was written", as Chrome writes it wearing p: a literal of a field
// the platform decides, or of the user agent, Huffman-coded only when that
// is shorter, as quiche's encoder decides, by p's value rather than the value
// Chrome on macOS sent ("Windows" is shorter so, "macOS" and "Linux" are not).
// Any other field is as it was.
func codedWearing(field string, p *profile.Profile) string {
	name, said, _ := strings.Cut(field, ": ")
	value, ok := ownValue(p, name)
	if !ok || !platformDecided(name) && !strings.EqualFold(name, "user-agent") {
		return field
	}
	coded := "value plain"
	if hpack.HuffmanEncodeLength(value) < uint64(len(value)) {
		coded = "value huffman"
	}
	for _, was := range []string{"value plain", "value huffman"} {
		if rest, cut := strings.CutSuffix(said, was); cut {
			return name + ": " + rest + coded
		}
	}
	return field
}

// headless is p with the user agent of a headless Chrome of its platform, the
// one the fixtures were measured with: each field as long as Chrome's, for
// what lengths decide (HPACK's table, the TLS records of HTTP/1.1).
func headless(p *profile.Profile) *profile.Profile {
	out := p.Clone()
	out.UserAgent = strings.Replace(p.UserAgent, " Chrome/", " HeadlessChrome/", 1)
	for i, h := range out.Headers {
		if strings.EqualFold(h.Name, "user-agent") {
			out.Headers[i].Value = out.UserAgent
		}
	}
	return out
}

// skipApart skips a scenario Chrome sends otherwise on p's platform than on
// macOS, where it was measured (harness.Apart): the bench passes it over there
// too. Chrome on that platform is not held to it.
func skipApart(t *testing.T, p *profile.Profile, scenario string) {
	t.Helper()
	_, platform := profile.Split(p.Name)
	if why := harness.Apart(platform)[scenario]; why != "" {
		t.Skipf("%s on %s: %s", scenario, platform, why)
	}
}

func TestEveryScenarioApartOnAPlatformIsMeasured(t *testing.T) {
	measured := loadChromeRequests(t)
	for _, name := range chromePlatforms {
		_, platform := profile.Split(name)
		for scenario := range harness.Apart(platform) {
			if _, ok := measured.Scenarios[scenario]; !ok {
				t.Errorf("%s: %s is not in the fixture", platform, scenario)
			}
		}
	}
	if len(harness.Apart("windows")) == 0 {
		t.Error("nothing is apart on Windows: the Negotiate scenario is")
	}
}

func TestAFieldIsCodedAsQuicheCodesTheProfilesValue(t *testing.T) {
	// A literal of a field the platform decides, or of the user agent, is
	// Huffman-coded when that is shorter for the profile's value: "Windows"
	// is, "macOS" and "Linux" are not; any other field, an indexed one, and
	// a size update are as they were.
	shipped := map[string]*profile.Profile{}
	for _, name := range chromePlatforms {
		p, err := profile.Get(name)
		if err != nil {
			t.Fatalf("profile: %v", err)
		}
		_, platform := profile.Split(name)
		shipped[platform] = p
	}
	platform := "sec-ch-ua-platform: literal with incremental indexing, name static 1, value "
	for _, tc := range []struct {
		field, platform, want string
	}{
		{platform + "plain", "windows", platform + "huffman"},
		{platform + "huffman", "macos", platform + "plain"},
		{platform + "huffman", "linux", platform + "plain"},
		{platform + "plain", "macos", platform + "plain"},
		{"user-agent: literal with incremental indexing, name static 58, value plain", "windows",
			"user-agent: literal with incremental indexing, name static 58, value huffman"},
		{"accept: literal with incremental indexing, name static 19, value plain", "windows",
			"accept: literal with incremental indexing, name static 19, value plain"},
		{"sec-ch-ua-platform: indexed dynamic 63", "windows", "sec-ch-ua-platform: indexed dynamic 63"},
		{"size update 0", "windows", "size update 0"},
	} {
		if got := codedWearing(tc.field, shipped[tc.platform]); got != tc.want {
			t.Errorf("%q wearing %s: %q, want %q", tc.field, tc.platform, got, tc.want)
		}
	}
}
