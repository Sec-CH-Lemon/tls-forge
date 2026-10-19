package profile

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	tls "github.com/igor-lemon/utls"
)

func TestEveryShippedProfileSendsItsTrustAnchorsAsItsChromeDid(t *testing.T) {
	// Chrome 154 and 155 sent their IDs sorted by their bytes on all three
	// platforms, and go out as captured; 152 and 153 drew their order for each
	// process, one order on each machine, and go out in the order this process
	// draws, the same every time; 151 sent none.
	paths, err := fs.Glob(embedded, "data/*/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("shipped profiles: %v, %v", paths, err)
	}
	for _, path := range paths {
		data, err := embedded.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		p, err := Load(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		captured := trustAnchorsCaptured(t, p)
		sent := trustAnchorsSent(t, p)
		version, _ := Split(p.Name)
		switch version {
		case "chrome_151":
			if captured != nil || sent != nil {
				t.Errorf("%s sends trust anchors: %x", path, sent)
			}
		case "chrome_152", "chrome_153":
			records, err := splitTrustAnchors(captured)
			if err != nil || inByteOrder(records) {
				t.Errorf("%s: captured in byte order, or not read: %v", path, err)
			}
			if again := trustAnchorsSent(t, p); !bytes.Equal(sent, again) {
				t.Errorf("%s drew another order: %x, then %x", path, sent, again)
			}
			if got, want := sortedTrustAnchors(t, sent), sortedTrustAnchors(t, captured); !slices.Equal(got, want) {
				t.Errorf("%s sends other IDs: %v, captured %v", path, got, want)
			}
		case "chrome_154", "chrome_155":
			records, err := splitTrustAnchors(sent)
			if err != nil || !inByteOrder(records) || !bytes.Equal(sent, captured) {
				t.Errorf("%s: sent %x, captured %x, %v", path, sent, captured, err)
			}
		default:
			// A browser measured later says here how it orders them.
			t.Errorf("%s: how %s orders its trust anchors is not known here", path, version)
		}
	}
}

// trustAnchorsCaptured is the trust_anchors payload of p's captured hello, nil
// for none.
func trustAnchorsCaptured(t *testing.T, p *Profile) []byte {
	t.Helper()
	spec, err := (&tls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(p.ClientHello)
	if err != nil {
		t.Fatalf("%s: %v", p.Name, err)
	}
	return trustAnchorsIn(*spec)
}

// sortedTrustAnchors are payload's records sorted, as one set.
func sortedTrustAnchors(t *testing.T, payload []byte) []string {
	t.Helper()
	records, err := splitTrustAnchors(payload)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(records))
	for i, record := range records {
		out[i] = fmt.Sprintf("%x", record)
	}
	slices.Sort(out)
	return out
}

func TestEveryShippedProfileIsReadAndWornAsItShips(t *testing.T) {
	// Each in the current schema, read strictly; built into a handshake and a
	// client without its bytes changing; and saved back as it ships, so that
	// the files are what Save writes.
	paths, err := fs.Glob(embedded, "data/*/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("shipped profiles: %v, %v", paths, err)
	}
	for _, path := range paths {
		data, err := embedded.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		before := bytes.Clone(data)
		p, err := Load(data)
		if err != nil || p.Schema != Schema {
			t.Fatalf("%s: schema %d, %v", path, p.Schema, err)
		}
		// Every one is Chrome's, and says what Chrome draws.
		if !reflect.DeepEqual(p.PerConnection, chromiumPerConnection()) {
			t.Errorf("%s draws %+v per connection", path, p.PerConnection)
		}
		hello := bytes.Clone(p.ClientHello)
		if _, err := p.Spec(); err != nil {
			t.Errorf("%s: Spec: %v", path, err)
		}
		if _, err := p.ClientProfile(); err != nil {
			t.Errorf("%s: ClientProfile: %v", path, err)
		}
		saved, err := p.Save()
		if err != nil || !bytes.Equal(saved, data) {
			t.Errorf("%s is not what Save writes of it (%v)", path, err)
		}
		if !bytes.Equal(data, before) || !bytes.Equal(p.ClientHello, hello) {
			t.Errorf("%s: reading or wearing it changed it", path)
		}
	}
}

func TestWhatABrowserDrawsPerConnectionIsSaidOutright(t *testing.T) {
	raw, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	captured := []uint16{uint16(capturedECH(t, raw).PayloadLength - 16)}
	for _, tc := range []struct {
		name     string
		profile  *Profile
		shuffles bool
		lengths  []uint16
	}{
		// Said, it is what is done, whatever the name says.
		{"Chrome said to draw nothing", &Profile{Name: "chrome_155", ClientHello: raw, PerConnection: &PerConnection{}},
			false, captured},
		{"Firefox said to draw", &Profile{Name: "firefox_148", ClientHello: raw,
			PerConnection: &PerConnection{ShufflesExtensions: true, ECHPayloadLengths: []uint16{100, 200}}},
			true, []uint16{100, 200}},
		// Unsaid, it is guessed from the name, as before profiles said it.
		{"Chrome unsaid", &Profile{Name: "chrome_155", ClientHello: raw}, true, chromeECHPayloadLengths},
		{"Firefox unsaid", &Profile{Name: "firefox_148", ClientHello: raw}, false, captured},
	} {
		spec, err := tc.profile.Spec()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := tc.profile.ShufflesExtensions(); got != tc.shuffles {
			t.Errorf("%s: shuffles %v", tc.name, got)
		}
		if got := greaseECH(t, spec).CandidatePayloadLens; !slices.Equal(got, tc.lengths) {
			t.Errorf("%s: draws from %v, want %v", tc.name, got, tc.lengths)
		}
	}
}

func TestFromCaptureSaysWhatTheBrowserDrawsPerConnection(t *testing.T) {
	raw, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	brands := func(names ...string) *capture.Navigator {
		nav := &capture.Navigator{}
		for _, name := range names {
			nav.Brands = append(nav.Brands, capture.Brand{Brand: name, Version: "155"})
		}
		return nav
	}
	for _, tc := range []struct {
		name      string
		navigator *capture.Navigator
		agent     string
		want      *PerConnection
	}{
		// The brands a browser gives say it best: only Chromium's count Chromium.
		{"Chrome's brands", brands("Not)A;Brand", "Chromium", "Google Chrome"), "", chromiumPerConnection()},
		{"brands without Chromium", brands("Not)A;Brand", "Something Else"), "Mozilla/5.0 Chrome/155", &PerConnection{}},
		// Without them, the user agent and the name do.
		{"Chrome's user agent", nil, "Mozilla/5.0 Chrome/155.0.0.0", chromiumPerConnection()},
		{"Chrome on an iPhone", nil, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/155.0", &PerConnection{}},
		{"Firefox", &capture.Navigator{UserAgent: "Mozilla/5.0 Firefox/148.0"}, "", &PerConnection{}},
	} {
		measured := &capture.Capture{RawClientHello: raw, Navigator: tc.navigator, HTTP2: &capture.HTTP2{
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			Headers:           []capture.HeaderField{{Name: ":method", Value: "GET"}, {Name: "user-agent", Value: tc.agent}},
		}}
		built, err := FromCapture("custom", measured)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reflect.DeepEqual(built.PerConnection, tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, built.PerConnection, tc.want)
		}
	}
}

func TestFromCaptureSaysTheUserAgentsHintsAsChromeSendsThem(t *testing.T) {
	raw, err := os.ReadFile("../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	built := func(nav *capture.Navigator) []Field {
		t.Helper()
		p, err := FromCapture("custom", &capture.Capture{RawClientHello: raw, Navigator: nav, HTTP2: &capture.HTTP2{
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			Headers:           []capture.HeaderField{{Name: ":method", Value: "GET"}},
		}})
		if err != nil {
			t.Fatalf("FromCapture: %v", err)
		}
		return p.ClientHints
	}
	// What Chrome 155 on this Mac told JavaScript is what it sent when asked,
	// as the shipped profile has it, measured.
	shipped, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	measured := map[string]string{}
	for _, hint := range shipped.ClientHints {
		measured[hint.Name] = hint.Value
	}
	got := built(&capture.Navigator{
		FullVersionList: []capture.Brand{{Brand: "Google Chrome", Version: "155.0.8059.80"},
			{Brand: "Chromium", Version: "155.0.8059.80"}, {Brand: "Not(A:Brand", Version: "24.0.0.0"}},
		Architecture: "arm", Bitness: "64", Model: "", PlatformVersion: "27.0.1", UAFullVersion: "155.0.8059.80",
		FormFactors: []string{"Desktop"},
	})
	var names []string
	for _, hint := range got {
		names = append(names, hint.Name)
		if measured[hint.Name] != hint.Value {
			t.Errorf("%s: %s, Chrome sent %s", hint.Name, hint.Value, measured[hint.Name])
		}
	}
	if want := "sec-ch-ua-full-version sec-ch-ua-arch sec-ch-ua-platform-version sec-ch-ua-model sec-ch-ua-bitness " +
		"sec-ch-ua-wow64 sec-ch-ua-full-version-list sec-ch-ua-form-factors"; strings.Join(names, " ") != want {
		t.Errorf("%v", names)
	}
	// A browser that gave no high-entropy values has none; WOW64 and form
	// factors are said as given, and strings escaped as Structured Fields.
	if hints := built(&capture.Navigator{Brands: []capture.Brand{{Brand: "Chromium", Version: "155"}}}); hints != nil {
		t.Errorf("no values: %v", hints)
	}
	if hints := built(nil); hints != nil {
		t.Errorf("no navigator: %v", hints)
	}
	got = built(&capture.Navigator{FullVersionList: []capture.Brand{{Brand: `A"B\C`, Version: "1"}}, WOW64: true,
		FormFactors: []string{"Tablet", "XR"}})
	values := map[string]string{}
	for _, hint := range got {
		values[hint.Name] = hint.Value
	}
	if values["sec-ch-ua-wow64"] != "?1" || values["sec-ch-ua-form-factors"] != `"Tablet", "XR"` ||
		values["sec-ch-ua-full-version-list"] != `"A\"B\\C";v="1"` || values["sec-ch-ua-arch"] != `""` {
		t.Errorf("%v", values)
	}
	if _, ok := values["sec-ch-ua-form-factors"]; !ok {
		t.Error("no form factors")
	}
	if got := built(&capture.Navigator{FullVersionList: []capture.Brand{{Brand: "B", Version: "1"}}}); len(got) != 7 {
		t.Errorf("no form factors given, and %v", got)
	}
}

func TestAnECHPayloadLengthIsOneABrowserCouldDraw(t *testing.T) {
	// The payload's length field holds 65535 bytes, the AEAD's tag among them.
	for length, ok := range map[int]bool{0: false, 1: true, 65519: true, 65520: false} {
		document := fmt.Sprintf(`{"schema":1,"name":"x","base":"chrome_133","per_connection":{"ech_payload_lengths":[128,%d]}}`, length)
		_, err := Load([]byte(document))
		if (err == nil) != ok || (err != nil && !strings.Contains(err.Error(), fmt.Sprintf("an ECH payload of %d bytes", length))) {
			t.Errorf("%d: %v", length, err)
		}
	}
}

func TestACloneDrawsFromItsOwnLengths(t *testing.T) {
	original := &Profile{Name: "x", PerConnection: chromiumPerConnection()}
	clone := original.Clone()
	clone.PerConnection.ECHPayloadLengths[0] = 1
	clone.PerConnection.ShufflesExtensions = false
	if !reflect.DeepEqual(original.PerConnection, chromiumPerConnection()) {
		t.Errorf("the clone shares %+v", original.PerConnection)
	}
	if (&Profile{Name: "x"}).Clone().PerConnection != nil {
		t.Error("a profile that says nothing says something cloned")
	}
}

func TestACustomProfileBuildsOnAnyCatalogueEntry(t *testing.T) {
	// Entries that are a spec of their own and entries that are utls's
	// presets, which have none to give.
	for _, base := range []string{"chrome_133", "chrome_110", "safari_16_0", "firefox_120"} {
		p := &Profile{Name: "custom", Base: base, HTTP2: HTTP2{Settings: []Setting{{ID: 1, Value: 65536}},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}}}
		if spec, err := p.Spec(); err != nil || len(spec.Extensions) == 0 {
			t.Errorf("%s: %d extensions, %v", base, len(spec.Extensions), err)
		}
		if _, err := p.ClientProfile(); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
}
