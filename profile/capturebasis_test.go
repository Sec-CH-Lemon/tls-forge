package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

func testCaptureBasis(t *testing.T) *Profile {
	t.Helper()
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.ClientHints = nil
	return p
}

func TestCaptureRequiresExplicitPolicyBasis(t *testing.T) {
	c := &capture.Capture{RawClientHello: chromeHelloBytes(t), HTTP2: &capture.HTTP2{}}
	if _, err := FromCapture("chrome_156_macos", c); err == nil {
		t.Fatal("missing basis accepted")
	}
	if _, err := FromCapture("x", c, (*Profile)(nil)); err == nil {
		t.Fatal("nil basis accepted")
	}
	p := testCaptureBasis(t)
	p.EngineMajor = Major(0)
	if _, err := FromCapture("x", c, p); err == nil {
		t.Fatal("old-engine basis silently retagged")
	}
}

func TestCaptureRetainsEveryUnmeasuredPolicyWithoutIdentityDispatch(t *testing.T) {
	basis := testCaptureBasis(t)
	before, _ := basis.Save()
	c := &capture.Capture{RawClientHello: chromeHelloBytes(t), HTTP2: &capture.HTTP2{}, Navigator: &capture.Navigator{UserAgent: "Windows Chrome/999", Brands: []capture.Brand{{Brand: "Chromium", Version: "999"}}}}
	built, err := FromCapture("firefox_999_windows", c, basis)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(built.Behavior, basis.Behavior) || !reflect.DeepEqual(built.PerConnection, basis.PerConnection) {
		t.Fatal("name/UA/brand changed explicit policies")
	}
	if len(built.Behavior) != len(basis.Behavior) {
		t.Fatal("policy fields lost")
	}
	for k, v := range basis.Behavior {
		if !reflect.DeepEqual(built.Behavior[k], v) {
			t.Fatalf("lost %s", k)
		}
	}
	built.Behavior["tls.close_notify"] = json.RawMessage(`true`)
	built.PerConnection.ECHPayloadLengths[0]++
	after, _ := basis.Save()
	if string(before) != string(after) {
		t.Fatal("capture aliases basis")
	}
}

func TestCaptureBasisSelectsShippedPlatformData(t *testing.T) {
	for _, platform := range []string{"macos", "linux", "windows"} {
		p, err := CaptureBasis("chrome", platform)
		if err != nil || p.Name != "chrome_155_"+platform {
			t.Fatalf("%s: %v %v", platform, p, err)
		}
	}
	for _, pair := range [][2]string{{"unknown", "macos"}, {"chrome", "unknown"}, {"../chrome", "macos"}} {
		if _, err := CaptureBasis(pair[0], pair[1]); err == nil {
			t.Fatal("missing/invalid basis accepted")
		}
	}
}

func TestCaptureProvenanceBindsDataAndDoesNotUpgradeVerdicts(t *testing.T) {
	basis, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	c := &capture.Capture{RawClientHello: chromeHelloBytes(t), HTTP2: &capture.HTTP2{}, Navigator: &capture.Navigator{Architecture: "x86", FullVersionList: []capture.Brand{{Brand: "Chromium", Version: "156.0.0.0"}}}}
	built, err := FromCapture("neutral", c, basis)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := ProvenanceForCapture(built, basis, c, "headed")
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := built.Save()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(serialized)
	want := hex.EncodeToString(sum[:])
	if provenance.ProfileSHA256 != want || provenance.BasisName != basis.Name || provenance.BrowserMode != "headed" {
		t.Fatal("provenance does not bind source")
	}
	for k := range basis.Behavior {
		if provenance.Fields["behavior."+k].Class != "inherited" {
			t.Fatalf("policy %s falsely measured", k)
		}
	}
	if provenance.Fields["client_hints.rtt"].Class != "inherited" || provenance.Fields["client_hints.sec-ch-ua-arch"].Class != "measured" {
		t.Fatal("dynamic/persona origin mixed")
	}
	if provenance.Acceptance != "candidate; browser/wire acceptance not established by capture" {
		t.Fatal("capture promoted to browser acceptance")
	}
	provenance.Browser.Architecture = "changed"
	if c.Navigator.Architecture != "x86" {
		t.Fatal("provenance aliases capture")
	}
	if _, err := ProvenanceForCapture(nil, basis, c, "headed"); err == nil {
		t.Fatal("nil candidate accepted")
	}
	invalid := built.Clone()
	invalid.Behavior["tls.close_notify"] = json.RawMessage("bad json")
	if _, err := ProvenanceForCapture(invalid, basis, c, "headed"); err == nil {
		t.Fatal("unhashable candidate accepted")
	}
	invalid = basis.Clone()
	invalid.Behavior["tls.close_notify"] = json.RawMessage("bad json")
	if _, err := ProvenanceForCapture(built, invalid, c, "headed"); err == nil {
		t.Fatal("unhashable basis accepted")
	}
	invalid = basis.Clone()
	invalid.EngineMajor = Major(0)
	if _, err := ProvenanceForCapture(built, invalid, c, "headed"); err == nil {
		t.Fatal("old basis accepted")
	}
	c.Navigator.Extra = json.RawMessage("bad json")
	if _, err := ProvenanceForCapture(built, basis, c, "headed"); err == nil {
		t.Fatal("unhashable capture accepted")
	}
}

func TestCaptureDoesNotFreezeContextOrInventMissingPersonaFields(t *testing.T) {
	basis, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	c := &capture.Capture{RawClientHello: chromeHelloBytes(t), HTTP2: &capture.HTTP2{}, Navigator: &capture.Navigator{FullVersionList: []capture.Brand{{Brand: "Chromium", Version: "156.0.0.0"}}}, ClientHints: []capture.HeaderField{{Name: "rtt", Value: "999"}, {Name: "viewport-width", Value: "999"}, {Name: "sec-ch-ua-arch", Value: `"x86"`}}}
	got, err := FromCapture("neutral", c, basis)
	if err != nil {
		t.Fatal(err)
	}
	hints := map[string]string{}
	for _, hint := range got.ClientHints {
		hints[hint.Name] = hint.Value
	}
	if hints["rtt"] == "999" || hints["viewport-width"] == "999" || hints["sec-ch-ua-arch"] != `"x86"` || hints["sec-ch-ua-full-version"] == `""` {
		t.Fatal("unknown/context data frozen or missing persona field invented")
	}
	for _, mutate := range []func(*Profile){func(p *Profile) { p.PerConnection = nil }, func(p *Profile) { p.Schema = 1 }} {
		p := basis.Clone()
		mutate(p)
		if _, err := FromCapture("x", c, p); err == nil {
			t.Fatal("implicit basis generation accepted")
		}
	}
}

type captureReadFault struct {
	fs.FS
	missing bool
}

func (f captureReadFault) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, "macos.json") {
		if f.missing {
			return nil, fs.ErrNotExist
		}
		return nil, fs.ErrPermission
	}
	return f.FS.Open(name)
}

func TestCaptureBasisSourceErrors(t *testing.T) {
	basis := testCaptureBasis(t)
	data, err := basis.Save()
	if err != nil {
		t.Fatal(err)
	}
	source := fstest.MapFS{"data/chrome_155/macos.json": {Data: data}, "data/not_chrome/macos.json": {Data: data}, "data/chrome_bad/macos.json": {Data: data}}
	for _, missing := range []bool{false, true} {
		if _, err := captureBasisIn(captureReadFault{source, missing}, "chrome", "macos"); err == nil {
			t.Fatal("unreadable basis accepted")
		}
	}
}

func TestCaptureRejectsUnrepresentableObservedDraws(t *testing.T) {
	chrome := testCaptureBasis(t)
	c := &capture.Capture{RawClientHello: rawHelloOf(t, chrome, true), Connections: hellosOf(t, chrome, true, 20), HTTP2: &capture.HTTP2{}}
	for _, mutate := range []func(*Profile){func(p *Profile) { p.PerConnection.ShufflesExtensions = false }, func(p *Profile) { p.PerConnection.ECHPayloadLengths = []uint16{128} }, func(p *Profile) { p.PerConnection.ECHPayloadLengths = []uint16{1, 2} }} {
		basis := chrome.Clone()
		mutate(basis)
		if _, err := FromCapture("candidate", c, basis); err == nil {
			t.Fatal("observed draws silently replaced/invented generation rules")
		}
	}
	p := chrome.Clone()
	p.Base = "chrome_133"
	p.ClientHello = nil
	p.HTTP2 = HTTP2{}
	if _, err := FromCapture("candidate", c, p); err == nil {
		t.Fatal("catalogue preset accepted as full basis")
	}
	c.Connections[0] = []byte{0}
	if _, err := ProvenanceForCapture(chrome, chrome, c, "headed"); err == nil {
		t.Fatal("broken draw evidence accepted")
	}
}

func TestCaptureAddsObservedPersonaAndBindsCompleteMeasurements(t *testing.T) {
	basis := testCaptureBasis(t)
	c := &capture.Capture{RawClientHello: chromeHelloBytes(t), HTTP1: &capture.HTTP1{Headers: []capture.HeaderField{{Name: "Host", Value: "localhost"}}, HeaderNames: []string{"Host"}}, HTTP2: &capture.HTTP2{PseudoHeaderOrder: []string{"m", "a", "s", "p"}, Headers: []capture.HeaderField{{Name: ":method", Value: "GET"}}}, Navigator: &capture.Navigator{Architecture: "riscv", FullVersionList: []capture.Brand{{Brand: "Chromium", Version: "156.0.0.0"}}}}
	candidate, err := FromCapture("candidate", c, basis)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.ClientHints) != 2 {
		t.Fatalf("observed persona lost: %v", candidate.ClientHints)
	}
	a, err := ProvenanceForCapture(candidate, basis, c, "headed")
	if err != nil {
		t.Fatal(err)
	}
	if a.Fields["http1"].Class != "measured" || a.Fields["http2"].Class != "measured" || a.Fields["headers"].Class != "measured" {
		t.Fatal("real measurements marked inherited")
	}
	renamed := candidate.Clone()
	renamed.Name = "renamed"
	b, err := ProvenanceForCapture(renamed, basis, c, "headed")
	if err != nil {
		t.Fatal(err)
	}
	if a.ProfileSHA256 == b.ProfileSHA256 || a.BasisSHA256 != b.BasisSHA256 {
		t.Fatal("hash does not bind final candidate")
	}
	c.HTTP2 = nil
	if _, err := ProvenanceForCapture(candidate, basis, c, "partial"); err != nil {
		t.Fatal(err)
	}
}
