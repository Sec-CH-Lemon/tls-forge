package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

// capturedOn holds the shipped chrome_<version> of a platform to the
// provenance capture.yml gave it: the profile is what Save writes, captured
// headed on basis, whose every unmeasured value it keeps, and it sends the
// build the browser said, which it returns.
func capturedOn(t *testing.T, registry *Registry, version, platform string, basis *Profile) CaptureProvenance {
	t.Helper()
	previous := hostPlatform
	t.Cleanup(func() { hostPlatform = previous })
	hostPlatform = platform
	got, err := registry.Get("chrome_" + version)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "chrome_"+version+"_"+platform {
		t.Fatalf("chrome_%s on %s is %s", version, platform, got.Name)
	}
	raw, err := os.ReadFile("data/chrome_" + version + "/" + platform + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if saved, err := got.Save(); err != nil || !bytes.Equal(raw, saved) {
		t.Fatalf("%s is not what Save writes: %v", got.Name, err)
	}
	metadata, err := os.ReadFile("provenance/chrome_" + version + "/" + platform + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance CaptureProvenance
	if err := json.Unmarshal(metadata, &provenance); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if provenance.ProfileSHA256 != hex.EncodeToString(sum[:]) || provenance.BrowserMode != "headed" ||
		provenance.BasisName != basis.Name {
		t.Fatalf("%s: the profile is not the one its provenance says, or not of its basis", got.Name)
	}
	if hash, err := canonicalHash(basis); err != nil || hash != provenance.BasisSHA256 {
		t.Fatalf("%s was captured on another %s: %v", got.Name, provenance.BasisName, err)
	}
	if !reflect.DeepEqual(got.Behavior, basis.Behavior) || !reflect.DeepEqual(got.PerConnection, basis.PerConnection) ||
		!reflect.DeepEqual(got.NetworkHints, basis.NetworkHints) {
		t.Fatalf("%s: unmeasured policies were lost or inferred", got.Name)
	}
	for key := range basis.Behavior {
		if origin := provenance.Fields["behavior."+key]; origin.Class != "inherited" {
			t.Fatalf("%s: behavior.%s is %q, where the capture measured none", got.Name, key, origin.Class)
		}
	}
	// The build the browser said is the one the profile sends.
	if provenance.Browser == nil || provenance.Browser.UAFullVersion[:4] != version+"." ||
		hintValue(got, "sec-ch-ua-full-version") != strconv.Quote(provenance.Browser.UAFullVersion) {
		t.Fatalf("%s: the build said %+v, sent %s", got.Name, provenance.Browser, hintValue(got, "sec-ch-ua-full-version"))
	}
	return provenance
}

// replacedChrome156 is the chrome_156 of a platform that tls-forge shipped
// until it was captured again (2026-11-08), from its kept copy.
func replacedChrome156(t *testing.T, platform string) *Profile {
	t.Helper()
	p, err := Load(keptBytes(t, "profile/data/chrome_156/"+platform+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Chrome 157 was captured on Google Chrome Stable of each platform, headed
// (capture.yml, 2026-11-07), with the chrome_156 tls-forge shipped for the
// platform then as its policy basis: what the capture did not measure is the
// basis's, every value of it.
func TestChrome157IsTheDefaultAndKeepsItsCaptureProvenance(t *testing.T) {
	previous := hostPlatform
	t.Cleanup(func() { hostPlatform = previous })
	registry := NewRegistry()
	registry.SetDir(t.TempDir())
	for _, platform := range []string{"macos", "linux", "windows"} {
		hostPlatform = platform
		got, err := registry.Get("chrome")
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "chrome_157_"+platform {
			t.Fatalf("the default on %s is %s", platform, got.Name)
		}
		capturedOn(t, registry, "157", platform, replacedChrome156(t, platform))
	}
}

// hintValue is the value p sends a client hint by, or nothing.
func hintValue(p *Profile, name string) string {
	for _, h := range p.ClientHints {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}
