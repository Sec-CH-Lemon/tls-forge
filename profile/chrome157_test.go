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

// Chrome 157 was captured on Google Chrome Stable of each platform, headed
// (capture.yml, 2026-11-07), with the chrome_156 tls-forge ships for the
// platform as its policy basis: what the capture did not measure is the
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
		raw, err := os.ReadFile("data/chrome_157/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if saved, err := got.Save(); err != nil || !bytes.Equal(raw, saved) {
			t.Fatalf("%s is not what Save writes: %v", platform, err)
		}
		metadata, err := os.ReadFile("provenance/chrome_157/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var provenance CaptureProvenance
		if err := json.Unmarshal(metadata, &provenance); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if provenance.ProfileSHA256 != hex.EncodeToString(sum[:]) || provenance.BrowserMode != "headed" ||
			provenance.BasisName != "chrome_156_"+platform {
			t.Fatalf("%s: the profile is not the one its provenance says, or not of its basis", platform)
		}
		// The basis it was captured on is the one shipped now.
		basis, err := registry.Get(provenance.BasisName)
		if err != nil {
			t.Fatal(err)
		}
		if hash, err := canonicalHash(basis); err != nil || hash != provenance.BasisSHA256 {
			t.Fatalf("%s was captured on another %s: %v", platform, provenance.BasisName, err)
		}
		if !reflect.DeepEqual(got.Behavior, basis.Behavior) || !reflect.DeepEqual(got.PerConnection, basis.PerConnection) ||
			!reflect.DeepEqual(got.NetworkHints, basis.NetworkHints) {
			t.Fatalf("%s: unmeasured policies were lost or inferred", platform)
		}
		for key := range basis.Behavior {
			if origin := provenance.Fields["behavior."+key]; origin.Class != "inherited" {
				t.Fatalf("%s: behavior.%s is %q, where the capture measured none", platform, key, origin.Class)
			}
		}
		// The build the browser said is the one the profile sends.
		if provenance.Browser == nil || provenance.Browser.UAFullVersion[:4] != "157." ||
			hintValue(got, "sec-ch-ua-full-version") != strconv.Quote(provenance.Browser.UAFullVersion) {
			t.Fatalf("%s: the build said %+v, sent %s", platform, provenance.Browser, hintValue(got, "sec-ch-ua-full-version"))
		}
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
