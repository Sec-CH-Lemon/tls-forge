package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The chrome_156 of A8, captured on 156.0.8078.74 (Linux .73) with Chrome
// 155 as its basis, then changed by the layers of provenance since, is kept
// as it was shipped until its capture on the last build of 156
// (provenance/recaptured.json): the layers end on those bytes.
func TestChrome156RetainsNativeCaptureProvenance(t *testing.T) {
	registry := NewRegistry()
	registry.SetDir(t.TempDir())
	for _, platform := range []string{"macos", "linux", "windows"} {
		raw := keptBytes(t, "profile/data/chrome_156/"+platform+".json")
		got, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "chrome_156_"+platform {
			t.Fatalf("the kept chrome_156 is %s", got.Name)
		}
		saved, err := got.Save()
		if err != nil || !bytes.Equal(raw, saved) {
			t.Fatal("chrome_156 differs from current explicit candidate bytes", err)
		}
		metadata := keptBytes(t, "profile/provenance/chrome_156/"+platform+".json")
		var provenance CaptureProvenance
		if err := json.Unmarshal(metadata, &provenance); err != nil {
			t.Fatal(err)
		}
		assertA13Derivation(t, "profile/data/chrome_156/"+platform+".json", raw, provenance.ProfileSHA256)
		if provenance.BasisName != "chrome_155_"+platform {
			t.Fatal("native data/provenance identity differs")
		}
		basis, err := registry.Get(provenance.BasisName)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Behavior, basis.Behavior) || !reflect.DeepEqual(got.PerConnection, basis.PerConnection) {
			t.Fatal("unmeasured policies were lost or inferred")
		}
		var inventory struct {
			Profiles []struct {
				File   string
				Fields map[string]FieldOrigin
			}
		}
		inventoryRaw, err := os.ReadFile("provenance/a10.json")
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(inventoryRaw, &inventory); err != nil {
			t.Fatal(err)
		}
		current := map[string]FieldOrigin{}
		for _, entry := range inventory.Profiles {
			if entry.File == "data/chrome_156/"+platform+".json" {
				current = entry.Fields
			}
		}
		if len(current) != 8 {
			t.Fatal("incomplete A10 origins")
		}
		derived := a13DerivationOf(t, "profile/data/chrome_156/"+platform+".json")
		for key := range basis.Behavior {
			want := "inherited"
			if origin, ok := current[key]; ok {
				want = origin.Class
			}
			origin := provenance.Fields["behavior."+key]
			if added, ok := derived.Fields[key]; ok {
				origin = added
				want = "source-derived"
				if added.Source == "" {
					t.Fatal("missing source derivation", key)
				}
			}
			if layer, ok := policyAdded(t, key); ok {
				// A value added after the release, with its own provenance.
				origin = FieldOrigin{"source-derived", layer.Source}
				want = "source-derived"
			}
			if key == "headers.network_hints" {
				// A13 is an explicit later source-derived policy, not part of
				// the immutable A12 capture provenance.
				origin = FieldOrigin{"source-derived", "provenance/a13-network-hints.json"}
				want = "source-derived"
			}
			if origin.Class != want {
				t.Fatalf("unmeasured field %s lost its origin", key)
			}
		}
	}
}

// Chrome 156 was captured again on 2026-11-08, headed, on the last build of
// 156 of each platform, the one the pinned installers are, with the
// chrome_156 it replaced as its policy basis, which was Chrome 157's too.
func TestChrome156IsCapturedOnTheBuildItsInstallersArePinnedTo(t *testing.T) {
	registry := NewRegistry()
	registry.SetDir(t.TempDir())
	raw, err := os.ReadFile("../verification/chrome156-installers.json")
	if err != nil {
		t.Fatal(err)
	}
	var installers struct {
		Platforms map[string]struct{ Version string }
	}
	if err := json.Unmarshal(raw, &installers); err != nil {
		t.Fatal(err)
	}
	for platform, system := range map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"} {
		basis := replacedChrome156(t, platform)
		provenance := capturedOn(t, registry, "156", platform, basis)
		if pinned := installers.Platforms[system].Version; provenance.Browser.UAFullVersion != pinned {
			t.Fatalf("%s was captured on %s, where its installer is %s", platform, provenance.Browser.UAFullVersion, pinned)
		}
		metadata, err := os.ReadFile("provenance/chrome_157/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var newer CaptureProvenance
		if err := json.Unmarshal(metadata, &newer); err != nil {
			t.Fatal(err)
		}
		if newer.BasisSHA256 != provenance.BasisSHA256 {
			t.Fatalf("%s: Chrome 157 and 156 were captured on other bases", platform)
		}
	}
}
