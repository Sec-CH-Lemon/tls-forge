package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestChrome156RetainsNativeCaptureProvenance(t *testing.T) {
	previous := hostPlatform
	t.Cleanup(func() { hostPlatform = previous })
	registry := NewRegistry()
	registry.SetDir(t.TempDir())
	for _, platform := range []string{"macos", "linux", "windows"} {
		hostPlatform = platform
		got, err := registry.Get("chrome_156")
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "chrome_156_"+platform {
			t.Fatalf("chrome_156 selected %s", got.Name)
		}
		raw, err := os.ReadFile("data/chrome_156/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		saved, err := got.Save()
		if err != nil || !bytes.Equal(raw, saved) {
			t.Fatal("chrome_156 differs from current explicit candidate bytes", err)
		}
		metadata, err := os.ReadFile("provenance/chrome_156/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
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
