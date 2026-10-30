package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestChrome156DefaultsRetainNativeCaptureProvenance(t *testing.T) {
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
		if got.Name != "chrome_156_"+platform {
			t.Fatalf("default selected %s", got.Name)
		}
		raw, err := os.ReadFile("data/chrome_156/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		saved, err := got.Save()
		if err != nil || !bytes.Equal(raw, saved) {
			t.Fatal("default differs from current explicit candidate bytes", err)
		}
		metadata, err := os.ReadFile("provenance/chrome_156/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var provenance CaptureProvenance
		if err := json.Unmarshal(metadata, &provenance); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if provenance.ProfileSHA256 != hex.EncodeToString(sum[:]) || provenance.BasisName != "chrome_155_"+platform {
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
		for key := range basis.Behavior {
			want := "inherited"
			if origin, ok := current[key]; ok {
				want = origin.Class
			}
			if provenance.Fields["behavior."+key].Class != want {
				t.Fatalf("unmeasured field %s lost its origin", key)
			}
		}
	}
}
