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
			t.Fatal("default differs from exact native candidate bytes", err)
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
		for key := range basis.Behavior {
			if provenance.Fields["behavior."+key].Class != "inherited" {
				t.Fatalf("unmeasured field %s lost its origin", key)
			}
		}
	}
}
