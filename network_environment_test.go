package tlsforge

import (
	"encoding/json"
	"github.com/Sec-CH-Lemon/tls-forge/v2/networkquality"
	"os"
	"strings"
	"testing"
)

func TestA13NativeNetworkMetadataIsActualAndHasNoEstimates(t *testing.T) {
	p := a13EstimatedProfile(t).NetworkHints.Policy.Environment
	p.Source = "system"
	p.Identity = "route-interface-addresses"
	p.Missing = "reject"
	actual, err := networkInput(p, nil)
	if err != nil {
		t.Fatal("native metadata unavailable", err)
	}
	if err := actual.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(actual.ID, "route:") || len(actual.ID) != 70 || actual.Signal != nil {
		t.Fatal("invalid system metadata", actual)
	}
	raw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rtt", "downlink", "ect", "salt"} {
		if strings.Contains(string(raw), `"`+name+`"`) {
			t.Fatal("estimate leaked into metadata", string(raw))
		}
	}
	if path := os.Getenv("TLSFORGE_A13_METADATA_EVIDENCE"); path != "" {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestA13MetadataMissingInputIsExplicitAndSnapshotsOverrides(t *testing.T) {
	p := a13EstimatedProfile(t).NetworkHints.Policy.Environment
	p.Source = "context"
	p.Missing = "reject"
	if _, err := networkInput(p, nil); err == nil {
		t.Fatal("missing mandatory context accepted")
	}
	p.Missing = "fallback"
	p.Fallback = NetworkContext{Type: "wifi", ID: "fallback", Signal: new(int)}
	got, err := networkInput(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	*got.Signal = 4
	if *p.Fallback.Signal != 0 {
		t.Fatal("fallback pointer aliases policy")
	}
	explicit := NetworkContext{Type: "none", ID: "offline", Signal: new(int)}
	got, err = networkInput(p, &explicit)
	if err != nil || got.Type != "none" {
		t.Fatal(got, err)
	}
	*got.Signal = 4
	if *explicit.Signal != 0 {
		t.Fatal("explicit input aliases caller")
	}
	if _, err := networkInput(p, &networkquality.Context{Type: "made-up"}); err == nil {
		t.Fatal("invalid metadata accepted")
	}
}

func TestA13SourceBoundConnectionTypeIdentityDoesNotInventSSID(t *testing.T) {
	p := a13EstimatedProfile(t).NetworkHints.Policy.Environment
	p.Source = "system"
	p.Missing = "reject"
	p.Identity = "connection-type"
	context, err := networkInput(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if context.ID != "" || context.Signal != nil {
		t.Fatal("pinned Chrome156 GetCurrentNetworkID returns type and empty identity/unavailable signal", context)
	}
}
