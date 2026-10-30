package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPlatformPolicyInheritanceKeepsOSChoicesAndProvenance(t *testing.T) {
	basis, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux", "windows"} {
		p, err := Get("chrome_155_" + platform)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile("provenance/chrome_155/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Fields        map[string]FieldOrigin `json:"fields"`
			ProfileSHA256 string                 `json:"profile_sha256"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile("data/chrome_155/" + platform + ".json")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if meta.ProfileSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("provenance exact hash mismatch")
		}
		if len(meta.Fields) != 38 {
			t.Fatalf("shared policy count %d", len(meta.Fields))
		}
		for field, origin := range meta.Fields {
			key := strings.TrimPrefix(field, "behavior.")
			if !reflect.DeepEqual(p.Behavior[key], basis.Behavior[key]) || origin.Class != func() string {
				if key == "http.instance_scope" || key == "http.cache_scope" {
					return "user-provided"
				}
				return "inherited"
			}() {
				t.Fatalf("policy origin/value lost: %s", key)
			}
		}
		if p.Behavior.Uint("tcp.keepalive_interval_seconds") != 45 || p.Behavior.Flag("http.negotiate_auth") != (platform == "windows") || p.Behavior.Has("quic.alarm_slack_ms") || p.Behavior.Has("quic.ack_alarm_slack_percent") {
			t.Fatal("OS choices overwritten")
		}
	}
}
