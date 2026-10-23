package profile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBehaviorIsExplicitAfterMigrationAndIndependentOfIdentity(t *testing.T) {
	old := &Profile{EngineMajor: Major(1), Name: "chrome_custom", Base: "chrome_133"}
	saved, err := old.Save()
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := Load(saved)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != Schema || migrated.Behavior == nil || migrated.PerConnection == nil {
		t.Fatal("migration did not materialize policy")
	}
	before := migrated.RuntimeBehavior().Clone()
	migrated.Name = "unrelated_200"
	migrated.Base = "firefox_148"
	migrated.UserAgent = "Metadata only"
	if !reflect.DeepEqual(before, migrated.RuntimeBehavior()) || !migrated.ShufflesExtensions() {
		t.Fatal("identity changed explicit policy")
	}
	clone := migrated.Clone()
	clone.Behavior["tls.handshake_retries"] = json.RawMessage("0")
	if migrated.Behavior.Int("tls.handshake_retries") != 1 {
		t.Fatal("cloning aliases behavior")
	}
	raw, err := clone.Save()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again.Behavior.Int("tls.handshake_retries") != 0 {
		t.Fatal("profile-only edit lost in round trip")
	}
	fresh := &Profile{EngineMajor: Major(1), Schema: 3, Name: "chrome", Base: "chrome_133", Behavior: map[string]json.RawMessage{}}
	if fresh.Chromium() || fresh.ShufflesExtensions() {
		t.Fatal("schema 3 inferred behavior from chrome name")
	}
}

func TestBehaviorRejectsInvalidDataAndUnavailableCapabilities(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{``, "requires an explicit behavior"},
		{`,"behavior":null`, "behavior must be an object"},
		{`,"behavior":{"tls.handshake_retires":1}`, "unsupported behavior field"},
		{`,"behavior":{"tls.handshake_retries":-1}`, "cannot unmarshal"},
		{`,"behavior":{"tls.handshake_retries":"1"}`, "cannot unmarshal"},
		{`,"behavior":{"tls.handshake_retries":1,"tls.handshake_retries":0}`, "duplicate behavior field"},
		{`,"behavior":{"h3.settings":[{"id":1,"value":1048577}]}`, "QPACK exceeds engine resource safety bound"},
		{`,"behavior":{"h3.settings":[{"id":7,"value":1025}]}`, "QPACK exceeds engine resource safety bound"},
		{`,"behavior":{"h3.settings":[{"id":1,"value":0},{"id":1,"value":0}]}`, "invalid/duplicate"},
		{`,"behavior":{"h3.settings":[{"id":1,"vaule":0}]}`, "unknown field"},
		{`,"behavior":{"h3.origin":true}`, "unsupported behavior field"},
		{`,"behavior":{"h3.qpack.huffman_names":"auto"}`, "unsupported primitive"},
		{`,"behavior":{"h3.qpack.huffman_values":true}`, "cannot unmarshal"},
		{`,"behavior":{"h3.qpack.huffman_values":null}`, "must not be null"},
		{`,"behavior":{"h3.qpack.huffman_names":"shorter","h3.qpack.huffman_names":"always"}`, "duplicate behavior field"},
		{`,"behavior":{"quic.enabled":true,"quic.versions":[1798521807]}`, "cross-version"},
		{`,"behavior":{"quic.preserve_extensions":[17613]}`, "ALPS bootstrap API is unavailable"},
		{`,"behavior":{"headers.renderer_order":"new-unimplemented-hash"}`, "unsupported primitive"},
		{`,"behavior":{"headers.renderer_initial_buckets":3}`, "power of two"},
		{`,"behavior":{"quic.max_udp_payload":1473}`, "must be in"},
		{`,"behavior":{"cache.entry_bytes":10,"cache.total_bytes":9}`, "exceeds total"},
		{`,"behavior":{"h1.missing_status":1000}`, "three digits"},
		{`,"behavior":{"http.content_codings":["unimplemented-codec"]}`, "API is unavailable"},
	} {
		raw := `{"engine_major":1,"schema":3,"name":"neutral","base":"chrome_133"` + tc.body + `}`
		_, err := Load([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", raw, err, tc.want)
		}
	}
}

func TestBehaviorControlsTransportWithoutFamilySwitch(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "neutral"
	p.UserAgent = "NeutralMetadata"
	p.Behavior["h2.header_frame_payload"] = []byte("1024")
	p.Behavior["h2.data_frame_payload"] = []byte("257")
	p.Behavior["h2.window_update_delay_ms"] = []byte("19")
	p.Behavior["tls.false_start"] = []byte("false")
	b, err := p.ClientProfile()
	if err != nil {
		t.Fatal(err)
	}
	if b.GetMaxHeaderFramePayload() != 1024 || b.GetMaxDataFramePayload() != 257 || b.GetWindowUpdateDelay().Milliseconds() != 19 || b.GetFalseStart() {
		t.Fatal("profile overrides did not reach transport")
	}
	if b.GetChromeBehavior() {
		t.Fatal("new profile still enables monolithic legacy switch")
	}
	if b.GetBehavior().Int("quic.initial_dcid_bytes") != 8 {
		t.Fatal("QUIC policy lost")
	}
}

func TestH3ControlPoliciesRejectInvalidRules(t *testing.T) {
	for name, value := range map[string]map[string]any{
		"empty-lengths":           {"h3.grease_payload_lengths": []uint64{}},
		"unbounded-payload":       {"h3.grease_payload_lengths": []uint64{4097}},
		"missing-settings":        {"h3.control_order": []string{"grease"}},
		"duplicate-settings":      {"h3.control_order": []string{"settings", "settings", "grease"}},
		"unknown-component":       {"h3.control_order": []string{"settings", "chrome", "grease"}},
		"missing-grease":          {"h3.control_order": []string{"settings"}},
		"initial-in-request-mode": {"h3.priority_updates": "per-request", "h3.control_order": []string{"settings", "priority", "grease"}},
		"unknown-mode":            {"h3.priority_updates": "snapshot"},
		"unknown-source":          {"h3.priority_source": "captured"},
	} {
		t.Run(name, func(t *testing.T) {
			p := LegacyBehavior()
			for k, v := range value {
				p[k], _ = json.Marshal(v)
			}
			if err := p.Validate(); err == nil {
				t.Fatal("invalid control policy accepted")
			}
		})
	}
}

func TestInitialH2ReadPolicyMustBeExplicitAndSupported(t *testing.T) {
	for _, raw := range []string{`null`, `true`, `1`, `"captured-delay"`} {
		p, err := Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		p.Behavior["h2.read_loop_start"] = json.RawMessage(raw)
		if err := p.validateBehavior(); err == nil {
			t.Fatalf("unsupported reader-start policy accepted: %s", raw)
		}
	}
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	delete(p.Behavior, "h2.read_loop_start")
	if err := p.validateBehavior(); err == nil {
		t.Fatal("missing engine7 reader-start policy inferred")
	}
}
