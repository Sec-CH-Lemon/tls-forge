package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/igor-lemon/utls/behavior"
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

func TestFramingPolicyMustBeExplicitAndTyped(t *testing.T) {
	for _, key := range []string{"http.zero_content_length_methods", "http.content_length_empty_body", "h1.zero_length_identity", "h1.zero_length_identity_excluded_methods"} {
		p, err := Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		delete(p.Behavior, key)
		if p.validateBehavior() == nil {
			t.Fatal("missing framing choice inferred", key)
		}
		for _, raw := range []string{`null`, `1`, `"captured"`} {
			p, err := Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.Behavior[key] = json.RawMessage(raw)
			if p.validateBehavior() == nil {
				t.Fatal("invalid framing choice accepted", key, raw)
			}
		}
	}
}

// TestConnectionLifecyclePolicyIsTypedAndCoherent: the keep-alive, close and
// idle fields are refused with a wrong type, past their bounds, null, or
// without the field they depend on.
func TestConnectionLifecyclePolicyIsTypedAndCoherent(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"tcp.keepalive":"yes"}`, "cannot unmarshal"},
		{`{"tcp.keepalive_idle_seconds":45}`, "requires tcp.keepalive"},
		{`{"tcp.keepalive_count":0}`, "requires tcp.keepalive"},
		{`{"tcp.keepalive":false,"tcp.keepalive_idle_seconds":45}`, "while tcp.keepalive is false"},
		{`{"tcp.keepalive":false,"tcp.keepalive_interval_seconds":1}`, "while tcp.keepalive is false"},
		{`{"tcp.keepalive":true,"tcp.keepalive_idle_seconds":32768}`, "must be in"},
		{`{"tcp.keepalive":true,"tcp.keepalive_interval_seconds":32768}`, "must be in"},
		{`{"tcp.keepalive":true,"tcp.keepalive_count":128}`, "must be in"},
		{`{"tcp.keepalive":true,"tcp.keepalive_count":-1}`, "cannot unmarshal"},
		{`{"tls.close_notify":0}`, "cannot unmarshal"},
		{`{"h2.close_on_goaway":null}`, "must not be null"},
		{`{"h2.idle_connection_timeout_ms":-1}`, "cannot unmarshal"},
		{`{"h1.idle_connection_timeout_ms":4294967296}`, "must be in"},
		{`{"h1.idle_reap":"on-request"}`, "requires h1.idle_connection_timeout_ms"},
		{`{"h1.idle_reap":"lazy","h1.idle_connection_timeout_ms":1}`, "unsupported primitive"},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.body, err, tc.want)
		}
	}
	for _, body := range []string{
		`{"tcp.keepalive":false,"tcp.keepalive_idle_seconds":0,"tcp.keepalive_interval_seconds":0,"tcp.keepalive_count":0}`,
		`{"tcp.keepalive":true}`,
		`{"tcp.keepalive":true,"tcp.keepalive_idle_seconds":32767,"tcp.keepalive_interval_seconds":32767,"tcp.keepalive_count":127}`,
		`{"h1.idle_connection_timeout_ms":0,"h1.idle_reap":"timer","h2.idle_connection_timeout_ms":4294967295}`,
		`{"tls.close_notify":true,"h2.close_on_goaway":false}`,
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// TestPrefacePingPolicyIsTypedAndCoherent: the connection's own PING, its
// count, when a connection is given up, the GOAWAY it says and how often a
// request goes again are typed, bounded, and said only with what they
// depend on.
func TestPrefacePingPolicyIsTypedAndCoherent(t *testing.T) {
	long := `"` + strings.Repeat("x", 1025) + `"`
	for _, tc := range []struct{ body, want string }{
		{`{"h2.preface_ping_idle_ms":-1}`, "cannot unmarshal"},
		{`{"h2.preface_ping_idle_ms":4294967296,"h2.preface_ping_first_id":1}`, "must be in"},
		{`{"h2.preface_ping_idle_ms":10000}`, "requires h2.preface_ping_first_id"},
		{`{"h2.preface_ping_first_id":1}`, "requires h2.preface_ping_idle_ms"},
		{`{"h2.preface_ping_hung_ms":10000}`, "requires h2.preface_ping_idle_ms"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_first_id":18446744073709551616}`, "cannot unmarshal"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":4294967296}`, "must be in"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_failed_retries":1}`, "requires h2.preface_ping_hung_ms"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_failed_goaway_code":1}`, "requires h2.preface_ping_hung_ms"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_retries":17}`, "must be in"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_goaway_code":4294967296}`, "must be in"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_goaway_debug":"x"}`, "requires h2.preface_ping_failed_goaway_code"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_goaway_code":1,"h2.preface_ping_failed_goaway_debug":"a\nb"}`, "control byte"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_goaway_code":1,"h2.preface_ping_failed_goaway_debug":` + long + `}`, "exceeds 1024"},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.120s: %v, want %q", tc.body, err, tc.want)
		}
	}
	for _, body := range []string{
		`{"h2.preface_ping_idle_ms":0}`,
		`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":0,"h2.preface_ping_failed_retries":0}`,
		`{"h2.preface_ping_idle_ms":4294967295,"h2.preface_ping_first_id":18446744073709551615}`,
		`{"h2.preface_ping_idle_ms":10000,"h2.preface_ping_first_id":0,"h2.preface_ping_hung_ms":4294967295,"h2.preface_ping_failed_retries":16,"h2.preface_ping_failed_goaway_code":4294967295,"h2.preface_ping_failed_goaway_debug":""}`,
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// TestEveryShippedChromeProfilePingsAsChrome pins the shipped data to
// Chrome's SpdySession and HttpNetworkTransaction: a PING after 10 s of
// reading nothing, the first saying 1, a connection given up 10 s after it
// with GOAWAY PROTOCOL_ERROR "Failed ping.", and a request sent again twice
// at most.
func TestEveryShippedChromeProfilePingsAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"h2.preface_ping_idle_ms":             "10000",
		"h2.preface_ping_first_id":            "1",
		"h2.preface_ping_hung_ms":             "10000",
		"h2.preface_ping_failed_goaway_code":  "1",
		"h2.preface_ping_failed_goaway_debug": `"Failed ping."`,
		"h2.preface_ping_failed_retries":      "2",
	}
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		b := p.RuntimeBehavior()
		for k, v := range want {
			if string(b[k]) != v {
				t.Errorf("%s: %s is %s, want %s", name, k, b[k], v)
			}
		}
	}
}

// TestEveryShippedChromeProfileKeepsItsConnectionsAsChrome pins the shipped
// data: Chrome's TCP keep-alive (45 s; the interval Linux's and Windows's 45 s,
// macOS's the system's), no close_notify, an HTTP/2 session with no idle timer
// closed once a GOAWAY leaves it no stream, an HTTP/1.1 socket kept 300 s and
// reaped when a socket is asked for; and no single idle timeout for both.
func TestEveryShippedChromeProfileKeepsItsConnectionsAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		b := p.RuntimeBehavior()
		interval := uint64(45)
		if strings.HasSuffix(name, "macos.json") {
			interval = 0
		}
		if !b.Flag("tcp.keepalive") || b.Uint("tcp.keepalive_idle_seconds") != 45 || b.Uint("tcp.keepalive_interval_seconds") != interval ||
			!b.Has("tcp.keepalive_count") || b.Uint("tcp.keepalive_count") != 0 {
			t.Errorf("%s: keep-alive %s %s %s %s", name, b["tcp.keepalive"], b["tcp.keepalive_idle_seconds"], b["tcp.keepalive_interval_seconds"], b["tcp.keepalive_count"])
		}
		if !b.Has("tls.close_notify") || b.Flag("tls.close_notify") || !b.Flag("h2.close_on_goaway") {
			t.Errorf("%s: close_notify %s, close on GOAWAY %s", name, b["tls.close_notify"], b["h2.close_on_goaway"])
		}
		if !b.Has("h2.idle_connection_timeout_ms") || b.Uint("h2.idle_connection_timeout_ms") != 0 ||
			b.Uint("h1.idle_connection_timeout_ms") != 300000 || b.Text("h1.idle_reap") != "on-request" || b.Has("http.idle_connection_timeout_ms") {
			t.Errorf("%s: idle %s/%s/%s, both %s", name, b["h1.idle_connection_timeout_ms"], b["h1.idle_reap"], b["h2.idle_connection_timeout_ms"], b["http.idle_connection_timeout_ms"])
		}
	}
}
