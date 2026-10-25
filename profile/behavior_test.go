package profile

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
		{`,"behavior":{"quic.preserve_extensions":[17613]}`, "quic.alps_protocols goes with an application_settings extension"},
		{`,"behavior":{"quic.preserve_extensions":[17513,17613],"quic.alps_protocols":["h3"]}`, "keeps both ALPS codepoints"},
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
// count, when a connection is given up and the GOAWAY it says are typed,
// bounded, and said only with what they depend on.
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
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_failed_goaway_code":1}`, "requires h2.preface_ping_hung_ms"},
		{`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,"h2.preface_ping_failed_retries":2}`, "unsupported behavior field"},
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
		`{"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":0}`,
		`{"h2.preface_ping_idle_ms":4294967295,"h2.preface_ping_first_id":18446744073709551615}`,
		`{"h2.preface_ping_idle_ms":10000,"h2.preface_ping_first_id":0,"h2.preface_ping_hung_ms":4294967295,"h2.preface_ping_failed_goaway_code":4294967295,"h2.preface_ping_failed_goaway_debug":""}`,
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

// TestRetryPolicyIsTypedAndCoherent: how many times a request goes again, for
// which HTTP/2 failures, after how long, how many times after a lost
// connection and by which methods, and whether after a 408: typed, bounded,
// each failure known and named once, and said only with what it depends on.
func TestRetryPolicyIsTypedAndCoherent(t *testing.T) {
	const ping = `"h2.preface_ping_idle_ms":0,"h2.preface_ping_hung_ms":1,`
	for _, tc := range []struct{ body, want string }{
		{`{"h2.retries":17,"h2.retry_errors":[]}`, "must be in"},
		{`{"h2.retries":-1,"h2.retry_errors":[]}`, "cannot unmarshal"},
		{`{"h2.retries":2}`, "go together"},
		{`{"h2.retry_errors":["refused-stream"]}`, "go together"},
		{`{"h2.retries":2,"h2.retry_errors":"refused-stream"}`, "cannot unmarshal"},
		{`{"h2.retries":2,"h2.retry_errors":["refused"]}`, "unknown or repeated"},
		{`{"h2.retries":2,"h2.retry_errors":["refused-stream","refused-stream"]}`, "unknown or repeated"},
		{`{"h2.retries":2,"h2.retry_errors":["ping-failed"]}`, "names ping-failed while no PING is given up"},
		{`{"h2.retry_delay_ms":0}`, "requires h2.retries"},
		{`{"h2.retries":2,"h2.retry_errors":[],"h2.retry_delay_ms":60001}`, "must be in"},
		{`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_retries":1001,"http.connection_error_methods":"any"}`, "must be in"},
		{`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_retries":50}`, "go together"},
		{`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_methods":"any"}`, "go together"},
		{`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_retries":50,"http.connection_error_methods":"post"}`, "unsupported primitive"},
		{`{"http.connection_error_retries":50,"http.connection_error_methods":"any"}`, "requires h2.retries"},
		{`{"h1.request_timeout_resend":1}`, "cannot unmarshal"},
		{`{"h1.request_timeout_resend":null}`, "must not be null"},
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
		`{"h2.retries":0,"h2.retry_errors":[]}`,
		`{"h2.retries":16,"h2.retry_errors":["refused-stream","goaway-no-error","goaway-error"],"h2.retry_delay_ms":60000}`,
		`{` + ping + `"h2.retries":2,"h2.retry_errors":["ping-failed"]}`,
		`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_retries":0,"http.connection_error_methods":"idempotent"}`,
		`{"h2.retries":2,"h2.retry_errors":[],"http.connection_error_retries":1000,"http.connection_error_methods":"any"}`,
		`{"h1.request_timeout_resend":false}`,
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

// TestPriorityDependencyIsAChoiceOfTheEngines: "root" or "nearest-weight",
// nothing else.
func TestPriorityDependencyIsAChoiceOfTheEngines(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"h2.priority_dependency":"chain"}`, "unsupported primitive"},
		{`{"h2.priority_dependency":""}`, "unsupported primitive"},
		{`{"h2.priority_dependency":1}`, "cannot unmarshal"},
		{`{"h2.priority_dependency":null}`, "must not be null"},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.body, err, tc.want)
		}
	}
	for _, body := range []string{`{"h2.priority_dependency":"root"}`, `{"h2.priority_dependency":"nearest-weight"}`} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// TestUnreadAnswerPolicyIsTypedAndCoherent: how an answer a request goes on
// from is let go of is one of the engine's ways for each kind and protocol,
// and its limits, its wait and the graces are said with the ways that use
// them, and only then.
func TestUnreadAnswerPolicyIsTypedAndCoherent(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"h2.dropped_body":"reset"}`, "unsupported primitive"},
		{`{"h1.auth_body":""}`, "unsupported primitive"},
		{`{"h1.preflight_body":1}`, "cannot unmarshal"},
		{`{"h2.restart_body":null}`, "must not be null"},
		{`{"h3.dropped_body":"close"}`, "unsupported behavior field"},
		{`{"h1.dropped_body":"drain"}`, "requires http.drain_bytes"},
		{`{"h1.dropped_body":"drain","http.drain_bytes":16384}`, "requires http.drain_ms"},
		{`{"h2.auth_body":"drain","http.drain_ms":5000}`, "requires http.drain_bytes"},
		{`{"http.drain_bytes":16384,"http.drain_ms":5000}`, "while no answer is let go of by drain"},
		{`{"h1.dropped_body":"close","http.drain_ms":5000}`, "while no answer is let go of by drain"},
		{`{"h1.dropped_body":"drain","http.drain_bytes":1073741825,"http.drain_ms":5000}`, "must be in"},
		{`{"h1.dropped_body":"drain","http.drain_bytes":16384,"http.drain_ms":4294967296}`, "must be in"},
		{`{"h2.preflight_body":"first-bytes"}`, "requires http.first_bytes_ms"},
		{`{"http.first_bytes_ms":0}`, "while no answer is let go of by first-bytes"},
		{`{"h1.preflight_body":"first-bytes","http.first_bytes_ms":-1}`, "cannot unmarshal"},
		{`{"h1.unread_grace_us":1000}`, "h1.unread_grace_us is set while no answer over it is let go of"},
		{`{"h2.dropped_body":"close","h1.unread_grace_us":1000}`, "h1.unread_grace_us is set while"},
		{`{"h1.dropped_body":"read-all","h1.unread_grace_us":1000}`, "h1.unread_grace_us is set while"},
		{`{"h2.dropped_body":"read","h2.unread_grace_us":1000}`, "h2.unread_grace_us is set while"},
		{`{"h2.dropped_body":"close","h2.unread_grace_us":10000001}`, "must be in"},
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
		`{"h1.dropped_body":"read","h2.dropped_body":"read-all","h1.auth_body":"read","h2.auth_body":"read-all"}`,
		`{"h1.dropped_body":"drain","h2.auth_body":"drain","http.drain_bytes":0,"http.drain_ms":0}`,
		`{"h1.dropped_body":"drain","http.drain_bytes":1073741824,"http.drain_ms":4294967295}`,
		`{"h1.preflight_body":"first-bytes","h2.restart_body":"first-bytes","http.first_bytes_ms":4294967295}`,
		`{"h1.restart_body":"close","h1.unread_grace_us":0,"h2.preflight_body":"close","h2.unread_grace_us":10000000}`,
		`{"h1.preflight_body":"first-bytes","http.first_bytes_ms":0,"h1.unread_grace_us":2000}`,
		`{"h2.dropped_body":"drain","http.drain_bytes":1,"http.drain_ms":1,"h2.unread_grace_us":1}`,
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

// TestEveryShippedChromeProfileLetsGoOfAnswersAsChrome pins the shipped data
// to what Chrome 155.0.8059.85 was measured to do with an answer it goes on
// from unread (HttpNetworkTransaction, HttpResponseBodyDrainer, the
// preflight's SimpleURLLoader): over HTTP/2 every such stream reset at once
// but a preflight's, let go of at its first bytes; over HTTP/1.1 a redirect's
// body drained, 16 KiB within 5 s, a 401's read whole, a restarted
// navigation's connection closed, a preflight's let go of at its first bytes
// however long they take; what comes within 2 ms (HTTP/1.1) or 0.5 ms
// (HTTP/2) of what came read as come already.
func TestEveryShippedChromeProfileLetsGoOfAnswersAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"h1.dropped_body":     `"drain"`,
		"h2.dropped_body":     `"close"`,
		"h1.auth_body":        `"read-all"`,
		"h2.auth_body":        `"close"`,
		"h1.restart_body":     `"close"`,
		"h2.restart_body":     `"close"`,
		"h1.preflight_body":   `"first-bytes"`,
		"h2.preflight_body":   `"first-bytes"`,
		"http.drain_bytes":    "16384",
		"http.drain_ms":       "5000",
		"http.first_bytes_ms": "0",
		"h1.unread_grace_us":  "2000",
		"h2.unread_grace_us":  "500",
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

// TestEveryShippedChromeProfileChainsItsStreamsAsChrome pins the shipped data
// to Chrome's Http2PriorityDependencies.
func TestEveryShippedChromeProfileChainsItsStreamsAsChrome(t *testing.T) {
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
		if got := p.RuntimeBehavior().Text("h2.priority_dependency"); got != "nearest-weight" {
			t.Errorf("%s: h2.priority_dependency %q", name, got)
		}
	}
}

// TestEveryShippedChromeProfilePingsAsChrome pins the shipped data to
// Chrome's SpdySession: a PING after 10 s of reading nothing, the first
// saying 1, and a connection given up 10 s after it with GOAWAY
// PROTOCOL_ERROR "Failed ping.".
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

// TestEveryShippedChromeProfileRetriesAsChrome pins the shipped data to
// Chrome's HttpNetworkTransaction (kMaxRetryAttempts,
// kMaxRetryAttemptsOnConnectionErrors, ShouldResendRequest and the 408 of
// DoReadHeadersComplete) and SpdySession (OnRstStream, OnGoAway), as
// measured: a request goes again at once, twice at most, after a refused
// stream, a GOAWAY with NO_ERROR above it or a PING not answered, never
// after a GOAWAY with another code; 50 times at most after a reused
// connection was lost, whatever its method; and after a 408 on a reused
// HTTP/1.1 connection.
func TestEveryShippedChromeProfileRetriesAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"h2.retries":                    "2",
		"h2.retry_errors":               `["refused-stream","goaway-no-error","ping-failed"]`,
		"h2.retry_delay_ms":             "0",
		"http.connection_error_retries": "50",
		"http.connection_error_methods": `"any"`,
		"h1.request_timeout_resend":     "true",
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
		if b.Has("h2.preface_ping_failed_retries") {
			t.Errorf("%s: still says h2.preface_ping_failed_retries", name)
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

// TestGivenFieldsPolicyIsTypedAndCoherent: where a request's own fields go
// that Chrome has no slot for is said in every order of a page's request or
// in none, once; how they go there, what a redirect takes of them and a
// request without a context sent as a typed navigation only with it; the
// Priority of a browser's request by what it is for only with the weights of
// each urgency, eight of them.
func TestGivenFieldsPolicyIsTypedAndCoherent(t *testing.T) {
	orders := func(withGiven ...string) string {
		var out []string
		for _, key := range []string{"navigation_order", "form_order", "redirected_order", "restarted_order"} {
			list := `["accept"]`
			if slices.Contains(withGiven, key) {
				list = `["@given","accept"]`
			}
			out = append(out, `"headers.`+key+`":`+list)
		}
		return strings.Join(out, ",")
	}
	all := orders("navigation_order", "form_order", "redirected_order", "restarted_order")
	const context = `"headers.browser_context":true,"headers.alps_after":"accept","headers.renderer_initial_buckets":8,` +
		`"headers.renderer_load_denominator":2,`
	for _, tc := range []struct{ body, want string }{
		{`{` + orders("navigation_order") + `}`, "@given is in some of"},
		{`{` + orders("navigation_order", "form_order", "redirected_order") + `}`, "@given is in some of"},
		{`{"headers.navigation_order":["@given","@given"]}`, "names @given more than once"},
		{`{"headers.given_order":"bytes"}`, "requires @given"},
		{`{` + all + `,"headers.given_order":"sorted"}`, "unsupported primitive"},
		{`{"headers.given_redirect_drops":["cookie"]}`, "requires @given"},
		{`{` + all + `,"headers.given_redirect_drops":["Cookie"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":[""]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a:b"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a b"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a\tb"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["@given"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a\rb"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a\nb"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.given_redirect_drops":["a\u0000b"]}`, "not a field name in lower case"},
		{`{` + all + `,"headers.without_context":"typed-navigation"}`, "requires headers.browser_context"},
		{`{` + context + orders() + `,"headers.without_context":"typed-navigation"}`, "requires @given"},
		{`{"headers.without_context":"navigation"}`, "unsupported primitive"},
		{`{"h2.urgency_weights":[255]}`, "a weight for each urgency"},
		{`{"h2.urgency_weights":[256,0,0,0,0,0,0,0]}`, "is no weight on the wire"},
		{`{"headers.sent_priority":["document=u=0"]}`, "requires h2.urgency_weights"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["document"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["=u=0"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["a=i","a=u=1"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["Image=i"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["im age=i"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["im\tage=i"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["image,font=i"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["image;x=i"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["image=i\r"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["image=i\n"]}`, "destination=Priority said once"},
		{`{"h2.urgency_weights":[1,1,1,1,1,1,1,1],"headers.sent_priority":["image=i\u0000"]}`, "destination=Priority said once"},
		{`{"headers.renderer_origin_dests":"font"}`, "cannot unmarshal"},
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
		`{` + all + `}`,
		`{` + all + `,"headers.given_order":"as-given","headers.given_redirect_drops":[]}`,
		`{` + context + all + `,"headers.without_context":"typed-navigation"}`,
		`{"headers.without_context":"as-given"}`,
		`{"h2.urgency_weights":[255,219,182,146,109,73,36,0],"headers.sent_priority":["script=","empty=u=1, i"]}`,
		`{"headers.renderer_origin_dests":["font"]}`,
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

// TestEveryShippedChromeProfileGivesFieldsAsChrome: a request without a
// context is a typed navigation, and what it is given goes where Chrome
// 155.0.8059.85 writes it (testdata/chrome155-given.json); a browser's
// request the Priority of what it is for (testdata/chrome155-subresources.json).
func TestEveryShippedChromeProfileGivesFieldsAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"headers.without_context":      `"typed-navigation"`,
		"headers.given_order":          `"bytes"`,
		"headers.given_redirect_drops": `["cookie"]`,
		"headers.navigation_order": `["pragma","cache-control","authorization","@hints","upgrade-insecure-requests",` +
			`"user-agent","@given","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer",` +
			`"accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]`,
		"headers.form_order": `["content-length","pragma","cache-control","authorization","@hints",` +
			`"upgrade-insecure-requests","content-type","user-agent","origin","@given","accept","sec-fetch-site",` +
			`"sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie",` +
			`"if-none-match","if-modified-since","priority"]`,
		"headers.redirected_order": `["content-length","pragma","cache-control","authorization",` +
			`"upgrade-insecure-requests","content-type","user-agent","origin","@given","accept","sec-fetch-site",` +
			`"sec-fetch-mode","sec-fetch-user","sec-fetch-dest","@hints","referer","accept-encoding","accept-language",` +
			`"cookie","if-none-match","if-modified-since","priority"]`,
		"headers.restarted_order": `["pragma","cache-control","authorization","upgrade-insecure-requests","user-agent",` +
			`"@given","accept","@hints","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer",` +
			`"accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]`,
		"headers.script_trailing": `["referer","accept-encoding","accept-language","cookie","if-none-match",` +
			`"if-modified-since","range","priority"]`,
		"headers.sent_priority": `["document=u=0, i","iframe=u=0, i","style=u=0","font=u=0","image=i","script=",` +
			`"empty=u=1, i"]`,
		"h2.urgency_weights":            `[255,219,182,146,109,73,36,0]`,
		"headers.renderer_origin_dests": `["font"]`,
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

// TestReloadPolicyIsTypedAndCoherent: how Chrome reloads a page (Ctrl+R) is
// said whole, a form posted again in an order where the ALPS hints have their
// anchor.
func TestReloadPolicyIsTypedAndCoherent(t *testing.T) {
	const context = `"headers.browser_context":true,"headers.alps_after":"accept",` +
		`"headers.renderer_initial_buckets":8,"headers.renderer_load_denominator":2,` +
		`"headers.navigation_order":["accept"],"headers.form_order":["accept"],` +
		`"headers.redirected_order":["accept"],"headers.restarted_order":["accept"],`
	const user = `"headers.navigation_fetch_user":"?1",`
	for _, tc := range []struct{ body, want string }{
		{`{` + user + `"headers.reload_cache_control":"max-age=0"}`, "are said together"},
		{`{` + user + `"headers.form_reload_order":["accept"]}`, "are said together"},
		{`{"headers.reload_cache_control":"max-age=0","headers.form_reload_order":["accept"]}`, "are said together"},
		{`{` + user + `"headers.reload_cache_control":0,"headers.form_reload_order":["accept"]}`, "cannot unmarshal"},
		{`{` + user + `"headers.reload_cache_control":"max-age=0\r","headers.form_reload_order":["accept"]}`,
			"control byte"},
		{`{` + user + `"headers.reload_cache_control":"max-age=0","headers.form_reload_order":"accept"}`,
			"cannot unmarshal"},
		{`{` + context + user + `"headers.reload_cache_control":"max-age=0","headers.form_reload_order":["origin"]}`,
			"headers.form_reload_order is missing ALPS anchor accept"},
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
		`{}`,
		`{` + user + `"headers.reload_cache_control":"max-age=0","headers.form_reload_order":["origin"]}`,
		`{` + context + user + `"headers.reload_cache_control":"max-age=0","headers.form_reload_order":["accept"]}`,
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

// TestEveryShippedChromeProfileReloadsAsChrome: a page reloaded asks for
// itself afresh, and a form posted again has its Content-Type after Origin, as
// Chrome 155.0.8059.85 sends them (testdata/chrome155-reload.json).
func TestEveryShippedChromeProfileReloadsAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"headers.navigation_fetch_user": `"?1"`,
		"headers.reload_cache_control":  `"max-age=0"`,
		"headers.form_reload_order": `["content-length","pragma","cache-control","authorization","@hints",` +
			`"upgrade-insecure-requests","user-agent","origin","content-type","accept","sec-fetch-site",` +
			`"sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie",` +
			`"if-none-match","if-modified-since","priority"]`,
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

// TestEveryShippedChromeProfileOffersECHAsChrome pins the shipped data: the
// addresses and the HTTPS records of a direct connection's name asked by a
// client of its own (Chrome's built-in DNS client) and waited for as
// Chrome's host resolver does, plain http sent to https by one, and ECH
// offered with their configs as Chrome 155's BoringSSL offers it, measured
// (testdata/chrome155-ech-dns.json).
func TestEveryShippedChromeProfileOffersECHAsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	want := map[string]string{
		"dns.https_records":          "true",
		"dns.https_wait_percent":     "20",
		"dns.https_wait_min_ms":      "5",
		"dns.https_wait_max_ms":      "50",
		"dns.https_upgrade":          "true",
		"dns.resolver":               `"built-in"`,
		"tls.ech":                    "true",
		"tls.ech_inner_own":          "[0,43,65037]",
		"tls.ech_inner_omitted":      "[11,23,35,65281]",
		"tls.ech_inner_min_version":  "772",
		"tls.ech_padding_block":      "32",
		"tls.ech_kems":               "[32]",
		"tls.ech_kdfs":               "[1]",
		"tls.ech_aeads":              "[1,2,3]",
		"tls.ech_chacha_without_aes": "true",
		"tls.ech_outer_psk":          `"none"`,
		"tls.ech_retries":            "1",
		"tls.ech_retry_without":      "true",
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

func TestEveryShippedChromeProfileGoesOverHTTP3AsChrome(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("data", "chrome_15*", "*.json"))
	if err != nil || len(names) != 15 {
		t.Fatalf("%d shipped Chrome profiles: %v", len(names), err)
	}
	// Chromium 155's DNS ALPN job, measured on macOS (bench/h3) and read in
	// its source (GetTimeDelayForWaitingJob, BrokenAlternativeServices,
	// unused_idle_socket_timeout).
	want := map[string]string{
		"dns.https_h3":                           "true",
		"quic.tcp_wait_cold_ms":                  "0",
		"quic.tcp_wait_broken_ms":                "0",
		"quic.tcp_wait_rtt_percent":              "150",
		"quic.tcp_wait_default_ms":               "300",
		"quic.tcp_wait_extra_ms":                 "0",
		"quic.tcp_wait_max_ms":                   "3000",
		"quic.tcp_waits_with_connection":         "false",
		"quic.broken_ms":                         "300000",
		"quic.broken_doublings":                  "18",
		"quic.broken_max_ms":                     "172800000",
		"quic.broken_recent_max":                 "200",
		"quic.server_rtts_max":                   "500",
		"http.unused_idle_connection_timeout_ms": "60000",
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

func TestHTTP3FromDNSPolicyOfAProfileIsTypedAndCoherent(t *testing.T) {
	// A profile file is refused for an HTTP/3 field the engine cannot do as
	// said, before anything is sent.
	for _, tc := range []struct{ body, want string }{
		{`{"dns.https_h3":true}`, "dns.https_h3 requires dns.https_records"},
		{`{"quic.broken_ms":300000}`, "is set while dns.https_h3 is not"},
		{`{"dns.https_h3":"yes"}`, "dns.https_h3"},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.body, err, tc.want)
		}
	}
}

func TestECHPolicyOfAProfileIsTypedAndCoherent(t *testing.T) {
	// A profile file is refused for an ECH or HTTPS record field the engine
	// cannot do as said, before anything is sent.
	for _, tc := range []struct{ body, want string }{
		{`{"tls.ech":true}`, "tls.ech requires tls.ech_inner_own"},
		{`{"tls.ech_retries":1}`, "is set while tls.ech is not"},
		{`{"dns.https_wait_percent":20}`, "is set while dns.https_records is not"},
		{`{"dns.https_upgrade":true}`, "dns.https_upgrade requires dns.https_records"},
		{`{"dns.https_records":true,"dns.https_wait_percent":20,"dns.https_wait_min_ms":60,"dns.https_wait_max_ms":50,"dns.resolver":"built-in"}`, "exceeds"},
		{`{"dns.https_records":true,"dns.https_wait_percent":20,"dns.https_wait_min_ms":5,"dns.https_wait_max_ms":50}`, "dns.https_records requires dns.resolver built-in"},
		{`{"dns.resolver":"getaddrinfo"}`, "unsupported primitive"},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.body, err, tc.want)
		}
	}
}

func TestARuntimeBehaviorIsTheProfilesOwnOrTheLegacyData(t *testing.T) {
	var none *Profile
	if none.RuntimeBehavior() != nil {
		t.Error("a nil profile has a behavior")
	}
	// Before schema 3 a Chromium profile reads the frozen legacy data, which
	// answers Negotiate on Windows alone; schema 3 says its own or has none.
	for platform, negotiates := range map[string]bool{"windows": true, "macos": false, "linux": false} {
		old := &Profile{EngineMajor: Major(1), Schema: 2, Name: "chrome_155_" + platform}
		if got := old.RuntimeBehavior().Flag("http.negotiate_auth"); got != negotiates {
			t.Errorf("%s: negotiates %v, want %v", platform, got, negotiates)
		}
	}
	if (&Profile{EngineMajor: Major(1), Schema: 3, Name: "chrome_155_windows"}).RuntimeBehavior() != nil {
		t.Error("a schema 3 profile without its own data has one")
	}
}

func TestAProfileWithoutAFieldThisEngineReadsIsRefused(t *testing.T) {
	data, err := mustGet(t, "chrome_155_macos").Save()
	if err != nil {
		t.Fatal(err)
	}
	var fields, pol map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields["behavior"], &pol); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		change func(map[string]json.RawMessage)
		want   string
	}{
		{func(b map[string]json.RawMessage) { delete(b, "http.max_site_pools") }, "requires http.max_site_pools"},
		{func(b map[string]json.RawMessage) { delete(b, "cache.entries") }, "requires cache.entries"},
		{func(b map[string]json.RawMessage) { delete(b, "h3.qpack.critical_close_reason") }, "requires h3.qpack.critical_close_reason"},
		{func(b map[string]json.RawMessage) { b["tls.ech_payload_lengths"] = json.RawMessage("[144]") }, "ECH lengths belong in per_connection"},
	} {
		changed := maps.Clone(pol)
		tc.change(changed)
		fields["behavior"], _ = json.Marshal(changed)
		raw, _ := json.Marshal(fields)
		if _, err := Load(raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
	// Without its own behavior a schema 3 profile is neither worn nor saved.
	bare := &Profile{EngineMajor: Major(1), Schema: 3, Name: "neutral", Base: "chrome_133"}
	if _, err := bare.ClientProfile(); err == nil || !strings.Contains(err.Error(), "requires an explicit behavior") {
		t.Errorf("worn: %v", err)
	}
	if _, err := bare.Save(); err == nil || !strings.Contains(err.Error(), "behavior is incomplete") {
		t.Errorf("saved: %v", err)
	}
}
