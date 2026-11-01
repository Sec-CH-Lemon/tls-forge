package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func networkPolicyJSON(t *testing.T) []byte {
	t.Helper()
	data, e := os.ReadFile("../networkquality/testdata/chromium156-nqe-source-candidate.json")
	if e != nil {
		t.Fatal(e)
	}
	return append(append([]byte(`{"mode":"estimated","policy":`), data...), '}')
}
func TestNetworkHintsPolicyStrictJSONAndNoLiteralFallback(t *testing.T) {
	good := networkPolicyJSON(t)
	var pol NetworkHintsPolicy
	if e := json.Unmarshal(good, &pol); e != nil {
		t.Fatal(e)
	}
	if pol.Mode != "estimated" || pol.Policy == nil {
		t.Fatal("missing rules")
	}
	for name, raw := range map[string][]byte{
		"not-object": []byte(`[]`), "wrong-mode-type": []byte(`{"mode":17}`),
		"null": []byte(`null`), "missing-mode": []byte(`{}`), "unknown-mode": []byte(`{"mode":"magic"}`), "case": []byte(`{"Mode":"literal"}`), "duplicate-mode": []byte(`{"mode":"literal","mode":"literal"}`), "null-policy": []byte(`{"mode":"estimated","policy":null}`), "missing-policy": []byte(`{"mode":"estimated"}`), "literal-with-policy": []byte(`{"mode":"literal","policy":{}}`),
		"missing-capacity": bytes.Replace(good, []byte(`"capacity": 300,`), nil, 1), "null-capacity": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"capacity": null`), 1), "duplicate-capacity": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"capacity": 300,"capacity":300`), 1), "case-capacity": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"Capacity": 300`), 1), "wrong-type": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"capacity": "300"`), 1), "unknown-param": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"capacity": 300,"invented":true`), 1), "unbounded": bytes.Replace(good, []byte(`"capacity": 300`), []byte(`"capacity": 65537`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var got NetworkHintsPolicy
			if e := json.Unmarshal(raw, &got); e == nil {
				t.Fatal("ambiguous or unsupported policy accepted")
			}
		})
	}
}

func TestNetworkHintsArchivedValuesAndExplicitLiteralMigration(t *testing.T) {
	p := mustGet(t, "chrome_156_macos").Clone()
	p.NetworkHints = &NetworkHintsPolicy{Mode: "literal"}
	p.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`)
	p.ClientHints = []Field{{Name: "rtt", Value: "-1"}}
	if p.validateNetworkHints() == nil {
		t.Fatal("programmatic malformed literal accepted")
	}
	raw, e := p.Save()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Inspect(raw); e == nil {
		t.Fatal("offline field inspection accepted invalid wire literal")
	}
	p = mustGet(t, "chrome_156_macos").Clone()
	p.NetworkHints.Policy.Algorithm = "unsupported"
	if p.validateNetworkHints() == nil {
		t.Fatal("invalid estimator policy accepted")
	}
	p = mustGet(t, "chrome_156_macos").Clone()
	p.NetworkHints = nil
	delete(p.Behavior, "headers.network_hints")
	p.ClientHints = []Field{{Name: "dpr", Value: "2"}, {Name: "rtt", Value: "50"}}
	migrated, e := p.Migrate("explicit-literal-candidate")
	if e != nil {
		t.Fatal(e)
	}
	if migrated.NetworkHints == nil || migrated.NetworkHints.Mode != "literal" || migrated.Behavior.Text("headers.network_hints") != "literal" || migrated.ClientHints[1].Value != "50" {
		t.Fatal("migration did not preserve selected literal semantics")
	}
	p = mustGet(t, "chrome_156_macos").Clone()
	delete(p.Behavior, "headers.network_hints")
	p.NetworkHints.Policy = nil
	if _, e = p.Migrate("invalid-candidate"); e == nil {
		t.Fatal("migration hid an invalid explicit policy")
	}
}

func TestNetworkHintsCloneSaveLoadAndConflicts(t *testing.T) {
	data, e := os.ReadFile("data/chrome_156/macos.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := Load(data)
	if e != nil {
		t.Fatal(e)
	}
	raw := networkPolicyJSON(t)
	var pol NetworkHintsPolicy
	if e := json.Unmarshal(raw, &pol); e != nil {
		t.Fatal(e)
	}
	p.NetworkHints = &pol
	p.Headers = nil
	p.ClientHints = nil
	clone := p.Clone()
	clone.NetworkHints.Policy.Metrics[0].Buffer.Capacity = 1
	if p.NetworkHints.Policy.Metrics[0].Buffer.Capacity != 300 {
		t.Fatal("mutable clone policy shared")
	}
	saved, e := p.Save()
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(saved, []byte(`"network_hints":`), []byte(`"NETWORK_HINTS":`), 1),
	} {
		if _, e := Load(bad); e == nil {
			t.Fatal("top-level case folding bypass")
		}
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(saved, &fields); e != nil {
		t.Fatal(e)
	}
	fields["network_hints"] = json.RawMessage(`null`)
	nullProfile, e := json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Load(nullProfile); e == nil {
		t.Fatal("explicit null erased policy selection")
	}
	loaded, e := Load(saved)
	if e != nil {
		t.Fatal(e)
	}
	if loaded.NetworkHints == nil || loaded.NetworkHints.Policy.Noise.SaltMax != 21 {
		t.Fatal("rules lost on save/load")
	}
	for _, name := range []string{"rtt", "downlink", "ECT"} {
		bad := p.Clone()
		bad.ClientHints = []Field{{Name: name, Value: "captured"}}
		if e := bad.Validate(); e == nil {
			t.Fatal("literal/generator conflict accepted", name)
		}
	}
	literal := p.Clone()
	literal.NetworkHints = &NetworkHintsPolicy{Mode: "literal"}
	literal.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`)
	literal.ClientHints = []Field{{Name: "rtt", Value: "100"}}
	if e := literal.Validate(); e != nil {
		t.Fatal(e)
	}
	literal.NetworkHints.Policy = pol.Policy
	if e := literal.Validate(); e == nil {
		t.Fatal("literal mode silently ignored generator")
	}
	bad := p.Clone()
	bad.NetworkHints.Policy = nil
	if e := bad.Validate(); e == nil {
		t.Fatal("missing estimator became literal")
	}
	bad.NetworkHints.Mode = "unsupported"
	if e := bad.Validate(); e == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestNetworkHintCapabilityIsMandatoryAndConsistent(t *testing.T) {
	p := mustGet(t, "chrome_156_macos")
	for name, change := range map[string]func(*Profile){
		"missing registry choice": func(p *Profile) { delete(p.Behavior, "headers.network_hints") },
		"no configuration":        func(p *Profile) { p.NetworkHints = nil },
		"different choice":        func(p *Profile) { p.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`) },
		"nil estimator":           func(p *Profile) { p.NetworkHints.Policy = nil },
		"http1 captured override": func(p *Profile) { p.HTTP1 = &HTTP1{Headers: []Field{{Name: "RTT", Value: "100"}}} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p.Clone()
			change(bad)
			if bad.Validate() == nil {
				t.Fatal("invalid executable capability accepted")
			}
		})
	}
	archived := p.Clone()
	delete(archived.Behavior, "headers.network_hints")
	archived.NetworkHints = nil
	archive, e := archived.Save()
	if e != nil {
		t.Fatal(e)
	}
	inspected, e := Inspect(archive)
	if e != nil {
		t.Fatal(e)
	}
	if inspected.NetworkHints != nil || inspected.Behavior.Has("headers.network_hints") {
		t.Fatal("offline save retagged capability")
	}
	if _, e = Load(archive); e == nil {
		t.Fatal("archive executed without capability")
	}
	migrated, e := inspected.Migrate("explicit-network-migration")
	if e != nil {
		t.Fatal(e)
	}
	if migrated.NetworkHints != nil || migrated.Behavior.Text("headers.network_hints") != "none" {
		t.Fatal("explicit migration invented network hints")
	}
	for _, name := range []string{"rtt", "downlink", "ECT"} {
		p := mustGet(t, "firefox_148").Clone()
		p.ClientHints = []Field{{Name: name, Value: "100"}}
		if p.Validate() == nil {
			t.Fatal("unselected literal bypass", name)
		}
	}
}

func TestLiteralNetworkHintsRejectMalformedWireValues(t *testing.T) {
	for name, values := range map[string][]string{
		"rtt":      {"", "-1", "1.0", "1e2", "1000000000000000", "NaN", "1\r\nX: a"},
		"downlink": {"", "-1", ".5", "1.", "1.0000", "1000000000000.0", "Inf", "1e2"},
		"ect":      {"", "offline", "unknown", "wifi", "4G", "\"4g\"", "4g;foo"},
	} {
		for _, value := range values {
			if validateLiteralNetworkHint(Field{Name: name, Value: value}) == nil {
				t.Fatal("invalid literal accepted", name, value)
			}
		}
	}
	for _, field := range []Field{{"rtt", "0"}, {"rtt", "999999999999999"}, {"downlink", "0.001"}, {"downlink", "999999999999.999"}, {"downlink", "10"}, {"ect", "slow-2g"}, {"ect", "2g"}, {"ect", "3g"}, {"ect", "4g"}, {"other", "unchanged"}} {
		if e := validateLiteralNetworkHint(field); e != nil {
			t.Fatal(e)
		}
	}
}
