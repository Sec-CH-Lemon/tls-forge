package profile

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutableHTTP2Semantics(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		edit       func(*Profile)
	}{
		{"small frame", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{5, 1}} }},
		{"frame below minimum", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{5, 16383}} }},
		{"large frame", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{5, 1 << 24}} }},
		{"large window", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{4, 1 << 31}} }},
		{"push boolean", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{2, 2}} }},
		{"connect boolean", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{8, 2}} }},
		{"priorities boolean", "http2.settings[0].value", func(p *Profile) { p.HTTP2.Settings = []Setting{{9, 2}} }},
		{"duplicate ID", "http2.settings[1].id", func(p *Profile) { p.HTTP2.Settings = []Setting{{4, 1}, {4, 2}} }},
		{"duplicate equal ID", "http2.settings[1].id", func(p *Profile) { p.HTTP2.Settings = []Setting{{4, 1}, {4, 1}} }},
		{"even request", "http2.stream_id", func(p *Profile) { p.HTTP2.StreamID = 2 }},
		{"reserved request bit", "http2.stream_id", func(p *Profile) { p.HTTP2.StreamID = 1 << 31 }},
		{"self dependency", "http2.header_priority.depends_on", func(p *Profile) { p.HTTP2.HeaderPriority.DependsOn = 1 }},
		{"reserved dependency", "http2.header_priority.depends_on", func(p *Profile) { p.HTTP2.HeaderPriority.DependsOn = 1 << 31 }},
		{"priority zero", "http2.priorities[0].stream_id", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: 0}} }},
		{"priority even", "http2.priorities[0].stream_id", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: 2}} }},
		{"priority overflow", "http2.priorities[0].stream_id", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: math.MaxInt32}} }},
		{"priority self", "http2.priorities[0].depends_on", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: 3, DependsOn: 3}} }},
		{"priority reserved dependency", "http2.priorities[0].depends_on", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: 3, DependsOn: 1 << 31}} }},
		{"effective first stream self", "http2.header_priority.depends_on", func(p *Profile) { p.HTTP2.Priorities = []Priority{{StreamID: 3}}; p.HTTP2.HeaderPriority.DependsOn = 5 }},
		{"flow overflow", "http2.connection_flow", func(p *Profile) { p.HTTP2.ConnectionFlow = math.MaxInt32 - 65535 + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustGet(t, "chrome_155_macos").Clone()
			p.Name = "neutral-f01"
			tc.edit(p)
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Inspect(data); err != nil {
				t.Fatalf("offline Inspect must preserve representable archive: %v", err)
			}
			file := filepath.Join(t.TempDir(), "renamed.json")
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			for name, run := range map[string]func() error{
				"Load":          func() error { _, e := Load(data); return e },
				"file registry": func() error { _, e := NewRegistry().Get(file); return e },
				"Register":      func() error { return NewRegistry().Register(p) },
				"adapter":       func() error { _, e := p.ClientProfile(); return e },
				"Spec":          func() error { _, e := p.Spec(); return e },
			} {
				err := run()
				if err == nil || !strings.Contains(err.Error(), p.Name) || !strings.Contains(err.Error(), tc.path) {
					t.Errorf("%s: %v; want profile and %s", name, err, tc.path)
				}
			}
		})
	}
}

func TestValidHTTP2SemanticEdgesPreserveValues(t *testing.T) {
	for _, setting := range []Setting{{4, 0}, {4, math.MaxInt32}, {5, 16384}, {5, 1<<24 - 1}, {1, 0}, {1, math.MaxUint32}, {3, 0}, {3, math.MaxUint32}, {6, 0}, {6, math.MaxUint32}, {2, 0}, {2, 1}, {8, 0}, {8, 1}, {9, 0}, {9, 1}, {65535, math.MaxUint32}} {
		p := mustGet(t, "chrome_155_macos").Clone()
		p.HTTP2.Settings = []Setting{setting}
		p.HTTP2.ConnectionFlow = math.MaxInt32 - 65535
		p.HTTP2.StreamID = math.MaxInt32
		p.HTTP2.HeaderPriority = nil
		data, _ := json.Marshal(p)
		loaded, err := Load(data)
		if err != nil {
			t.Fatal(setting, err)
		}
		cp, err := loaded.ClientProfile()
		if err != nil || len(cp.GetSettings()) != 1 {
			t.Fatal(setting, err)
		}
		for _, v := range cp.GetSettings() {
			if v != setting.Value {
				t.Fatal("setting normalized", setting, v)
			}
		}
	}
}

func TestExecutableJSONCannotHideSettings(t *testing.T) {
	p := mustGet(t, "chrome_155_macos")
	data, _ := json.Marshal(p)
	for _, tc := range []struct{ old, replacement, path string }{
		{`"schema":4`, `"schema":3,"Schema":4`, "schema"},
		{`"name":`, `"name":"discarded","Name":`, "name"},
		{`"settings":[`, `"settings":[],"ſettings":[`, "http2.settings"},
		{`"id":1`, `"id":1,"ID":5`, "http2.settings[0].id"},
		{`"value":65536`, `"value":1,"Value":65536`, "http2.settings[0].value"},
		{`"id":1`, `"id":null`, "http2.settings[0].id"},
		{`"id":1`, `"id":"1"`, "http2.settings[0].id"},
		{`"value":65536`, `"value":null`, "http2.settings[0].value"},
		{`"exclusive":true`, `"exclusive":null`, "http2.header_priority.exclusive"},
	} {
		t.Run(tc.replacement, func(t *testing.T) {
			original := string(data)
			changed := strings.Replace(original, tc.old, tc.replacement, 1)
			if strings.HasPrefix(tc.path, "http2.") {
				h, _ := json.Marshal(p.HTTP2)
				replacement := strings.Replace(string(h), tc.old, tc.replacement, 1)
				changed = strings.Replace(original, `"http2":`+string(h), `"http2":`+replacement, 1)
			}
			if changed == original {
				t.Fatal("fixture mutation missed", tc.old)
			}
			if _, err := Load([]byte(changed)); err == nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatal(err, tc.path)
			}
		})
	}
	for _, raw := range []string{`null`, `{"id":1}`, `{"value":42}`} {
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		h := fields["http2"].(map[string]any)
		var v any
		_ = json.Unmarshal([]byte(raw), &v)
		h["settings"] = []any{v}
		changed, _ := json.Marshal(fields)
		if _, err := Load(changed); err == nil || !strings.Contains(err.Error(), "http2.settings[0]") {
			t.Fatal(raw, err)
		}
	}
}

// TLS-only parser fixtures retain their original hello/behavior and object
// identity, but now supply otherwise-valid HTTP metadata to the executable
// gate. This does not assert another browser uses these HTTP2 values.
func executableTLSFixture(t *testing.T, p *Profile) *Profile {
	t.Helper()
	if !p.BareBase() && len(p.HTTP2.PseudoHeaderOrder) == 0 && len(p.HTTP2.Settings) == 0 {
		p.HTTP2 = mustGet(t, "chrome_155_macos").HTTP2
	}
	return p
}

func TestRegistryAndCatalogueCannotBypassSemantics(t *testing.T) {
	p := mustGet(t, "chrome_155_macos").Clone()
	registry := NewRegistry()
	if err := registry.Register(p); err != nil {
		t.Fatal(err)
	}
	p.HTTP2.Settings = []Setting{{5, 1}}
	got, err := registry.Get(p.Name)
	if err != nil {
		t.Fatal(err)
	}
	got.HTTP2.Settings = []Setting{{4, 1 << 31}}
	again, err := registry.Get(p.Name)
	if err != nil || again.HTTP2.Settings[0].ID != 1 {
		t.Fatal("registry snapshot mutated", err)
	}
	registry.added[p.Name].HTTP2.Settings = []Setting{{5, 1}}
	if _, err = registry.Get(p.Name); err == nil {
		t.Fatal("retained registry entry bypassed validator")
	}
	old := catalogueTemplate
	defer func() { catalogueTemplate = old }()
	for _, body := range []string{
		`"http2":{"settings":[{"id":5,"value":1}],"pseudo_header_order":[":method",":authority",":scheme",":path"]}`,
		`"http2":{"settings":null,"settings":[]}`,
	} {
		catalogueTemplate = []byte(`{"entries":{"chrome_133":"x"},"templates":{"x":{"engine_major":1,"name":"template","base":"chrome_133",` + body + `}}}`)
		if _, err := NewRegistry().Get("chrome_133"); err == nil {
			t.Fatal("catalogue bypass", body)
		}
	}
}

func TestExecutableJSONTypedBoundaries(t *testing.T) {
	p := mustGet(t, "chrome_155_macos")
	original, _ := json.Marshal(p)
	for _, bad := range []string{
		`{"settings":[{"id":65536,"value":0}]}`,
		`{"settings":[{"id":1,"value":4294967296}]}`,
		`{"settings":[{"id":1,"value":-1}]}`,
		`{"settings":[{"id":1,"value":1.5}]}`,
		`{"settings":[{"id":1,"value":1e2}]}`,
		`{"settings":{}}`, `{"priorities":{}}`, `{"pseudo_header_order":{}}`,
		`{"header_priority":[]}`, `{"connection_flow":null}`, `{"stream_id":4294967296}`,
		`{"header_priority":{"stream_id":1,"weight":256}}`,
	} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(original, &fields)
		fields["http2"] = json.RawMessage(bad)
		data, _ := json.Marshal(fields)
		if _, err := Load(data); err == nil || !strings.Contains(err.Error(), "http2.") {
			t.Fatal(bad, err)
		}
	}
}

func TestOtherSemanticRepresentationBoundaries(t *testing.T) {
	p := mustGet(t, "chrome_155_macos").Clone()
	p.Behavior["h2.priority_dependency"] = json.RawMessage(`"root"`)
	p.HTTP2.HeaderPriority.DependsOn = 3
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "future request") {
		t.Fatal(err)
	}
	p = mustGet(t, "chrome_155_macos").Clone()
	p.HTTP2.Settings = make([]Setting, 2731)
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "16384") {
		t.Fatal(err)
	}
	for _, id := range []uint32{2, 1 << 31} {
		p = mustGet(t, "chrome_155_macos").Clone()
		p.HTTP2.HeaderPriority.StreamID = id
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "header_priority.stream_id") {
			t.Fatal(err)
		}
	}
	p, err := Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP2.ConnectionFlow = 1
	if err = p.Validate(); err == nil || !strings.Contains(err.Error(), "bare catalogue") {
		t.Fatal(err)
	}
}

func TestExecutableJSONScannerRefusesTruncatedOrMultipleValues(t *testing.T) {
	for _, raw := range []string{``, `{1:2}`, `{"x":`, `{"x":1,`, `{} {}`, `[] true`} {
		if err := validateProfileJSON([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
}

func TestInvalidTLSAndOfflineFormatRemainChecked(t *testing.T) {
	p := mustGet(t, "chrome_155_macos").Clone()
	p.ClientHello = nil
	p.Base = "unavailable-full-base"
	if _, err := p.Spec(); err == nil || !strings.Contains(err.Error(), "unknown base") {
		t.Fatal(err)
	}
	if _, err := p.ClientProfile(); err == nil {
		t.Fatal("adapter accepted an unavailable full base")
	}
	for _, field := range []string{"behavior", "behavior-choice", "name"} {
		p = mustGet(t, "chrome_155_macos").Clone()
		switch field {
		case "behavior":
			p.Behavior = nil
		case "behavior-choice":
			p.Behavior["h2.read_loop_start"] = json.RawMessage(`"unavailable-primitive"`)
		default:
			p.Name = ""
		}
		raw, _ := json.Marshal(p)
		if _, err := Inspect(raw); err == nil {
			t.Fatal("offline malformed format accepted", field)
		}
	}
}
