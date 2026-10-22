package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEngineCompatibilityMatrix(t *testing.T) {
	for _, running := range []int{0, 1, 2, 3, 4} {
		for _, declared := range []int{0, 1, 2, 3, 4} {
			p := &Profile{Name: "renamed", EngineMajor: Major(declared)}
			if err := p.validateEngineMajor(running); (err == nil) != (running == declared) {
				t.Fatal(running, declared, err)
			}
		}
	}
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := p.Save()
	var fields map[string]json.RawMessage
	json.Unmarshal(data, &fields)
	for _, raw := range []string{"missing", "null", "0", "1", "2", "3", "5", "-1", "1.25", `"1"`, "true"} {
		t.Run(raw, func(t *testing.T) {
			if raw == "missing" {
				delete(fields, "engine_major")
			} else {
				fields["engine_major"] = json.RawMessage(raw)
			}
			bytes, _ := json.Marshal(fields)
			_, err := Load(bytes)
			if err == nil || !strings.Contains(err.Error(), "engine_major") || !strings.Contains(err.Error(), "running engine major 4") {
				t.Fatal(err)
			}
			at := filepath.Join(t.TempDir(), "renamed.json")
			os.WriteFile(at, bytes, 0600)
			if _, err := Get(at); err == nil {
				t.Fatal("file bypass")
			}
		})
	}
	for _, major := range []*int{nil, Major(-1), Major(0), Major(1), Major(2), Major(3), Major(5)} {
		q := p.Clone()
		q.Name = "firefox_148"
		q.Base = "chrome_133"
		q.EngineMajor = major
		if q.ValidateEngine() == nil {
			t.Fatal("renaming bypass")
		}
		if _, err := q.Spec(); err == nil {
			t.Fatal("Spec bypass")
		}
		if _, err := q.ClientProfile(); err == nil {
			t.Fatal("adapter bypass")
		}
		if err := NewRegistry().Register(q); err == nil {
			t.Fatal("registry bypass")
		}
	}
}
func TestEngineMajorPreservedAndMigrationExplicit(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	q := p.Clone()
	*q.EngineMajor = 0
	if *p.EngineMajor != 4 {
		t.Fatal("major pointer aliases")
	}
	for _, major := range []*int{nil, Major(0), Major(1), Major(2), Major(3), Major(5)} {
		q := p.Clone()
		q.EngineMajor = major
		b, err := q.Save()
		if err != nil {
			t.Fatal(err)
		}
		archived, err := Inspect(b)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(archived.EngineMajor, major) {
			t.Fatal("Save retagged archive")
		}
		if _, err := Load(b); err == nil {
			t.Fatal("archive executable")
		}
		m, err := archived.Migrate("explicit-engine-4-candidate")
		if err != nil {
			t.Fatal(err)
		}
		if *m.EngineMajor != 4 || m.Notes == p.Notes || !reflect.DeepEqual(m.ClientHello, p.ClientHello) || !reflect.DeepEqual(archived.EngineMajor, major) {
			t.Fatal("migration lost provenance or changed source")
		}
	}
}
func TestAllEmbeddedProfilesPinThisEngine(t *testing.T) {
	paths, err := filepath.Glob("data/chrome_*/*.json")
	if err != nil || len(paths) != 15 {
		t.Fatal(paths, err)
	}
	for _, path := range paths {
		b, _ := os.ReadFile(path)
		p, err := Load(b)
		if err != nil {
			t.Fatal(path, err)
		}
		if p.Schema != 4 || p.EngineMajor == nil || *p.EngineMajor != 4 {
			t.Fatal(path)
		}
		if _, err := p.ClientProfile(); err != nil {
			t.Fatal(path, err)
		}
	}
	p, err := catalogueProfile("firefox_148")
	if err != nil || p.EngineMajor == nil || *p.EngineMajor != 4 {
		t.Fatal(p, err)
	}
}

func TestLocalIncompatibleProfileDoesNotFallBack(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.EngineMajor = Major(0)
	b, _ := p.Save()
	dir := t.TempDir()
	at := filepath.Join(dir, "chrome_155", "macos.json")
	os.MkdirAll(filepath.Dir(at), 0755)
	os.WriteFile(at, b, 0600)
	registry := NewRegistry()
	registry.SetDir(dir)
	for _, name := range []string{"chrome_155_macos", "chrome_155"} {
		if _, err := registry.Get(name); err == nil || !strings.Contains(err.Error(), "engine_major 0") {
			t.Fatal(name, err)
		}
	}
	if _, err := registry.Get("chrome_154_macos"); err != nil {
		t.Fatal("unrelated compatible embedded profile", err)
	}
}

func TestCatalogueMetadataIsCheckedBeforeTemplateExpansion(t *testing.T) {
	original := append([]byte(nil), catalogueTemplate...)
	defer func() { catalogueTemplate = original }()
	var inventory struct {
		Entries   map[string]string          `json:"entries"`
		Templates map[string]json.RawMessage `json:"templates"`
	}
	json.Unmarshal(original, &inventory)
	key := inventory.Entries["firefox_148"]
	template := string(inventory.Templates[key])
	for _, replacement := range []string{`"engine_major":0,`, `"engine_major":5,`, `"engine_major":null,`, ``, `"engine_major":4,"engine_major":4,`, `"engine_major":0,"Engine_Major":1,`} {
		compact := strings.ReplaceAll(strings.ReplaceAll(template, " ", ""), "\n", "")
		inventory.Templates[key] = json.RawMessage(strings.Replace(compact, `"engine_major":4,`, replacement, 1))
		catalogueTemplate, _ = json.Marshal(inventory)
		if _, err := catalogueProfile("firefox_148"); err == nil || !strings.Contains(err.Error(), "firefox_148") || !strings.Contains(err.Error(), "engine_major") {
			t.Fatal(replacement, err)
		}
	}
}

func TestOldEngineProfileInspectionDoesNotInventQPACKPolicy(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.EngineMajor = Major(1)
	delete(p.Behavior, "h3.qpack.huffman_names")
	delete(p.Behavior, "h3.qpack.huffman_values")
	raw, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	archived, err := Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if *archived.EngineMajor != 1 || archived.Behavior.Has("h3.qpack.huffman_names") {
		t.Fatal("offline inspection changed archive")
	}
	if _, err = Load(raw); err == nil {
		t.Fatal("old profile executed")
	}
	migrated, err := archived.Migrate("neutral-engine2-candidate")
	if err != nil {
		t.Fatal(err)
	}
	if *migrated.EngineMajor != 4 || migrated.Behavior.Text("h3.qpack.huffman_names") != "always" || migrated.Behavior.Text("h3.qpack.huffman_values") != "always" {
		t.Fatal("explicit migration missed data defaults")
	}
	if archived.Behavior.Has("h3.qpack.huffman_names") || *archived.EngineMajor != 1 {
		t.Fatal("migration mutated original")
	}
	delete(migrated.Behavior, "h3.qpack.huffman_values")
	raw, err = migrated.Save()
	if err == nil {
		if _, err = Load(raw); err == nil {
			t.Fatal("incomplete engine2 profile executed")
		}
	}
}
