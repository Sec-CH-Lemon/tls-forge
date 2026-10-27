package profile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestContentCodingExecutionChoicesDoNotRetagArchives(t *testing.T) {
	for _, key := range []string{"http.max_content_codings", "http.content_coding_overflow", "http.ignored_content_codings", "cookie.prefixes"} {
		p, err := Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		delete(p.Behavior, key)
		if _, err := p.ClientProfile(); err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("execution inferred %s: %v", key, err)
		}
		// An actual archive from before this capability has none of the
		// group's fields, rather than half of an inconsistent policy pair.
		for _, oldKey := range []string{"http.max_content_codings", "http.content_coding_overflow", "http.ignored_content_codings"} {
			delete(p.Behavior, oldKey)
		}
		data, err := p.Save()
		if err != nil {
			t.Fatal("offline Save:", err)
		}
		if _, err := Load(data); err == nil || !strings.Contains(err.Error(), "behavior is incomplete") {
			t.Fatalf("Load inferred %s: %v", key, err)
		}
		archive, err := Inspect(data)
		if err != nil {
			t.Fatal("offline Inspect:", err)
		}
		if archive.Behavior.Has(key) || archive.EngineMajor == nil || *archive.EngineMajor != *p.EngineMajor {
			t.Fatal("Inspect changed archive identity or completed missing data")
		}
		cloned := archive.Clone()
		if cloned.Behavior.Has(key) || !bytes.Equal(cloned.ClientHello, archive.ClientHello) {
			t.Fatal("Clone silently migrated archive")
		}
		migrated, err := archive.Migrate("explicit-security-migration")
		if err != nil || !migrated.Behavior.Has(key) || !bytes.Equal(archive.ClientHello, migrated.ClientHello) {
			t.Fatalf("explicit migration failed: %v", err)
		}
		if archive.Behavior.Has(key) {
			t.Fatal("migration mutated its source")
		}
	}
	for _, raw := range []string{`null`, `65`, `-1`, `1.5`, `"10"`} {
		p, err := Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		p.Behavior["http.max_content_codings"] = json.RawMessage(raw)
		if _, err := p.ClientProfile(); err == nil {
			t.Fatal("invalid limit accepted:", raw)
		}
	}
}

func TestNoProfileRunsWithoutItsCodingAndCookieRulesWhateverItsSchema(t *testing.T) {
	// The rules of a body's codings and of the cookies a server may set are
	// required of every profile this engine runs, whatever schema it says:
	// one that said an older schema used to run without them, its cookie
	// prefixes protecting nothing.
	shipped := mustGet(t, "chrome_155_macos")
	for _, schema := range []int{0, 1, 2, 3, Schema} {
		// The two depth keys are one rule, supplied together or not at all.
		for _, missing := range [][]string{
			{"http.max_content_codings", "http.content_coding_overflow"},
			{"http.ignored_content_codings"},
			{"cookie.prefixes"},
		} {
			p := shipped.Clone()
			p.Schema = schema
			for _, key := range missing {
				delete(p.Behavior, key)
			}
			if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "requires "+missing[0]) {
				t.Errorf("schema %d without %s: %v", schema, missing[0], err)
			}
			// Kept as it was, and saved, as an archive; only running it is refused.
			if _, err := Inspect(mustSave(t, p)); err != nil {
				t.Errorf("schema %d without %s is no longer read offline: %v", schema, missing[0], err)
			}
		}
		p := shipped.Clone()
		p.Schema = schema
		if err := p.Validate(); err != nil {
			t.Errorf("schema %d with every rule: %v", schema, err)
		}
	}
	// An older schema with no behavior of its own runs with the frozen
	// legacy data and this engine's additions to it, which hold every rule.
	for _, name := range []string{"chrome_155_windows", "firefox_148"} {
		old := mustGet(t, name).Clone()
		old.Schema, old.Behavior = 2, nil
		for _, key := range requiredRules {
			if !old.RuntimeBehavior().Has(key) {
				t.Errorf("%s of schema 2 runs without %s", name, key)
			}
		}
		if err := old.Validate(); err != nil {
			t.Errorf("%s of schema 2 with the legacy behavior: %v", name, err)
		}
	}
}

func mustSave(t *testing.T, p *Profile) []byte {
	t.Helper()
	data, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
