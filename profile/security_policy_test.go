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
