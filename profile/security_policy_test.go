package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/igor-lemon/utls/behavior"
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

// An archive of an older schema with no behavior of its own, saved, keeps
// the frozen data it was read with: the rules of this engine are Migrate's to
// add, not Save's. One this engine runs saves what it runs with.
func TestSavingAnOldArchiveAddsNoRuleOfThisEngine(t *testing.T) {
	for _, name := range []string{"chrome_155_macos", "chrome_155_windows", "firefox_148"} {
		for _, major := range []*int{nil, Major(0), Major(2)} {
			said := "no major"
			if major != nil {
				said = fmt.Sprintf("major %d", *major)
			}
			old := mustGet(t, name).Clone()
			old.Schema, old.Behavior, old.EngineMajor = 2, nil, major
			archive, err := Inspect(mustSave(t, old))
			if err != nil {
				t.Fatalf("%s of %s saved is not read offline: %v", name, said, err)
			}
			frozen := savedOf(old.RuntimeBehavior())
			for _, key := range requiredRules {
				if archive.Behavior.Has(key) {
					t.Errorf("%s of %s saved with %s", name, said, key)
				}
				delete(frozen, key)
			}
			if !reflect.DeepEqual(archive.Behavior, frozen) {
				t.Errorf("%s of %s saved with other data than its frozen data", name, said)
			}
			migrated, err := archive.Migrate(name + "-candidate")
			if err != nil {
				t.Fatalf("%s of %s: Migrate: %v", name, said, err)
			}
			for _, key := range requiredRules {
				if !migrated.Behavior.Has(key) {
					t.Errorf("%s of %s migrated without %s", name, said, key)
				}
			}
		}
		// An archive whose behavior is its own is saved as it is, rules and all.
		own := mustGet(t, name).Clone()
		own.EngineMajor = Major(0)
		own.Behavior["http.max_content_codings"] = json.RawMessage(`5`)
		archived, err := Inspect(mustSave(t, own))
		if err != nil {
			t.Fatalf("%s of major 0 saved is not read offline: %v", name, err)
		}
		if !reflect.DeepEqual(archived.Behavior, savedOf(own.Behavior)) {
			t.Errorf("%s of major 0 saved with other data than its own", name)
		}
		runs := mustGet(t, name).Clone()
		runs.Schema, runs.Behavior = 2, nil
		loaded, err := Load(mustSave(t, runs))
		if err != nil {
			t.Fatalf("%s of schema 2 this engine runs, saved, does not run: %v", name, err)
		}
		if !reflect.DeepEqual(loaded.Behavior, savedOf(runs.RuntimeBehavior())) {
			t.Errorf("%s of schema 2 this engine runs saved with other data than it runs with", name)
		}
	}
}

// A migration gives an archive the rules of this engine of its own kind:
// those measured of Chrome to a Chromium profile, the generic data's to
// another browser's, as an older schema of each kind runs with.
func TestAMigrationGivesAnArchiveTheRulesOfItsOwnKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		want behavior.Policy
	}{
		{"chrome_155_macos", behavior.Legacy()},
		{"firefox_148", behavior.Generic()},
		{"safari_ios_18_5", behavior.Generic()},
	} {
		archive := mustGet(t, tc.name).Clone()
		archive.EngineMajor = Major(0)
		for _, key := range requiredRules {
			delete(archive.Behavior, key)
		}
		migrated, err := archive.Migrate(tc.name + "-candidate")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, key := range requiredRules {
			if got, want := string(migrated.Behavior[key]), string(tc.want[key]); !jsonEqual(t, got, want) {
				t.Errorf("%s migrated with %s %s, want %s", tc.name, key, got, want)
			}
		}
		// A rule the archive says already is its own to keep.
		archive.Behavior["http.max_content_codings"] = json.RawMessage(`5`)
		archive.Behavior["http.content_coding_overflow"] = json.RawMessage(`"raw"`)
		kept, err := archive.Migrate(tc.name + "-candidate")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if kept.Behavior.Uint("http.max_content_codings") != 5 || kept.Behavior.Text("http.content_coding_overflow") != "raw" {
			t.Errorf("%s: a migration replaced the archive's own rule", tc.name)
		}
	}
}

// savedOf is a behavior as Save writes it: ECH lengths are per_connection's.
func savedOf(pol behavior.Policy) behavior.Policy {
	pol = pol.Clone()
	delete(pol, "tls.ech_payload_lengths")
	return pol
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
