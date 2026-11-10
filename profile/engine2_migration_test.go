package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// engine2Migration is the explicit Migrate that made engine 1's profiles
// engine 2's: each file's bytes before and after. Undoing it gives the bytes
// before exactly, so that the layers of provenance made under engine 1 see
// the bytes they were made of.
type engine2Migration struct {
	Schema   int    `json:"schema"`
	Major    int    `json:"engine_major"`
	From     int    `json:"from_engine_major"`
	Source   string `json:"source"`
	Profiles map[string]struct {
		Before string `json:"before_sha256"`
		After  string `json:"after_sha256"`
	} `json:"profiles"`
}

func readEngine2Migration() (engine2Migration, error) {
	var m engine2Migration
	raw, err := os.ReadFile("provenance/engine2-migration.json")
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if m.Schema != 1 || m.Major != 2 || m.From != 1 || m.Source == "" || len(m.Profiles) == 0 {
		return m, fmt.Errorf("invalid engine 2 migration inventory")
	}
	return m, nil
}

// migrationNote is the line Migrate appends to a profile it makes engine 2's.
func migrationNote(name string) string {
	return "\nExplicit engine migration to 2.0.0 (major 2) from profile " + strconv.Quote(name) +
		"; capture provenance retained; browser acceptance must be rechecked."
}

// undoEngine2 gives the engine 1 bytes the migration made raw of, read
// offline (engine 1's bytes are no engine 2 profile): engine_major 1 again,
// the migration's line of notes taken off, through Save. Bytes no row of m
// made come back as they are.
func undoEngine2(raw []byte, m engine2Migration) ([]byte, error) {
	sum := a13SHA(raw)
	for path, row := range m.Profiles {
		if row.After != sum {
			continue
		}
		p, err := Inspect(raw)
		if err != nil {
			return nil, err
		}
		if p.EngineMajor == nil || *p.EngineMajor != 2 {
			return nil, fmt.Errorf("%s: the migration made no engine 2 profile", path)
		}
		note := migrationNote(p.Name)
		if !strings.HasSuffix(p.Notes, note) {
			return nil, fmt.Errorf("%s: no note of the migration ends its notes", path)
		}
		p.Notes = strings.TrimSuffix(p.Notes, note)
		p.EngineMajor = Major(1)
		out, err := p.Save()
		if err != nil {
			return nil, err
		}
		if a13SHA(out) != row.Before {
			return nil, fmt.Errorf("%s: the migration changed more than its major and its note", path)
		}
		return out, nil
	}
	return raw, nil
}

// engine1Bytes is the file at path (from the repository's root) as engine 1
// had it, the migration undone.
func engine1Bytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../" + path)
	if err != nil {
		t.Fatal(err)
	}
	return engine1Of(t, raw)
}

// engine1Of is raw as engine 1 had it, the migration undone; bytes the
// migration did not make come back as they are.
func engine1Of(t *testing.T, raw []byte) []byte {
	t.Helper()
	m, err := readEngine2Migration()
	if err != nil {
		t.Fatal(err)
	}
	out, err := undoEngine2(raw, m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// migratedBytes is the file at path (from the repository's root) as the
// migration left it: the file itself, or the kept copy of it a capture made
// under engine 2 replaced.
func migratedBytes(t *testing.T, path string) []byte {
	t.Helper()
	if row, ok := recaptures(t)[path]; ok && row.Major == 2 {
		return keptBytes(t, path)
	}
	raw, err := os.ReadFile("../" + path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEveryProfileMigratedToEngine2UndoesToItsEngine1Bytes(t *testing.T) {
	m, err := readEngine2Migration()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob("data/chrome_*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	examples, err := filepath.Glob("../example/profiles/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var want, got []string
	for _, path := range paths {
		want = append(want, "profile/"+path)
	}
	for _, path := range examples {
		want = append(want, strings.TrimPrefix(path, "../"))
	}
	for path := range m.Profiles {
		got = append(got, path)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("the migration names %v; the files are %v", got, want)
	}
	for _, path := range got {
		row := m.Profiles[path]
		current := migratedBytes(t, path)
		if a13SHA(current) != row.After {
			t.Fatalf("%s is not the bytes the migration made", path)
		}
		p, err := Load(current)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		before, err := undoEngine2(current, m)
		if err != nil {
			t.Fatal(err)
		}
		if a13SHA(before) != row.Before {
			t.Fatalf("%s: undone to other bytes", path)
		}
		old, err := Inspect(before)
		if err != nil {
			t.Fatal(err)
		}
		if *old.EngineMajor != 1 || old.Name != p.Name {
			t.Fatalf("%s: undone to major %d, %q", path, *old.EngineMajor, old.Name)
		}
		if _, err := Load(before); err == nil || !strings.Contains(err.Error(), "engine_major 1 is incompatible with running engine major 2") {
			t.Fatalf("%s: engine 2 runs its engine 1 bytes: %v", path, err)
		}
		// Nothing but the major and the notes: every other field is as it was.
		var a, b map[string]json.RawMessage
		if json.Unmarshal(current, &a) != nil || json.Unmarshal(before, &b) != nil {
			t.Fatal(path)
		}
		for _, field := range []string{"engine_major", "notes"} {
			delete(a, field)
			delete(b, field)
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if string(x) != string(y) {
			t.Fatalf("%s: the migration changed another field", path)
		}
	}
}

func TestAnEngine2MigrationThatIsNotOneIsRefused(t *testing.T) {
	m, err := readEngine2Migration()
	if err != nil {
		t.Fatal(err)
	}
	const path = "profile/data/chrome_156/macos.json"
	current, err := os.ReadFile("../" + path)
	if err != nil {
		t.Fatal(err)
	}
	if a13SHA(current) != m.Profiles[path].After {
		t.Fatalf("%s is not the bytes the migration made", path)
	}
	// Bytes no row made come back as they are.
	other := append([]byte(nil), current...)
	other[len(other)-2] = ' '
	if out, err := undoEngine2(other, m); err != nil || string(out) != string(other) {
		t.Fatalf("other bytes: %v", err)
	}
	p, err := Inspect(current)
	if err != nil {
		t.Fatal(err)
	}
	row := m.Profiles[path]
	for name, change := range map[string]func(q *Profile){
		"no note":    func(q *Profile) { q.Notes = strings.TrimSuffix(q.Notes, migrationNote(q.Name)) },
		"major 3":    func(q *Profile) { q.EngineMajor = Major(3) },
		"more added": func(q *Profile) { q.Notes = strings.Replace(q.Notes, "captured", "Captured", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			q := p.Clone()
			change(q)
			raw, err := q.Save()
			if err != nil {
				t.Fatal(err)
			}
			// A row that says these are the bytes the migration made.
			lying := engine2Migration{Schema: 1, Major: 2, From: 1, Source: "s", Profiles: m.Profiles}
			lying.Profiles = map[string]struct {
				Before string `json:"before_sha256"`
				After  string `json:"after_sha256"`
			}{path: {Before: row.Before, After: a13SHA(raw)}}
			if _, err := undoEngine2(raw, lying); err == nil {
				t.Fatal("undone")
			}
		})
	}
	for _, doc := range []string{`{}`, `{"schema":1,"engine_major":1,"from_engine_major":1,"source":"s","profiles":{"x":{}}}`, `[`} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "provenance"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "provenance", "engine2-migration.json"), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if _, err := readEngine2Migration(); err == nil {
			t.Fatalf("%s read", doc)
		}
	}
}
