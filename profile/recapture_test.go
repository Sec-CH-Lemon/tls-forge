package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/engine"
)

// A file a capture of a browser replaced is kept as it was, by its hash: the
// layers of provenance written before the capture end on those bytes, and are
// unwound from the copy (provenance/recaptured.json). Each copy says the
// engine major of the profile it is or describes: chrome_156 was captured
// again under engine 1, chrome_157 under engine 2.
type recapture struct {
	Path     string `json:"path"`
	KeptFile string `json:"kept_file"`
	SHA256   string `json:"sha256"`
	Major    int    `json:"engine_major"`
	Why      string `json:"why"`
}

func recapturesIn(raw []byte) (map[string]recapture, error) {
	var doc struct {
		Schema int         `json:"schema"`
		Files  []recapture `json:"files"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != 2 || len(doc.Files) == 0 {
		return nil, fmt.Errorf("invalid recapture inventory")
	}
	rows := map[string]recapture{}
	for _, row := range doc.Files {
		if row.Path == "" || row.Why == "" || rows[row.Path].Path != "" ||
			row.Major < 1 || row.Major > engine.Major() ||
			filepath.ToSlash(row.KeptFile) != "provenance/recaptured/"+row.SHA256+".json.txt" {
			return nil, fmt.Errorf("invalid recapture of %q", row.Path)
		}
		rows[row.Path] = row
	}
	return rows, nil
}

func recaptures(t *testing.T) map[string]recapture {
	t.Helper()
	raw, err := os.ReadFile("provenance/recaptured.json")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := recapturesIn(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// keptCopy is the file at path (from the repository's root) as it was before
// a capture replaced it.
func keptCopy(rows map[string]recapture, path string) ([]byte, error) {
	row, ok := rows[path]
	if !ok {
		return nil, fmt.Errorf("%s was not replaced", path)
	}
	raw, err := os.ReadFile(row.KeptFile)
	if err != nil {
		return nil, err
	}
	if a13SHA(raw) != row.SHA256 {
		return nil, fmt.Errorf("the kept copy of %s is not the one recorded", path)
	}
	current, err := os.ReadFile("../" + path)
	if err != nil {
		return nil, err
	}
	m, err := readEngine2Migration()
	if err != nil {
		return nil, err
	}
	engine1, err := undoEngine2(current, m)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(current, raw) || bytes.Equal(engine1, raw) {
		return nil, fmt.Errorf("%s is kept as it still is", path)
	}
	return raw, nil
}

func keptBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := keptCopy(recaptures(t), path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// chainBytes is what the layers of provenance before a capture end on, as
// engine 1 had them (the migration to engine 2 undone): the kept copy of a
// file the capture replaced, else the file itself.
func chainBytes(t *testing.T, path string) []byte {
	t.Helper()
	if _, ok := recaptures(t)[path]; ok {
		return engine1Of(t, keptBytes(t, path))
	}
	return engine1Bytes(t, path)
}

// recapturedProfile is the profile a provenance file at path describes:
// profile/provenance/chrome_X/P.json is of profile/data/chrome_X/P.json.
func recapturedProfile(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "profile/provenance/")
	if !ok {
		return "", false
	}
	return "profile/data/" + rest, true
}

func TestEveryFileACaptureReplacedIsKeptAsItWas(t *testing.T) {
	rows := recaptures(t)
	named := map[string]bool{}
	for path, row := range rows {
		kept, err := keptCopy(rows, path)
		if err != nil {
			t.Fatal(err)
		}
		named[filepath.Base(row.KeptFile)] = true
		// The major a copy says is the one its profile declares, or, for
		// a capture's provenance, the one of the profile it describes.
		if described, ok := recapturedProfile(path); ok {
			if rows[described].Major != row.Major {
				t.Fatalf("%s says engine %d, the profile it describes %d", path, row.Major, rows[described].Major)
			}
			continue
		}
		p, err := Inspect(kept)
		if err != nil {
			t.Fatal(err)
		}
		if p.EngineMajor == nil || *p.EngineMajor != row.Major {
			t.Fatalf("the kept %s says engine %d, its profile %v", path, row.Major, p.EngineMajor)
		}
	}
	entries, err := os.ReadDir("provenance/recaptured")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !named[entry.Name()] {
			t.Fatalf("provenance/recaptured/%s is kept for no file", entry.Name())
		}
	}

	// A copy that is not the one recorded, a file kept as it still is, a
	// file never replaced, and a record that names its copy otherwise are
	// each refused.
	for _, path := range []string{"profile/data/chrome_156/macos.json", "profile/data/chrome_157/macos.json"} {
		row := rows[path]
		changed := map[string]recapture{path: row}
		changed[path] = recapture{Path: path, KeptFile: row.KeptFile, SHA256: a13SHA(nil), Major: row.Major, Why: row.Why}
		if _, err := keptCopy(changed, path); err == nil {
			t.Fatal("a copy of other bytes was taken for the one recorded")
		}
		current, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		// As it is, and as engine 1 had it.
		for _, same := range [][]byte{current, engine1Bytes(t, path)} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "same"), same, 0o600); err != nil {
				t.Fatal(err)
			}
			changed[path] = recapture{Path: path, KeptFile: filepath.Join(dir, "same"), SHA256: a13SHA(same), Major: row.Major, Why: row.Why}
			if _, err := keptCopy(changed, path); err == nil {
				t.Fatalf("%s kept as it still is was taken for one replaced", path)
			}
		}
	}
	if _, ok := recapturedProfile("profile/data/chrome_157/macos.json"); ok {
		t.Fatal("a profile was taken for a capture's provenance")
	}
	if _, err := keptCopy(rows, "profile/data/chrome_151/macos.json"); err == nil {
		t.Fatal("a file never replaced has a kept copy")
	}
	const good = `{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","engine_major":2,"why":"y"}`
	if rows, err := recapturesIn([]byte(`{"schema":2,"files":[` + good + `]}`)); err != nil || rows["x"].Major != 2 {
		t.Fatalf("a recapture inventory was refused: %v", err)
	}
	for _, bad := range []string{
		`{"schema":2,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"b","engine_major":2,"why":"y"}]}`,
		`{"schema":2,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","engine_major":2,"why":""}]}`,
		`{"schema":2,"files":[{"path":"","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","engine_major":2,"why":"y"}]}`,
		`{"schema":2,"files":[` + good + `,` + good + `]}`,
		`{"schema":2,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":"y"}]}`,
		`{"schema":2,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","engine_major":3,"why":"y"}]}`,
		`{"schema":1,"engine_major":1,"files":[` + good + `]}`,
		`{"schema":2,"files":[]}`,
		`[]`,
	} {
		if _, err := recapturesIn([]byte(bad)); err == nil {
			t.Fatalf("a recapture inventory was taken: %s", bad)
		}
	}
}
