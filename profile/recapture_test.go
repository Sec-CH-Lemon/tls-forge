package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A file a capture of a browser replaced is kept as it was, by its hash: the
// layers of provenance written before the capture end on those bytes, and are
// unwound from the copy (provenance/recaptured.json). A file captured again
// more than once has a row for each copy, oldest first: the oldest is what the
// layers end on, the newest what the file as it is replaced.
type recapture struct {
	Path     string `json:"path"`
	KeptFile string `json:"kept_file"`
	SHA256   string `json:"sha256"`
	Why      string `json:"why"`
}

func recapturesIn(raw []byte) (map[string][]recapture, error) {
	var doc struct {
		Schema int         `json:"schema"`
		Major  int         `json:"engine_major"`
		Files  []recapture `json:"files"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || doc.Major != 1 || len(doc.Files) == 0 {
		return nil, fmt.Errorf("invalid recapture inventory")
	}
	rows := map[string][]recapture{}
	kept := map[string]bool{}
	for _, row := range doc.Files {
		if row.Path == "" || row.Why == "" || kept[row.SHA256] ||
			filepath.ToSlash(row.KeptFile) != "provenance/recaptured/"+row.SHA256+".json.txt" {
			return nil, fmt.Errorf("invalid recapture of %q", row.Path)
		}
		kept[row.SHA256] = true
		rows[row.Path] = append(rows[row.Path], row)
	}
	return rows, nil
}

func recaptures(t *testing.T) map[string][]recapture {
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
// a capture first replaced it.
func keptCopy(rows map[string][]recapture, path string) ([]byte, error) {
	return keptAt(rows, path, 0)
}

// keptAt is the i-th copy kept of the file at path, oldest first; -1 is the
// newest, the one the file as it is replaced.
func keptAt(rows map[string][]recapture, path string, i int) ([]byte, error) {
	copies := rows[path]
	if i < 0 {
		i += len(copies)
	}
	if i < 0 || i >= len(copies) {
		return nil, fmt.Errorf("%s was not replaced", path)
	}
	row := copies[i]
	raw, err := os.ReadFile(row.KeptFile)
	if err != nil {
		return nil, err
	}
	if a13SHA(raw) != row.SHA256 {
		return nil, fmt.Errorf("the kept copy of %s is not the one recorded", path)
	}
	if current, err := os.ReadFile("../" + path); err != nil {
		return nil, err
	} else if bytes.Equal(current, raw) {
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

// lastKeptBytes is the copy the file at path, as it is, replaced.
func lastKeptBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := keptAt(recaptures(t), path, -1)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// chainBytes is what the layers of provenance before a capture end on: the
// kept copy of a file the capture replaced, else the file itself.
func chainBytes(t *testing.T, path string) []byte {
	t.Helper()
	if _, ok := recaptures(t)[path]; ok {
		return keptBytes(t, path)
	}
	raw, err := os.ReadFile("../" + path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEveryFileACaptureReplacedIsKeptAsItWas(t *testing.T) {
	rows := recaptures(t)
	named := map[string]bool{}
	for path, copies := range rows {
		for i, row := range copies {
			if _, err := keptAt(rows, path, i); err != nil {
				t.Fatal(err)
			}
			named[filepath.Base(row.KeptFile)] = true
		}
		if _, err := keptAt(rows, path, len(copies)); err == nil {
			t.Fatalf("%s has a copy past its last", path)
		}
		if _, err := keptAt(rows, path, -len(copies)-1); err == nil {
			t.Fatalf("%s has a copy before its first", path)
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
	for path, copies := range rows {
		row := copies[0]
		changed := map[string][]recapture{}
		changed[path] = []recapture{{Path: path, KeptFile: row.KeptFile, SHA256: a13SHA(nil), Why: row.Why}}
		if _, err := keptCopy(changed, path); err == nil {
			t.Fatal("a copy of other bytes was taken for the one recorded")
		}
		current, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "same"), current, 0o600); err != nil {
			t.Fatal(err)
		}
		changed[path] = []recapture{{Path: path, KeptFile: filepath.Join(dir, "same"), SHA256: a13SHA(current), Why: row.Why}}
		if _, err := keptCopy(changed, path); err == nil {
			t.Fatal("a file kept as it still is was taken for one replaced")
		}
		break
	}
	if _, err := keptCopy(rows, "profile/data/chrome_151/macos.json"); err == nil {
		t.Fatal("a file never replaced has a kept copy")
	}
	for _, bad := range []string{
		`{"schema":1,"engine_major":1,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"b","why":"y"}]}`,
		`{"schema":1,"engine_major":1,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":""}]}`,
		`{"schema":1,"engine_major":1,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":"y"},{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":"y"}]}`,
		`{"schema":1,"engine_major":2,"files":[{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":"y"}]}`,
		`{"schema":1,"engine_major":1,"files":[]}`,
		`[]`,
	} {
		if _, err := recapturesIn([]byte(bad)); err == nil {
			t.Fatalf("a recapture inventory was taken: %s", bad)
		}
	}
	twice, err := recapturesIn([]byte(`{"schema":1,"engine_major":1,"files":[` +
		`{"path":"x","kept_file":"provenance/recaptured/a.json.txt","sha256":"a","why":"y"},` +
		`{"path":"x","kept_file":"provenance/recaptured/b.json.txt","sha256":"b","why":"z"}]}`))
	if err != nil || len(twice["x"]) != 2 || twice["x"][0].SHA256 != "a" || twice["x"][1].SHA256 != "b" {
		t.Fatalf("a file captured again twice: %v, %v", twice, err)
	}
}
