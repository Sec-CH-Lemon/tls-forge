package profile

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestProfileFileLayoutRejectsPaths(t *testing.T) {
	for _, name := range []string{"../local", "a/b", "a\\b", "/absolute", "two..dots", ".hidden", "UPPER", ""} {
		if _, err := FilePath(name, "macos"); err == nil {
			t.Errorf("name %q accepted", name)
		}
		if _, err := FilePath("safe", name); err == nil {
			t.Errorf("platform %q accepted", name)
		}
	}
	if got, err := FilePath("safe_155", "macos"); err != nil || got != "safe_155/macos.json" {
		t.Fatalf("%s %v", got, err)
	}
	tree := fstest.MapFS{"good/UPPER.json": &fstest.MapFile{Data: []byte("not a profile")}}
	if _, _, ok := lookup(tree, ".", "good_UPPER"); ok {
		t.Error("lookup accepted invalid platform")
	}
	dir, outside := t.TempDir(), t.TempDir()
	data, err := fs.ReadFile(embedded, "data/chrome_155/macos.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "macos.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escaped")); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	registry.SetDir(dir)
	if _, ok, _ := registry.fromDir("escaped_macos"); ok {
		t.Error("read escaped profile through symlink")
	}
}
