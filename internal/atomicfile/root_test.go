package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRootWriteIsAtomicAndConfined(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteRoot(root, "p.json", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := oldFile(t)
	if err := os.Symlink(outside, filepath.Join(dir, "p.json.link")); err != nil {
		t.Fatal(err)
	}
	if err := WriteRoot(root, "p.json.link", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	leftAsItWas(t, outside)
	if err := WriteRoot(root, "../escape", []byte("bad"), 0600); err == nil {
		t.Error("escaped root")
	}
	if err := WriteRoot(root, "missing/p.json", nil, 0600); err == nil {
		t.Error("missing directory accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteRoot(root, "directory", nil, 0600); err == nil {
		t.Error("replaced directory")
	}
	for _, failure := range []string{"write", "short", "sync", "close"} {
		t.Run(failure, func(t *testing.T) {
			keepSeams(t)
			switch failure {
			case "write":
				writeFile = func(*os.File, []byte) (int, error) { return 0, errors.New("full") }
			case "short":
				writeFile = func(*os.File, []byte) (int, error) { return 0, nil }
			case "sync":
				syncFile = func(*os.File) error { return errors.New("sync") }
			case "close":
				closeFile = func(f *os.File) error { _ = f.Close(); return errors.New("close") }
			}
			if err := WriteRoot(root, "p.json", []byte("bad"), 0600); err == nil {
				t.Fatal("failed write succeeded")
			}
			if data, err := root.ReadFile("p.json"); err != nil || string(data) != "new" {
				t.Fatalf("previous file changed: %q %v", data, err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Errorf("temporary file leaked: %v %v", entries, err)
	}
}
