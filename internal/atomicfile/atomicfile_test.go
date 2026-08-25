package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReplacesFileAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if runtime.GOOS == "windows" {
		// Windows has no Unix permission bits. Go's Chmod implementation uses
		// only 0200 to clear or set the Windows read-only attribute; Stat then
		// commonly reports a writable regular file as 0666.
		if mode&0o200 == 0 {
			t.Fatalf("mode = %o, want a writable file", mode)
		}
	} else if mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
}

func TestWriteErrors(t *testing.T) {
	originalCreate := createTemp
	originalChmod := chmodFile
	originalWrite := writeFile
	originalSync := syncFile
	originalClose := closeFile
	originalRename := renameFile
	originalRemove := removeFile
	t.Cleanup(func() {
		createTemp = originalCreate
		chmodFile = originalChmod
		writeFile = originalWrite
		syncFile = originalSync
		closeFile = originalClose
		renameFile = originalRename
		removeFile = originalRemove
	})

	tests := []struct {
		name string
		fail func()
	}{
		{"create", func() {
			createTemp = func(string, string) (*os.File, error) { return nil, errors.New("create") }
		}},
		{"chmod", func() {
			chmodFile = func(*os.File, os.FileMode) error { return errors.New("chmod") }
		}},
		{"write", func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, errors.New("write") }
		}},
		{"short write", func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, nil }
		}},
		{"sync", func() {
			syncFile = func(*os.File) error { return errors.New("sync") }
		}},
		{"close", func() {
			closeFile = func(file *os.File) error {
				_ = originalClose(file)
				return errors.New("close")
			}
		}},
		{"rename", func() {
			renameFile = func(string, string) error { return errors.New("rename") }
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			createTemp = originalCreate
			chmodFile = originalChmod
			writeFile = originalWrite
			syncFile = originalSync
			closeFile = originalClose
			renameFile = originalRename
			removeFile = originalRemove
			test.fail()
			if err := Write(filepath.Join(t.TempDir(), "file"), []byte("data"), 0o600); err == nil {
				t.Fatal("Write() error = nil")
			}
		})
	}
}
