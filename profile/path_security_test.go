package profile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	if _, _, ok, err := lookup(tree, ".", "good_UPPER"); ok || err != nil {
		t.Errorf("lookup accepted invalid platform: %v", err)
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
	if p, ok, err := registry.fromDir("escaped_macos"); p != nil || !ok || err == nil {
		t.Errorf("a profile through a link out of the directory: %v, %v, %v", p, ok, err)
	}
}

// A profile the directory holds a link for that it does not follow is refused,
// and the shipped profile of its name does not answer for it: an absolute link
// (even to a file in the directory), a link out of it, a link to nothing. A
// relative link that stays in the directory is followed, and a stray file
// that is no profile's name is passed over, as before.
func TestAProfileLinkTheDirectoryDoesNotFollowIsRefused(t *testing.T) {
	shipped, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	mine := shipped.Clone()
	mine.Notes = "measured here"
	data, err := mine.Save()
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "macos.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, ask string
		lay       func(t *testing.T, dir string)
		refused   bool
	}{
		{"a file", "chrome_155_macos", func(t *testing.T, dir string) { put(t, filepath.Join(dir, "chrome_155", "macos.json"), data) }, false},
		{"a relative link in the directory", "chrome_155_macos", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, "kept.json"), data)
			link(t, filepath.Join("..", "kept.json"), filepath.Join(dir, "chrome_155", "macos.json"))
		}, false},
		{"an absolute link to a file in the directory", "chrome_155_macos", func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, "kept.json"), data)
			link(t, filepath.Join(dir, "kept.json"), filepath.Join(dir, "chrome_155", "macos.json"))
		}, true},
		{"an absolute link out of it", "chrome_155_macos", func(t *testing.T, dir string) {
			link(t, filepath.Join(outside, "macos.json"), filepath.Join(dir, "chrome_155", "macos.json"))
		}, true},
		{"a relative link out of it", "chrome_155_macos", func(t *testing.T, dir string) {
			rel, err := filepath.Rel(filepath.Join(dir, "chrome_155"), filepath.Join(outside, "macos.json"))
			if err != nil {
				t.Fatal(err)
			}
			link(t, rel, filepath.Join(dir, "chrome_155", "macos.json"))
		}, true},
		{"a link to nothing", "chrome_155_macos", func(t *testing.T, dir string) {
			link(t, "gone.json", filepath.Join(dir, "chrome_155", "macos.json"))
		}, true},
		{"the version's file for this machine", "chrome_155", func(t *testing.T, dir string) {
			link(t, filepath.Join(outside, "macos.json"), filepath.Join(dir, "chrome_155", hostPlatform+".json"))
		}, true},
		{"a flat file", "chrome_155_macos", func(t *testing.T, dir string) {
			link(t, filepath.Join(outside, "macos.json"), filepath.Join(dir, "chrome_155_macos.json"))
		}, true},
		{"a version directory linked out", "chrome_155_macos", func(t *testing.T, dir string) {
			link(t, outside, filepath.Join(dir, "chrome_155"))
		}, true},
		{"a version directory linked out, asked by its version", "chrome_155", func(t *testing.T, dir string) {
			link(t, outside, filepath.Join(dir, "chrome_155"))
		}, true},
		{"a stray file named as a version", "chrome_155", func(t *testing.T, dir string) { put(t, filepath.Join(dir, "chrome_155"), data) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.lay(t, dir)
			registry := NewRegistry()
			registry.SetDir(dir)
			p, err := registry.Get(c.ask)
			switch {
			case c.refused:
				if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "cannot be read") {
					t.Fatalf("worn %q, %v; want it refused", notesOf(p), err)
				}
			case err != nil:
				t.Fatal(err)
			case c.name == "a stray file named as a version":
				if p.Notes == mine.Notes {
					t.Fatal("a stray file was read as a profile")
				}
			case p.Notes != mine.Notes:
				t.Fatalf("worn %q, not the measured profile", notesOf(p))
			}
		})
	}
}

func put(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func notesOf(p *Profile) string {
	if p == nil {
		return ""
	}
	return p.Notes[:min(len(p.Notes), 40)]
}
