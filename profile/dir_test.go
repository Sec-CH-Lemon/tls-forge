package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// keptHere points a registry at a directory a test wrote, which is the only way
// to exercise this: the real one belongs to whoever is running the tests.
func keptHere(t *testing.T, names ...string) (*Registry, string) {
	t.Helper()
	dir := t.TempDir()
	shipped, err := embedded.ReadFile("data/chrome_151/macos.json")
	if err != nil {
		t.Fatalf("reading the shipped profile: %v", err)
	}
	for _, name := range names {
		p, err := Load(shipped)
		if err != nil {
			t.Fatalf("loading: %v", err)
		}
		p.Name = name
		p.Notes = "kept on this machine"
		data, err := p.Save()
		if err != nil {
			t.Fatalf("saving: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0o644); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}
	r := NewRegistry()
	r.SetDir(dir)
	return r, dir
}

func TestGetFindsAProfileKeptHere(t *testing.T) {
	r, _ := keptHere(t, "my_browser")

	p, err := r.Get("my_browser")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "my_browser" || len(p.ClientHello) == 0 {
		t.Errorf("got %+v", p.Name)
	}
	// And it is listed, so `profiles` shows it and a family name can find it.
	var listed bool
	for _, name := range r.Names() {
		listed = listed || name == "my_browser"
	}
	if !listed {
		t.Error("a profile kept here was not listed")
	}
	if kept := r.KeptHere(); len(kept) != 1 || kept[0] != "my_browser" {
		t.Errorf("KeptHere = %v", kept)
	}
}

func TestAProfileKeptHereBeatsTheShippedOne(t *testing.T) {
	// The point of the directory: someone who captured their own Chrome should
	// get theirs, because theirs is the browser a server will be comparing
	// against.
	r, _ := keptHere(t, "chrome_151")

	p, err := r.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Notes != "kept on this machine" {
		t.Errorf("the shipped profile won: %q", p.Notes)
	}
	// Registering one at runtime still beats both.
	own := &Profile{Name: "chrome_151", Notes: "registered at runtime"}
	if err := r.Register(own); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if p, _ := r.Get("chrome_151"); p.Notes != "registered at runtime" {
		t.Errorf("the directory beat a registered profile: %q", p.Notes)
	}
}

func TestAFamilyNameFindsAProfileKeptHere(t *testing.T) {
	// A machine that captured a newer Chrome than the one shipped should have
	// "chrome" mean theirs.
	r, _ := keptHere(t, "chrome_999")

	p, err := r.Get("chrome")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "chrome_999" {
		t.Errorf("chrome resolved to %q", p.Name)
	}
}

func TestGetTakesAPath(t *testing.T) {
	// Someone with a profile in hand should not have to move it anywhere first.
	_, dir := keptHere(t, "somewhere")
	path := filepath.Join(dir, "somewhere.json")

	p, err := NewRegistry().Get(path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "somewhere" {
		t.Errorf("got %q", p.Name)
	}

	if _, err := NewRegistry().Get(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a path that is not there should fail")
	}
}

func TestADirectoryProfileIsIgnoredWhenItWillNotLoad(t *testing.T) {
	// A broken file in the directory falls through to the other sources rather
	// than taking a name hostage.
	r, dir := keptHere(t)
	if err := os.WriteFile(filepath.Join(dir, "chrome_151.json"), []byte("{"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	p, err := r.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(p.ClientHello) == 0 {
		t.Error("the shipped profile was not used")
	}
}

func TestADirectoryNameCannotReachOutOfIt(t *testing.T) {
	// A name is a file name here. One carrying a separator would name a file
	// somewhere else, which is not the directory's to offer.
	r, dir := keptHere(t, "inside")
	outside := filepath.Join(filepath.Dir(dir), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	for _, name := range []string{"..", ".", ".." + string(filepath.Separator) + "outside"} {
		if _, err := r.Get(name); err == nil {
			t.Errorf("%q resolved to something", name)
		}
	}
}

func TestNoDirectoryIsNotAnError(t *testing.T) {
	// A container with no HOME has nowhere to keep profiles; the other three
	// sources still answer.
	r := NewRegistry()
	r.SetDir("")
	if _, err := r.Get("chrome_151"); err != nil {
		t.Errorf("Get: %v", err)
	}
	if kept := r.KeptHere(); kept != nil {
		t.Errorf("KeptHere = %v", kept)
	}

	// And a directory that is not there is the same as none.
	r.SetDir(filepath.Join(t.TempDir(), "absent"))
	if _, err := r.Get("chrome_151"); err != nil {
		t.Errorf("Get: %v", err)
	}
	if kept := r.KeptHere(); kept != nil {
		t.Errorf("KeptHere = %v", kept)
	}
}

func TestDefaultDir(t *testing.T) {
	// The environment moves it, which is how a container or a test says where
	// to look without touching a real one.
	home := os.Getenv("HOME")
	t.Setenv("TLSFORGE_PROFILES", "/somewhere/else")
	if got := DefaultDir(); got != "/somewhere/else" {
		t.Errorf("DefaultDir = %q", got)
	}

	os.Unsetenv("TLSFORGE_PROFILES")

	// No home to speak of, which happens in a container with no HOME set. The
	// other sources still answer, so this is nowhere rather than an error.
	//
	// HOME is not the only way to a config directory: on Linux, os.UserConfigDir
	// reads XDG_CONFIG_HOME first and only falls back to $HOME/.config. GitHub's
	// runners set it, so clearing HOME alone left this test asking for nowhere
	// and being handed somewhere.
	if runtime.GOOS != "windows" {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "")
		if got := DefaultDir(); got != "" {
			t.Errorf("with no home: %q", got)
		}
		t.Setenv("HOME", home)
	}

	got := DefaultDir()
	if got == "" {
		t.Skip("this machine has no config directory")
	}
	// Under the user's config directory, not beside the binary: a profile is
	// this machine's measurement and should survive a reinstall.
	if filepath.Base(got) != "profiles" || filepath.Base(filepath.Dir(got)) != "tls-forge" {
		t.Errorf("DefaultDir = %q", got)
	}
}

func TestDirNamesIgnoresWhatIsNotAProfile(t *testing.T) {
	// A directory of profiles collects other things: a subdirectory, a note, a
	// half-written file with the wrong suffix.
	r, dir := keptHere(t, "real")
	if err := os.Mkdir(filepath.Join(dir, "old"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if kept := r.KeptHere(); len(kept) != 1 || kept[0] != "real" {
		t.Errorf("KeptHere = %v", kept)
	}
}

func TestLooksLikePath(t *testing.T) {
	for name, want := range map[string]bool{
		"chrome_151":      false,
		"chrome":          false,
		"my-chrome.json":  true,
		"MY-CHROME.JSON":  true,
		"/etc/profiles/a": true,
		"./a":             true,
		"dir/name":        true,
	} {
		if got := looksLikePath(name); got != want {
			t.Errorf("looksLikePath(%q) = %v, want %v", name, got, want)
		}
	}
}
