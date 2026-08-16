package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// laidOut writes a tree in the shape the shipped profiles use: a directory per
// version, one file per platform, with the odd flat file for the ones written
// by hand.
func laidOut(t *testing.T, files map[string]string) *Registry {
	t.Helper()
	dir := t.TempDir()
	shipped, err := embedded.ReadFile("data/chrome_151/macos.json")
	if err != nil {
		t.Fatalf("reading a shipped profile: %v", err)
	}
	for name, at := range files {
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
		path := filepath.Join(dir, filepath.FromSlash(at))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}
	r := NewRegistry()
	r.SetDir(dir)
	return r
}

func TestAVersionMeansThisMachinesPlatform(t *testing.T) {
	// The plain name is Chrome 151 as it looks from here. Anything else is one
	// word longer and says so, which is the right way round for a thing that
	// changes what a server sees.
	original := hostPlatform
	t.Cleanup(func() { hostPlatform = original })

	r := laidOut(t, map[string]string{
		"chrome_151_macos":   "chrome_151/macos.json",
		"chrome_151_linux":   "chrome_151/linux.json",
		"chrome_151_windows": "chrome_151/windows.json",
	})

	for _, platform := range []string{"macos", "linux", "windows"} {
		hostPlatform = platform
		p, err := r.Get("chrome_151")
		if err != nil {
			t.Fatalf("on %s: %v", platform, err)
		}
		if p.Name != "chrome_151_"+platform {
			t.Errorf("on %s, chrome_151 gave %q", platform, p.Name)
		}
	}

	// And each is still there to ask for by name, whatever this machine is.
	hostPlatform = "macos"
	for _, name := range []string{"chrome_151_linux", "chrome_151_windows"} {
		if p, err := r.Get(name); err != nil || p.Name != name {
			t.Errorf("%s: %+v, %v", name, p, err)
		}
	}
}

func TestAVersionWithOnePlatformNeedsNoGuess(t *testing.T) {
	// A machine that measured one platform should not have to be that platform
	// to use what it measured.
	original := hostPlatform
	t.Cleanup(func() { hostPlatform = original })
	hostPlatform = "windows"

	r := laidOut(t, map[string]string{"chrome_151_linux": "chrome_151/linux.json"})
	p, err := r.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "chrome_151_linux" {
		t.Errorf("got %q", p.Name)
	}
}

func TestAVersionWithSeveralAndNoneForThisMachine(t *testing.T) {
	// Two to choose from and neither is this machine's: one is picked anyway,
	// and always the same one.
	//
	// This used to refuse, on the reasoning that picking would be inventing. It
	// would not: measured, Chrome 151 sends the same ClientHello on macOS and on
	// Linux down to the byte, because Chrome carries its own BoringSSL. Only the
	// user-agent differs, and a profile that says macOS is a coherent identity
	// from anywhere — `--profile chrome_151_macos` on Linux has always been a
	// legitimate thing to ask for. Refusing cost more than it protected: on
	// Windows, where no capture exists yet, `chrome_151` resolved to nothing and
	// took the default profile down with it, so the library would not start.
	original := hostPlatform
	t.Cleanup(func() { hostPlatform = original })
	hostPlatform = "plan9"

	r := laidOut(t, map[string]string{
		"chrome_151_macos": "chrome_151/macos.json",
		"chrome_151_linux": "chrome_151/linux.json",
	})
	p, err := r.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Sorted, so it does not depend on the order a filesystem hands them over.
	if p.Name != "chrome_151_linux" {
		t.Errorf("got %q, want the first in sorted order", p.Name)
	}
	if _, err := r.Get("chrome_151_macos"); err != nil {
		t.Errorf("the named one failed: %v", err)
	}
}

func TestTheShippedCatalogueAnswersOnAPlatformItHasNoCaptureFor(t *testing.T) {
	// The exact shape of a CI failure, kept as a test: on Windows, where this
	// project ships a binary and a wheel but has captured no browser yet,
	// `chrome_151` resolved to nothing — and so did `chrome`, and so did the
	// default profile, so tlsforge.New() would not return a client at all. The
	// error even listed chrome_151 among the names it said it did not know.
	original := hostPlatform
	t.Cleanup(func() { hostPlatform = original })
	hostPlatform = "windows"

	// "chrome" is what the root package's DefaultProfile resolves to; naming it
	// here rather than importing keeps profile free of a cycle back to it.
	for _, name := range []string{"chrome_151", "chrome"} {
		p, err := Get(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(p.ClientHello) == 0 {
			t.Errorf("%s resolved to %q, which has no handshake", name, p.Name)
		}
	}
}

func TestAVersionDirectoryWithNothingInIt(t *testing.T) {
	// An interrupted capture, or a directory somebody made by hand. There is
	// nothing to fall back to, so this is the one case that still refuses.
	// A name nothing ships, or the shipped catalogue would answer for it and
	// this would be testing the fallback to that instead.
	r := laidOut(t, map[string]string{})
	if err := os.MkdirAll(filepath.Join(r.Dir(), "mybrowser_9"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := r.Get("mybrowser_9"); err == nil {
		t.Error("an empty directory resolved to something")
	}
}

func TestAFlatFileStillWorks(t *testing.T) {
	// A profile written by hand is one file with a name, and always was.
	r := laidOut(t, map[string]string{"my_browser": "my_browser.json"})
	if p, err := r.Get("my_browser"); err != nil || p.Name != "my_browser" {
		t.Errorf("%+v, %v", p, err)
	}
}

func TestAFamilyNameReachesThroughTheLayout(t *testing.T) {
	// "chrome" means the newest chrome_<major>, and a version laid out as a
	// directory has to be nameable for that to find it.
	original := hostPlatform
	t.Cleanup(func() { hostPlatform = original })
	hostPlatform = "linux"

	r := laidOut(t, map[string]string{"chrome_999_linux": "chrome_999/linux.json"})
	p, err := r.Get("chrome")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "chrome_999_linux" {
		t.Errorf("chrome resolved to %q", p.Name)
	}
}

func TestMeasuredMergesWhatIsShippedWithWhatIsKept(t *testing.T) {
	// A machine that measured one platform still resolves the shipped profile
	// for the others, so a listing showing only the local one would be saying
	// less than is true.
	r := laidOut(t, map[string]string{"chrome_151_windows": "chrome_151/windows.json"})

	var found *Group
	for i, group := range r.Measured() {
		if group.Name == "chrome_151" {
			found = &r.Measured()[i]
		}
	}
	if found == nil {
		t.Fatal("chrome_151 is not listed")
	}
	if !found.Local {
		t.Error("the group is not marked as kept here")
	}

	local := map[string]bool{}
	for _, variant := range found.Variants {
		local[variant.Platform] = variant.Local
	}
	for _, want := range []string{"macos", "linux", "windows"} {
		if _, ok := local[want]; !ok {
			t.Errorf("%s is missing from %v", want, local)
		}
	}
	if !local["windows"] {
		t.Error("the one kept here is not marked")
	}
	if local["macos"] || local["linux"] {
		t.Error("a shipped platform was marked as kept here")
	}
}

func TestMeasuredListsTheShippedProfilesOnTheirOwn(t *testing.T) {
	r := NewRegistry()
	r.SetDir("")
	groups := r.Measured()
	if len(groups) == 0 {
		t.Fatal("nothing was listed")
	}
	for _, group := range groups {
		if group.Local {
			t.Errorf("%s is marked as kept here with no directory", group.Name)
		}
	}
}

func TestSplitAndHostPlatform(t *testing.T) {
	// Only a platform this project knows counts: chrome_151 is a version whose
	// last word happens to be a number, not a platform called 151.
	for name, want := range map[string][2]string{
		"chrome_151_macos":   {"chrome_151", "macos"},
		"chrome_151_linux":   {"chrome_151", "linux"},
		"chrome_151_windows": {"chrome_151", "windows"},
		"chrome_151":         {"chrome_151", ""},
		"my_browser":         {"my_browser", ""},
	} {
		version, platform := Split(name)
		if version != want[0] || platform != want[1] {
			t.Errorf("Split(%q) = %q, %q; want %q, %q", name, version, platform, want[0], want[1])
		}
	}

	if HostPlatform() == "" {
		t.Error("this machine has no platform name")
	}
	for goos, want := range map[string]string{
		"darwin": "macos", "windows": "windows", "linux": "linux", "freebsd": "freebsd",
	} {
		if got := platformName(goos); got != want {
			t.Errorf("platformName(%q) = %q, want %q", goos, got, want)
		}
	}
}

func TestALayoutThatCannotBeReadIsNotAProfile(t *testing.T) {
	r := laidOut(t, map[string]string{"real": "real.json"})
	dir := r.Dir()

	// A directory with nothing usable in it, and a file with the wrong suffix.
	if err := os.MkdirAll(filepath.Join(dir, "empty_version"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty_version", "readme.md"), nil, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if kept := r.KeptHere(); len(kept) != 1 || kept[0] != "real" {
		t.Errorf("KeptHere = %v", kept)
	}
	if _, err := r.Get("empty_version"); err == nil {
		t.Error("a directory with no profiles in it resolved to one")
	}
}

func TestMeasuredListsAFlatProfileKeptHere(t *testing.T) {
	// One written by hand, under a name nothing shipped uses.
	r := laidOut(t, map[string]string{"my_browser": "my_browser.json"})

	var found bool
	for _, group := range r.Measured() {
		if group.Name == "my_browser" {
			found = true
			if !group.Local {
				t.Error("it is not marked as kept here")
			}
			if len(group.Variants) != 0 {
				t.Errorf("a flat profile was given platforms: %v", group.Variants)
			}
		}
	}
	if !found {
		t.Error("my_browser is not listed")
	}
}

func TestMeasuredWithADirectoryThatIsNotThere(t *testing.T) {
	// A machine that has never captured anything. The shipped profiles still
	// list, and nothing claims to be local.
	r := NewRegistry()
	r.SetDir(filepath.Join(t.TempDir(), "never-made"))
	for _, group := range r.Measured() {
		if group.Local {
			t.Errorf("%s claims to be kept here", group.Name)
		}
	}
}

func TestADirectoryThatCannotBeReadIsSkipped(t *testing.T) {
	// A version directory with the permissions taken off it. The others still
	// list rather than the whole listing failing.
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	r := laidOut(t, map[string]string{"chrome_151_macos": "chrome_151/macos.json"})
	closed := filepath.Join(r.Dir(), "chrome_999")
	if err := os.MkdirAll(closed, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(closed, "linux.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	names := r.KeptHere()
	for _, name := range names {
		if name == "chrome_999" || name == "chrome_999_linux" {
			t.Errorf("a directory that cannot be read was listed: %v", names)
		}
	}
	var listed bool
	for _, group := range r.Measured() {
		listed = listed || group.Name == "chrome_151"
	}
	if !listed {
		t.Error("the readable one stopped listing")
	}
}
