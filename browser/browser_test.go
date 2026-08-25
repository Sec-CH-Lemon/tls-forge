package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBrowser writes an executable that records its arguments and then waits,
// which is close enough to a browser for everything this package does with one.
func fakeBrowser(t *testing.T, name string, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fakes are shell scripts")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("writing the fake: %v", err)
	}
	return path
}

func TestFindAnExplicitPath(t *testing.T) {
	path := fakeBrowser(t, "my-browser", "exit 0\n")

	found, err := Find(path)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if found.Path != path {
		t.Errorf("Path = %q, want %q", found.Path, path)
	}
	if found.Name != "custom" {
		t.Errorf("Name = %q, want custom", found.Name)
	}
}

func TestFindAnExplicitPathThatIsNotThere(t *testing.T) {
	if _, err := Find("/no/such/browser"); err == nil {
		t.Error("expected an error for a path that does not exist")
	}
}

func TestFindRejectsAnExplicitDirectory(t *testing.T) {
	if _, err := Find(t.TempDir()); err == nil {
		t.Error("expected a directory to be rejected")
	}
}

func TestFindAnUnknownName(t *testing.T) {
	_, err := Find("netscape")
	if err == nil {
		t.Fatal("expected an error")
	}
	// The message has to list what IS known, or the caller is left guessing.
	if !strings.Contains(err.Error(), "chrome") {
		t.Errorf("error = %q, want it to list the known browsers", err)
	}
}

func TestFindSearchesInOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"fake-chromium", "fake-edge"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("writing the fake: %v", err)
		}
	}

	f := finder{
		order: []string{"chrome", "chromium", "edge"},
		candidates: map[string][]string{
			"chrome":   {filepath.Join(dir, "absent")},
			"chromium": {filepath.Join(dir, "fake-chromium")},
			"edge":     {filepath.Join(dir, "fake-edge")},
		},
	}

	found, err := f.find("")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if found.Name != "chromium" {
		t.Errorf("Name = %q, want chromium — the first one present", found.Name)
	}

	byName, err := f.find("edge")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if byName.Name != "edge" {
		t.Errorf("Name = %q, want edge", byName.Name)
	}
}

func TestFindWhenNothingIsInstalled(t *testing.T) {
	f := finder{
		order:      []string{"chrome"},
		candidates: map[string][]string{"chrome": {"/definitely/not/here"}},
	}
	_, err := f.find("")
	if err == nil || !strings.Contains(err.Error(), "no Chromium-based browser") {
		t.Fatalf("error = %v, want a not-found complaint", err)
	}
}

func TestFindOnPath(t *testing.T) {
	// A bare name is resolved through PATH, and Windows will only resolve one
	// that carries an extension from PATHEXT — an extensionless file is not an
	// executable there, however its permission bits look. The candidate stays
	// bare either way: LookPath is what appends the extension.
	name := "acme-browser"
	if runtime.GOOS == "windows" {
		name += ".bat"
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing the fake: %v", err)
	}
	t.Setenv("PATH", dir)

	f := finder{order: []string{"acme"}, candidates: map[string][]string{"acme": {"acme-browser"}}}
	found, err := f.find("")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if filepath.Base(found.Path) != name {
		t.Errorf("Path = %q, want it to end in %q", found.Path, name)
	}
}

func TestFindSkipsBareNamesThatArePathsAndDirectories(t *testing.T) {
	dir := t.TempDir()
	// A directory at the candidate path is not a browser, and Stat alone would
	// say it exists.
	if err := os.Mkdir(filepath.Join(dir, "not-a-file"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("PATH", t.TempDir())

	f := finder{
		order:      []string{"acme"},
		candidates: map[string][]string{"acme": {filepath.Join(dir, "not-a-file"), "missing-from-path"}},
	}
	if _, err := f.find(""); err == nil {
		t.Error("a directory should not resolve as a browser")
	}
}

func TestDefaultTablesAreConsistent(t *testing.T) {
	// Every browser in the search order must have candidate locations, or the
	// search silently skips it.
	for _, name := range searchOrder {
		if len(candidates[name]) == 0 {
			t.Errorf("%q is in the search order but has no candidate locations", name)
		}
	}
}

func TestOpenLaunchesAndCleansUp(t *testing.T) {
	// The fake records the arguments it was given, then waits to be killed —
	// which is what a browser does.
	output := filepath.Join(t.TempDir(), "args")
	path := fakeBrowser(t, "recorder", fmt.Sprintf(`printf '%%s\n' "$@" > %q
mv %q %q
sleep 30
`, output+".tmp", output+".tmp", output))

	found, err := Find(path)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stop, err := found.Open(ctx, "https://localhost:1234/", Options{
		Headless: true,
		Args:     []string{"--custom-flag"},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var recorded string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if data, err := os.ReadFile(output); err == nil && len(data) > 0 {
			recorded = string(data)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()

	if recorded == "" {
		t.Fatal("the fake browser was never launched")
	}
	for _, want := range []string{"--user-data-dir=", "--ignore-certificate-errors", "--headless=new",
		"--custom-flag", "https://localhost:1234/"} {
		if !strings.Contains(recorded, want) {
			t.Errorf("launch arguments do not include %q:\n%s", want, recorded)
		}
	}

	// The throwaway profile directory is what keeps --ignore-certificate-errors
	// away from the user's real browser profile, and it must not be left behind.
	var userDataDir string
	for _, line := range strings.Split(recorded, "\n") {
		if strings.HasPrefix(line, "--user-data-dir=") {
			userDataDir = strings.TrimPrefix(line, "--user-data-dir=")
		}
	}
	if userDataDir == "" {
		t.Fatal("no --user-data-dir was passed")
	}
	if _, err := os.Stat(userDataDir); !os.IsNotExist(err) {
		t.Errorf("the temporary profile directory %s survived stop()", userDataDir)
	}
}

func TestOpenWithoutHeadless(t *testing.T) {
	output := filepath.Join(t.TempDir(), "args")
	path := fakeBrowser(t, "recorder", `printf '%s\n' "$@" > `+output+"\n")

	found, _ := Find(path)
	stop, err := found.Open(context.Background(), "https://localhost/", Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stop()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if data, err := os.ReadFile(output); err == nil && len(data) > 0 {
			if strings.Contains(string(data), "--headless") {
				t.Error("headless was passed when it was not asked for")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the fake browser was never launched")
}

func TestOpenReportsAnUnusableTempDirectory(t *testing.T) {
	// The throwaway profile directory is created before the browser starts. If
	// it cannot be, the launch must be refused rather than falling back to the
	// user's real profile — which is where --ignore-certificate-errors would
	// then apply.
	if runtime.GOOS == "windows" {
		t.Skip("TMPDIR is not the mechanism on Windows")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	found := &Browser{Name: "fake", Path: "/bin/sh"}
	if _, err := found.Open(context.Background(), "https://localhost/", Options{}); err == nil {
		t.Error("expected an error when the profile directory cannot be created")
	}
}

func TestOpenReportsALaunchFailure(t *testing.T) {
	// A file that exists but cannot be executed: Find only proves it is there.
	path := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(path, []byte("not a program"), 0o644); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	found, err := Find(path)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if _, err := found.Open(context.Background(), "https://localhost/", Options{}); err == nil {
		t.Error("expected a launch failure")
	}
}
