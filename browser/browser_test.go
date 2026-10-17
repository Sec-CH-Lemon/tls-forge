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

func TestExpandSaysWhereAPathUnderAWindowsFolderIs(t *testing.T) {
	original := getenv
	t.Cleanup(func() { getenv = original })
	getenv = func(name string) string {
		return map[string]string{"LOCALAPPDATA": `C:\Users\me\AppData\Local`, "HOMEDRIVE": "C:"}[name]
	}
	for _, tc := range []struct {
		location, want string
		ok             bool
	}{
		{`%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`, `C:\Users\me\AppData\Local\Google\Chrome\Application\chrome.exe`, true},
		{`%HOMEDRIVE%\%LOCALAPPDATA%`, `C:\C:\Users\me\AppData\Local`, true},
		{"/opt/google/chrome/chrome", "/opt/google/chrome/chrome", true},
		{"google-chrome", "google-chrome", true},
		// Not set: nowhere, rather than \Chromium\… looked for where the run is.
		{`%PROGRAMDATA%\Chromium\chrome.exe`, "", false},
		{`%LOCALAPPDATA%\%NOT_SET%\chrome.exe`, "", false},
		// Not a variable: a percent sign is a character of a name.
		{"100% chrome", "100% chrome", true},
	} {
		got, ok := expand(tc.location)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("expand(%q) = %q, %v; want %q, %v", tc.location, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFindABrowserInstalledForTheUserAlone(t *testing.T) {
	// The table's own %LOCALAPPDATA% entries, against a folder of fakes: each
	// written where its entry says, whatever this machine's separator.
	appData := filepath.Join(t.TempDir(), "appdata")
	original := getenv
	t.Cleanup(func() { getenv = original })
	getenv = func(name string) string {
		if name == "LOCALAPPDATA" {
			return appData
		}
		return ""
	}
	for _, name := range []string{"chrome", "chromium", "brave"} {
		var own []string
		for _, location := range candidates[name] {
			if strings.HasPrefix(location, "%LOCALAPPDATA%") {
				own = append(own, location)
			}
		}
		if len(own) != 1 {
			t.Fatalf("%s has %d entries under %%LOCALAPPDATA%%", name, len(own))
		}
		path, _ := expand(own[0])
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("writing the fake: %v", err)
		}
		f := finder{candidates: map[string][]string{name: own}, order: []string{name}}
		found, err := f.find(name)
		if err != nil || found.Path != path || found.Name != name {
			t.Errorf("%s: found %+v, %v; want it at %s", name, found, err, path)
		}
	}

	// On a machine that does not name the folder, nothing is under it: left
	// as \Google\Chrome\…, which a Unix path takes for one file name, it would
	// be looked for in the working directory, and found there.
	if runtime.GOOS == "windows" {
		return
	}
	getenv = func(string) string { return "" }
	t.Chdir(t.TempDir())
	if err := os.WriteFile(`\Google\Chrome\Application\chrome.exe`, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing the decoy: %v", err)
	}
	var own string
	for _, location := range candidates["chrome"] {
		if strings.HasPrefix(location, `%LOCALAPPDATA%\Google\Chrome\`) {
			own = location
		}
	}
	f := finder{candidates: map[string][]string{"chrome": {own}}, order: []string{"chrome"}}
	if found, err := f.find(""); own == "" || err == nil {
		t.Errorf("found %+v under a folder nobody named", found)
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
	// which is what a browser does — or for ten seconds, so that a run that
	// failed to kill it does not leave it behind for long.
	output := filepath.Join(t.TempDir(), "args")
	path := fakeBrowser(t, "recorder", fmt.Sprintf(`printf '%%s\n' "$@" > %q
mv %q %q
sleep 10
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
