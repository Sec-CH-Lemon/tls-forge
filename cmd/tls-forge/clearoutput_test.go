package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// tree writes files under dir, each a path relative to it, with the directories
// they are in.
func tree(t *testing.T, dir string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(path), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
}

// untouched fails the test unless every path is still in dir.
func untouched(t *testing.T, dir string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(filepath.Join(dir, path)); err != nil {
			t.Errorf("%s was removed from %s: %v", path, dir, err)
		}
	}
}

// notRoot skips a test that needs a permission to be refused, which root is
// never refused.
func notRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root is refused no permission")
	}
}

func TestClearOutputDirEmptiesTheDirectoryFirst(t *testing.T) {
	server, _ := replying(t, 200)
	tmp := t.TempDir()
	out := filepath.Join(tmp, "out")
	// What an earlier run left, a hidden file, a directory of its own, and a link
	// to a file elsewhere, which goes and leaves the file where it was.
	tree(t, out, "127.0.0.1-old-1.txt", ".hidden", "sub/deeper/x.txt")
	elsewhere := filepath.Join(tmp, "elsewhere.txt")
	tree(t, tmp, "elsewhere.txt")
	if err := os.Symlink(elsewhere, filepath.Join(out, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	before, err := os.Stat(out)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	// The trace in it and the report beside what is kept are written after it
	// is emptied, and are there.
	trace := filepath.Join(out, "run.trace.json")
	code, _, stderr := exec(t, "fetch", "-o", out, "--clear-output-dir", "--trace", trace, "--report", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "cleared "+out+": 4 entries removed\n") {
		t.Errorf("stderr does not say what was cleared:\n%s", stderr)
	}
	kept := keptIn(t, out)
	for _, gone := range []string{"127.0.0.1-old-1.txt", ".hidden", "sub", "link"} {
		if slices.Contains(kept, gone) {
			t.Errorf("%s was left in %v", gone, kept)
		}
	}
	page, log, report := false, false, false
	for _, name := range kept {
		page = page || strings.HasSuffix(name, "-1.txt")
		log = log || strings.HasSuffix(name, "-1.log")
		report = report || strings.HasPrefix(name, "report-")
	}
	if !page || !log || !report || !slices.Contains(kept, "run.trace.json") {
		t.Errorf("the run kept %v", kept)
	}
	untouched(t, tmp, "elsewhere.txt")
	// The directory itself stays, as it was.
	after, err := os.Stat(out)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Errorf("the directory was replaced: %v, %v", after, err)
	}
}

func TestClearOutputDirOfOneNotThereYet(t *testing.T) {
	server, _ := replying(t, 200)
	out := filepath.Join(t.TempDir(), "new")
	code, _, stderr := exec(t, "fetch", "-o", out, "--clear-output-dir", server.URL)
	if code != 0 || !strings.Contains(stderr, "cleared "+out+": 0 entries removed\n") {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if len(keptIn(t, out)) != 3 {
		t.Errorf("the new directory holds %v", keptIn(t, out))
	}
}

func TestClearOutputDirNeedsOutput(t *testing.T) {
	code, _, stderr := exec(t, "fetch", "--clear-output-dir", "https://example.test/")
	if code != 2 || !strings.Contains(stderr, "--clear-output-dir requires --output") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestClearOutputDirRefusesADirectoryWhoseLossIsADisaster(t *testing.T) {
	server, _ := replying(t, 200)
	for _, tc := range []struct {
		name string
		// set lays out the case under tmp, and returns the arguments to fetch
		// and the directory that must be left as it was.
		set  func(t *testing.T, tmp string) (args []string, kept string)
		want string
	}{
		{"the directory the command runs in", func(t *testing.T, tmp string) ([]string, string) {
			t.Chdir(tmp)
			return []string{"-o", ".", server.URL}, tmp
		}, "is the directory the command runs in, or holds it"},
		{"one that holds it", func(t *testing.T, tmp string) ([]string, string) {
			t.Chdir(filepath.Join(tmp, "a"))
			return []string{"-o", "..", server.URL}, tmp
		}, "is the directory the command runs in, or holds it"},
		{"the home directory", func(t *testing.T, tmp string) ([]string, string) {
			t.Setenv("HOME", filepath.Join(tmp, "a"))
			return []string{"-o", filepath.Join(tmp, "a"), server.URL}, tmp
		}, "is the home directory, or holds it"},
		{"one that holds it", func(t *testing.T, tmp string) ([]string, string) {
			t.Setenv("HOME", filepath.Join(tmp, "a"))
			return []string{"-o", tmp, server.URL}, tmp
		}, "is the home directory, or holds it"},
		{"one with a repository in it", func(t *testing.T, tmp string) ([]string, string) {
			tree(t, tmp, "a/project/.git/HEAD")
			return []string{"-o", tmp, server.URL}, tmp
		}, "holds a git repository, "},
		{"the list it reads", func(t *testing.T, tmp string) ([]string, string) {
			list := filepath.Join(tmp, "a", "urls.txt")
			if err := os.WriteFile(list, []byte(server.URL+"\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			return []string{"-o", tmp, "--input", list}, tmp
		}, "holds --input "},
		{"the session it starts from", func(t *testing.T, tmp string) ([]string, string) {
			return []string{"-o", tmp, "--cookies", filepath.Join(tmp, "a", "b"), server.URL}, tmp
		}, "holds --cookies"},
		{"the exit fields it lays over its own", func(t *testing.T, tmp string) ([]string, string) {
			fields := filepath.Join(tmp, "a", "exit-headers.json")
			if err := os.WriteFile(fields, []byte(`{"fields": []}`), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			return []string{"-o", tmp, "--exit-headers", fields, server.URL}, tmp
		}, "holds --exit-headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := resolve(t.TempDir())
			tree(t, tmp, "a/b")
			args, kept := tc.set(t, tmp)
			code, _, stderr := exec(t, append([]string{"fetch", "--clear-output-dir"}, args...)...)
			if code != 2 || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "nothing was removed") {
				t.Errorf("exit code = %d, want 2 and %q\n%s", code, tc.want, stderr)
			}
			untouched(t, kept, "a/b")
		})
	}
}

func TestClearOutputDirRefusesWhereItsOwnOutputGoes(t *testing.T) {
	// Standard output or error redirected to a file in the directory: emptied,
	// the run would go on writing to a file nobody can open any more.
	server, _ := replying(t, 200)
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			tree(t, out, "earlier.txt")
			file, err := os.Create(filepath.Join(out, "lines.jsonl"))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			defer func() { _ = file.Close() }()
			var other bytes.Buffer
			var stdout, stderr io.Writer = file, &other
			if stream == "stderr" {
				stdout, stderr = &other, file
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{"fetch", "-o", out, "--clear-output-dir", "--json", server.URL}
			if code := run(ctx, args, stdout, stderr); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			said, _ := os.ReadFile(file.Name())
			if !strings.Contains(string(said)+other.String(), "which the run's output is written to") {
				t.Errorf("the refusal was not said:\n%s%s", said, other.String())
			}
			untouched(t, out, "earlier.txt", "lines.jsonl")
		})
	}
}

func TestClearOutputDirThatCannotBeCleared(t *testing.T) {
	notRoot(t)
	server, _ := replying(t, 200)
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, out string) string
		want string
	}{
		{"a directory in it that cannot be emptied", func(t *testing.T, out string) string {
			tree(t, out, "locked/x.txt")
			lock(t, filepath.Join(out, "locked"), 0o500)
			return out
		}, "permission denied"},
		{"a directory that cannot be read", func(t *testing.T, out string) string {
			tree(t, out, "x.txt")
			lock(t, out, 0o300)
			return out
		}, "permission denied"},
		{"one that cannot be reached", func(t *testing.T, out string) string {
			tree(t, out, "x.txt")
			lock(t, filepath.Dir(out), 0o000)
			return out
		}, "permission denied"},
		{"a file", func(t *testing.T, out string) string {
			tree(t, out, "x.txt")
			return filepath.Join(out, "x.txt")
		}, "is not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			target := tc.set(t, out)
			code, _, stderr := exec(t, "fetch", "-o", target, "--clear-output-dir", server.URL)
			if code != 1 || !strings.Contains(stderr, "--clear-output-dir") || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit code = %d, want 1 and %q\n%s", code, tc.want, stderr)
			}
		})
	}
}

// lock gives a path the mode, and the test's clean-up back the one to remove
// it with.
func lock(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
}

func TestClearOutputDirWithNowhereToStand(t *testing.T) {
	// The directory the command runs in cannot be told, so neither can whether
	// the one to empty holds it.
	original := workingDir
	t.Cleanup(func() { workingDir = original })
	workingDir = func() (string, error) { return "", errors.New("getwd: no such file or directory") }
	if _, err := clearOutput("out", nil, nil); err == nil || !strings.Contains(err.Error(), "getwd") {
		t.Errorf("clearOutput = %v", err)
	}
}

func TestRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, dir, cwd, home string
		reads                map[string]string
		want                 string
	}{
		{"the root", "/", "/x", "/h", nil, "is the root of the file system"},
		{"a directory of its own", "/x/out", "/x", "/h", nil, ""},
		// A name that begins with the other's is not in it.
		{"beside the one the command runs in", "/x/run", "/x/runner", "", nil, ""},
		{"beside the home directory", "/home/me", "/x", "/home/meg", nil, ""},
		// No home to keep from harm, and a file read elsewhere, or not there.
		{"no home", "/x/out", "/x", "", map[string]string{"--input": "elsewhere.txt", "--cookies": ""}, ""},
		{"a file read in it, by a relative path", "/x/out", "/x", "", map[string]string{"--input": "out/list.txt"},
			"holds --input out/list.txt, which the run reads"},
	} {
		if got := refusal(tc.dir, tc.cwd, tc.home, tc.reads); got != tc.want {
			t.Errorf("%s: refusal = %q, want %q", tc.name, got, tc.want)
		}
	}
	// With HOME unset there is no home directory to refuse.
	t.Setenv("HOME", "")
	if got := home(); got != "" {
		t.Errorf("home with HOME unset = %q", got)
	}
}

func TestStreamFiles(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	closed, err := os.Create(filepath.Join(t.TempDir(), "closed.txt"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = closed.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = file.Close(); _ = null.Close() }()
	// A file, and not a buffer, a device, or a file that cannot be asked.
	got := streamFiles(file, &bytes.Buffer{}, null, closed)
	if info, err := file.Stat(); err != nil || len(got) != 1 || !os.SameFile(got[0], info) {
		t.Errorf("streamFiles = %v", got)
	}
}
