package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/cookie"
)

// planned is one file of a plan in a test: what names it, its path, and what
// the run does with it.
type planned struct {
	flag, path string
	use        fileUse
}

// planOf is a plan of files, keeping requests in output, which is emptied
// first when cleared says so.
func planOf(output string, cleared bool, files ...planned) *filePlan {
	plan := newFilePlan()
	plan.keepIn(output, cleared)
	for _, f := range files {
		plan.add(f.flag, f.path, f.use)
	}
	return plan
}

// checked fails the test unless err is a usage error saying says, or nil when
// says is empty.
func checked(t *testing.T, err error, says string) {
	t.Helper()
	switch {
	case says == "" && err != nil:
		t.Errorf("refused: %v", err)
	case says != "" && (!errors.Is(err, errUsage) || !strings.Contains(err.Error(), says)):
		t.Errorf("error = %v, want a usage error saying %q", err, says)
	}
}

// written is a file with what it holds.
func written(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// linkedTo is a symbolic link at path to target, or a skipped test where none
// can be made.
func linkedTo(t *testing.T, target, path string) string {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	return path
}

// hardLinkedTo is a second name for target, at path.
func hardLinkedTo(t *testing.T, target, path string) string {
	t.Helper()
	if err := os.Link(target, path); err != nil {
		t.Fatalf("Link: %v", err)
	}
	return path
}

// foldingCase has file names told apart with or without case for one test.
func foldingCase(t *testing.T, folds bool) {
	t.Helper()
	original := foldsCase
	t.Cleanup(func() { foldsCase = original })
	foldsCase = folds
}

func TestFilePlanRefusesTwoNamesForOneFile(t *testing.T) {
	dir := t.TempDir()
	list := written(t, filepath.Join(dir, "urls.txt"), "https://example.test/\n")
	link := linkedTo(t, list, filepath.Join(dir, "link.txt"))
	hard := hardLinkedTo(t, list, filepath.Join(dir, "hard.txt"))
	fresh := filepath.Join(dir, "new.json")
	t.Chdir(dir)

	for _, tc := range []struct {
		name  string
		files []planned
		says  string
	}{
		{"read twice", []planned{{"--input", list, readsFile}, {"--exit-headers", list, readsFile}}, ""},
		{"read, then written over", []planned{{"--input", list, readsFile}, {"--trace", list, writesFile}},
			"--trace " + list + " is the file --input names"},
		{"through a link", []planned{{"--input", list, readsFile}, {"--report", link, writesFile}},
			"--report " + link + " is the file --input names"},
		{"by a hard link", []planned{{"--input", list, readsFile}, {"--log", hard, writesFile}},
			"--log " + hard + " is the file --input names"},
		{"relative to the working directory", []planned{{"--input", "urls.txt", readsFile}, {"--trace", list, writesFile}},
			"--trace " + list + " is the file --input names"},
		{"written twice, and not there yet", []planned{{"--trace", fresh, writesFile}, {"--report", fresh, writesFile}},
			"--report " + fresh + " is the file --trace names"},
		{"spelt another way", []planned{{"--trace", fresh, writesFile},
			{"--log", filepath.Join(dir, "sub", "..", "new.json"), writesFile}}, "is the file --trace names"},
		{"a session read and saved over it", []planned{{flagCookies, list, readsFile}, {flagSaveCookies, list, writesFile}}, ""},
		{"a session saved, then read", []planned{{flagSaveCookies, list, writesFile}, {flagCookies, list, readsFile}}, ""},
		{"a session saved over the list", []planned{{"--input", list, readsFile}, {flagSaveCookies, link, writesFile}},
			"--save-cookies " + link + " is the file --input names"},
		{"two files", []planned{{"--input", list, readsFile}, {"--trace", fresh, writesFile}}, ""},
		{"named by nobody", []planned{{"--input", "", readsFile}, {"--trace", "", writesFile}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked(t, planOf("", false, tc.files...).check(), tc.says)
		})
	}
}

func TestFilePlanFoldsCaseWhereNamesDo(t *testing.T) {
	// Two files not there yet, whose names differ only in case: one file on
	// macOS and Windows, two elsewhere.
	dir := t.TempDir()
	upper, lower := filepath.Join(dir, "RUN.json"), filepath.Join(dir, "run.json")
	for _, folds := range []bool{true, false} {
		foldingCase(t, folds)
		err := planOf("", false, planned{"--trace", upper, writesFile}, planned{"--report", lower, writesFile}).check()
		if folds {
			checked(t, err, "--report "+lower+" is the file --trace names")
		} else {
			checked(t, err, "")
		}
	}
}

func TestFilePlanRefusesAFileItsOutputGoesTo(t *testing.T) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "lines.jsonl"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	fresh := filepath.Join(dir, "new.json")

	for _, tc := range []struct {
		name    string
		files   []planned
		streams []io.Writer
		says    string
	}{
		{"written by the run as well", []planned{{"--trace", file.Name(), writesFile}},
			[]io.Writer{file}, "--trace " + file.Name() + " is the file standard output is written to"},
		// Read before a line is written, and opened by the shell before that.
		{"read by the run", []planned{{"--input", file.Name(), readsFile}}, []io.Writer{file}, ""},
		{"both streams", nil, []io.Writer{file, file}, ""},
		{"a file of the run's not there yet", []planned{{"--trace", fresh, writesFile}}, []io.Writer{file}, ""},
		{"a stream that is no file", []planned{{"--trace", fresh, writesFile}}, []io.Writer{&bytes.Buffer{}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planOf("", false, tc.files...)
			for _, w := range tc.streams {
				plan.stream("standard output", w)
			}
			checked(t, plan.check(), tc.says)
		})
	}
}

func TestFilePlanRefusesAFileWhereADirectoryGoes(t *testing.T) {
	dir := t.TempDir()
	aFile := written(t, filepath.Join(dir, "a-file"), "")
	existing := filepath.Join(dir, "existing")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	x := filepath.Join(dir, "x")

	for _, tc := range []struct {
		name   string
		output string
		files  []planned
		says   string
	}{
		{"in a file the run writes", "", []planned{{"--trace", x, writesFile},
			{"--report", filepath.Join(x, "r.html"), writesFile}},
			"--report " + filepath.Join(x, "r.html") + " would be in " + x + ", the file --trace names"},
		{"the other way round", "", []planned{{"--report", filepath.Join(x, "r.html"), writesFile},
			{"--trace", x, writesFile}},
			"--report " + filepath.Join(x, "r.html") + " would be in " + x + ", the file --trace names"},
		{"in a file the run reads", "", []planned{{"--input", aFile, readsFile},
			{"--trace", filepath.Join(aFile, "t.json"), writesFile}},
			"--trace " + filepath.Join(aFile, "t.json") + " cannot be written: " + aFile + " is not a directory"},
		{"deeper in a file", "", []planned{{"--log", filepath.Join(aFile, "a", "b", "run.log"), writesFile}},
			"cannot be written: " + aFile + " is not a directory"},
		{"a directory", "", []planned{{"--trace", existing, writesFile}}, "--trace " + existing + " is a directory"},
		{"named as one", "", []planned{{flagSaveCookies, filepath.Join(dir, "sessions") + string(os.PathSeparator), writesFile}},
			"names a directory, and is written as a file"},
		{"named as one, the other way", "", []planned{{"--trace", filepath.Join(dir, "traces") + "/", writesFile}},
			"names a directory, and is written as a file"},
		{"a directory read", "", []planned{{"--input", existing, readsFile}}, ""},
		{"a file read where none can be", "", []planned{{"--input", filepath.Join(aFile, "urls.txt"), readsFile}}, ""},
		{"in directories not made yet", "", []planned{{"--trace", filepath.Join(dir, "new", "deeper", "t.json"), writesFile}}, ""},
		{"under a directory nobody has made", "",
			[]planned{{"--trace", filepath.Join(string(os.PathSeparator), "no-such-root-tlsforge", "t.json"), writesFile}}, ""},

		{"the output directory", filepath.Join(dir, "out"), []planned{{"--trace", filepath.Join(dir, "out"), writesFile}},
			"--trace " + filepath.Join(dir, "out") + " is the --output directory"},
		{"the directory the output is made in", filepath.Join(x, "out"), []planned{{"--trace", x, writesFile}},
			"--output " + filepath.Join(x, "out") + " would be in " + x + ", the file --trace names"},
		{"an output that is a file", aFile, nil, "--output " + aFile + " is not a directory"},
		{"an output in a file", filepath.Join(aFile, "out"), nil,
			"--output " + filepath.Join(aFile, "out") + " cannot be made: " + aFile + " is not a directory"},
		{"an output not made yet", filepath.Join(dir, "new", "out"),
			[]planned{{"--trace", filepath.Join(dir, "new", "out", "t.json"), writesFile}}, ""},
		{"an output there", existing, []planned{{"--trace", filepath.Join(existing, "t.json"), writesFile}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked(t, planOf(tc.output, false, tc.files...).check(), tc.says)
		})
	}
}

func TestFilePlanTakesADirectoryBeingEmptiedAsEmpty(t *testing.T) {
	// What is in the directory now will not be by the time the run writes:
	// a directory where a file goes, two names of one file, a file in the way.
	out := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(filepath.Join(out, "trace.json"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	one := written(t, filepath.Join(out, "a.json"), "")
	other := hardLinkedTo(t, one, filepath.Join(out, "b.json"))
	inTheWay := written(t, filepath.Join(out, "blocked"), "")
	files := []planned{
		{"--trace", filepath.Join(out, "trace.json"), writesFile},
		{"--report", one, writesFile},
		{"--log", other, writesFile},
		{flagSaveCookies, filepath.Join(inTheWay, "s.json"), writesFile},
	}
	checked(t, planOf(out, true, files...).check(), "")

	// Not emptied, each is what it is.
	checked(t, planOf(out, false, files...).check(), "is a directory")
	checked(t, planOf(out, false, files[1:]...).check(), "--log "+other+" is the file --report names")
	checked(t, planOf(out, false, files[3:]...).check(), "cannot be written: "+inTheWay+" is not a directory")

	// Two names spelt alike are one file there all the same.
	same := filepath.Join(out, "run.json")
	checked(t, planOf(out, true, planned{"--trace", same, writesFile}, planned{"--report", same, writesFile}).check(),
		"--report "+same+" is the file --trace names")
}

func TestLocated(t *testing.T) {
	dir := t.TempDir()
	real := resolve(dir)
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := linkedTo(t, filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	for _, tc := range []struct{ path, cwd, want string }{
		// Followed as far as it is there, and the rest as it is spelt.
		{filepath.Join(link, "new", "file.json"), "", filepath.Join(real, "real", "new", "file.json")},
		{link, "", filepath.Join(real, "real")},
		{"new/file.json", dir, filepath.Join(real, "new", "file.json")},
		{"link/x", dir, filepath.Join(real, "real", "x")},
		{dir, "", real},
		// Nothing of it there: as it is spelt, from the top.
		{filepath.Join(string(os.PathSeparator), "no-such-root-tlsforge", "x"), "",
			filepath.Join(resolve(string(os.PathSeparator)), "no-such-root-tlsforge", "x")},
	} {
		if got := located(tc.path, tc.cwd); got != tc.want {
			t.Errorf("located(%q, %q) = %q, want %q", tc.path, tc.cwd, got, tc.want)
		}
	}
}

func TestSpelt(t *testing.T) {
	sep := string(os.PathSeparator)
	for _, tc := range []struct{ dir, at, given, want string }{
		// What is not there yet comes off the path as it was given.
		{sep + "private" + sep + "var" + sep + "a-file", sep + "private" + sep + "var" + sep + "a-file" + sep + "out",
			sep + "var" + sep + "a-file" + sep + "out", sep + "var" + sep + "a-file"},
		{sep + "w" + sep + "a-file", sep + "w" + sep + "a-file" + sep + "x" + sep + "y", "a-file/x/y", "a-file"},
		// Given otherwise than it ends: the directory as it is located.
		{sep + "w" + sep + "a-file", sep + "w" + sep + "a-file" + sep + "y", "elsewhere", sep + "w" + sep + "a-file"},
		// Nothing would be left of it.
		{sep, sep + "out", sep + "out", sep},
	} {
		if got := spelt(tc.dir, tc.at, tc.given); got != tc.want {
			t.Errorf("spelt(%q, %q, %q) = %q, want %q", tc.dir, tc.at, tc.given, got, tc.want)
		}
	}
}

// contentsOf is every file under dir and what it holds, by its path.
func contentsOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	held := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			held[path] = string(data)
			return err
		}
		held[path] = entry.Type().String()
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	return held
}

// sameContents fails the test unless dir holds what it held, and nothing more.
func sameContents(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	after := contentsOf(t, dir)
	paths := slices.Collect(maps.Keys(before))
	for path := range after {
		if _, ok := before[path]; !ok {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	for _, path := range paths {
		if before[path] != after[path] {
			t.Errorf("%s holds %q, and held %q", path, after[path], before[path])
		}
	}
}

func TestFetchRefusesTwoFlagsForOneFileAndTouchesNothing(t *testing.T) {
	server, asked := replying(t, 200)
	dir := t.TempDir()
	list := written(t, filepath.Join(dir, "urls.txt"), server.URL+"\n")
	session := written(t, filepath.Join(dir, "session.json"), `{"sets":[]}`)
	fields := written(t, filepath.Join(dir, "fields.json"), `{"fields": []}`)
	trace := written(t, filepath.Join(dir, "run.trace.json"), "[\n]\n")
	report := written(t, filepath.Join(dir, "report.html"), "<!doctype html>the last run")
	link := linkedTo(t, list, filepath.Join(dir, "link.txt"))
	hard := hardLinkedTo(t, session, filepath.Join(dir, "hard.json"))
	before := contentsOf(t, dir)
	out, x := filepath.Join(dir, "out"), filepath.Join(dir, "x")

	for _, tc := range []struct {
		args []string
		says string
	}{
		{[]string{"--input", list, "--trace", list}, "--trace " + list + " is the file --input names"},
		{[]string{"--input", list, "--report=" + list}, "--report " + list + " is the file --input names"},
		{[]string{"--input", list, "--save-cookies", list}, "--save-cookies " + list + " is the file --input names"},
		{[]string{"--input", list, "--log", link}, "--log " + link + " is the file --input names"},
		{[]string{"--cookies", session, "--trace", session, server.URL}, "--trace " + session + " is the file --cookies names"},
		{[]string{"--cookies", session, "--report=" + hard, server.URL}, "--report " + hard + " is the file --cookies names"},
		{[]string{"--exit-headers", fields, "--save-cookies", fields, server.URL},
			"--save-cookies " + fields + " is the file --exit-headers names"},
		{[]string{"--trace", trace, "--report=" + trace, server.URL}, "--report " + trace + " is the file --trace names"},
		{[]string{"--save-cookies", report, "--report=" + report, server.URL},
			"--report " + report + " is the file --save-cookies names"},
		{[]string{"--log", trace, "--report=" + trace, server.URL}, "--report " + trace + " is the file --log names"},
		{[]string{"-o", out, "--trace", out, server.URL}, "--trace " + out + " is the --output directory"},
		{[]string{"--trace", x, "-o", filepath.Join(x, "out"), server.URL},
			"--output " + filepath.Join(x, "out") + " would be in " + x + ", the file --trace names"},
		{[]string{"--trace", x, "--report=" + filepath.Join(x, "r.html"), server.URL},
			"--report " + filepath.Join(x, "r.html") + " would be in " + x + ", the file --trace names"},
		{[]string{"--trace", dir, server.URL}, "--trace " + dir + " is a directory"},
		{[]string{"--save-cookies", filepath.Join(dir, "sessions") + "/", server.URL},
			"--save-cookies " + filepath.Join(dir, "sessions") + "/ names a directory, and is written as a file"},
		{[]string{"--log", filepath.Join(list, "run.log"), server.URL},
			"--log " + filepath.Join(list, "run.log") + " cannot be written: " + list + " is not a directory"},
		{[]string{"-o", filepath.Join(list, "out"), server.URL},
			"--output " + filepath.Join(list, "out") + " cannot be made: " + list + " is not a directory"},
		{[]string{"-o", list, server.URL}, "--output " + list + " is not a directory"},
	} {
		code, _, stderr := exec(t, append([]string{"fetch"}, tc.args...)...)
		if code != 2 || !strings.Contains(stderr, "tlsforge: bad usage: "+tc.says) {
			t.Errorf("%q: exit code = %d, want 2 and %q\n%s", tc.args, code, tc.says, stderr)
		}
	}
	// Refused before anybody was asked anything, and before anything was
	// read again, emptied, opened or made.
	if got := asked.Load(); got != 0 {
		t.Errorf("the server was asked %d times", got)
	}
	sameContents(t, dir, before)
}

func TestFetchRefusesToWriteOverItsOwnOutput(t *testing.T) {
	server, asked := replying(t, 200)
	for _, stream := range []string{"standard output", "standard error"} {
		t.Run(stream, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "said.txt"))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			defer func() { _ = file.Close() }()
			var other bytes.Buffer
			var stdout, stderr io.Writer = file, &other
			if stream == "standard error" {
				stdout, stderr = &other, file
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if code := run(ctx, []string{"fetch", "--trace", file.Name(), server.URL}, stdout, stderr); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			said, _ := os.ReadFile(file.Name())
			want := "--trace " + file.Name() + " is the file " + stream + " is written to"
			if !strings.Contains(string(said)+other.String(), want) {
				t.Errorf("the refusal was not said:\n%s%s", said, other.String())
			}
		})
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("the server was asked %d times", got)
	}
}

func TestFetchSavesASessionBackWhereItStarted(t *testing.T) {
	// One file to start from and to save to is what a session kept between
	// runs is: read first, and added to at the end.
	server := cookieEcho(t)
	path := filepath.Join(t.TempDir(), "session.json")
	if code, _, stderr := exec(t, "fetch", "-k", "--save-cookies", path, server.URL+"/set"); code != 0 {
		t.Fatalf("the first run: exit code = %d\n%s", code, stderr)
	}
	code, stdout, stderr := exec(t, "fetch", "-k", "--cookies", path, "--save-cookies", path, server.URL+"/")
	if code != 0 || stdout != "tier=gold visitor=42" {
		t.Fatalf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	data, _ := os.ReadFile(path)
	if file, err := cookie.Load(data); err != nil || len(file.Sets) != 2 {
		t.Errorf("the file holds %v (%v), want both runs' sessions", file, err)
	}
}

func TestClearOutputDirKeepsASessionTheRunAddsTo(t *testing.T) {
	// A .json file of sessions is read so that the run's is added to it, and
	// emptied first, every session before this run's would be lost.
	server := cookieEcho(t)
	out := filepath.Join(t.TempDir(), "out")
	sessions := written(t, filepath.Join(out, "sessions.json"), `{"sets":[]}`)
	code, _, stderr := exec(t, "fetch", "-k", "-o", out, "--clear-output-dir", "--save-cookies", sessions, server.URL+"/set")
	if code != 2 || !strings.Contains(stderr, "holds --save-cookies "+sessions+", which the run reads") {
		t.Errorf("exit code = %d, want 2\n%s", code, stderr)
	}
	untouched(t, out, "sessions.json")

	// A cookies.txt is written anew whatever it held, so it is emptied with
	// everything else and written once the run is over.
	jar := written(t, filepath.Join(out, "cookies.txt"), "# the last run's\n")
	if err := os.Remove(sessions); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	tree(t, out, "earlier.html")
	if code, _, stderr := exec(t, "fetch", "-k", "-o", out, "--clear-output-dir", "--save-cookies", jar,
		server.URL+"/set"); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if data, _ := os.ReadFile(jar); !strings.Contains(string(data), "visitor\t42") {
		t.Errorf("the session was not written anew:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(out, "earlier.html")); !os.IsNotExist(err) {
		t.Errorf("the directory was not emptied: %v", err)
	}
}

// meanwhile is a server that changes the file system while it is asked, so
// that what a run checked before it began is not so by the time it writes:
// as when a disk fills, or somebody tidies up during a run. It answers with a
// cookie, so that a run has a session to save, or with nothing at all for a
// status of 0.
func meanwhile(t *testing.T, status int, change func()) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		change()
		if status == 0 {
			if hijacked, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = hijacked.Close()
			}
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "visitor", Value: "42", Path: "/"})
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, "the page")
	}))
	t.Cleanup(server.Close)
	return server, &asked
}

// inTheWay is what MkdirAll says of dir when a file is where it would go:
// "not a directory" on Unix, and on Windows the words of
// ERROR_PATH_NOT_FOUND, which syscall.ENOTDIR is there.
func inTheWay(dir string) string {
	return (&fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}).Error()
}

// fileIn puts a file at path, where a directory was to go.
func fileIn(t *testing.T, path string) func() {
	return func() {
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Errorf("WriteFile: %v", err)
		}
	}
}
