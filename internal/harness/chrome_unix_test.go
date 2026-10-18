//go:build unix

package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stand is a browser standing in for Chrome: it writes its arguments down,
// and starts a process of its own, as a browser does, that waits ten seconds
// at most. With --dump-dom it prints dump and ends with code, leaving that
// process behind, unless dump is hang; without, it waits for it.
type stand struct {
	path, args, child string
}

func standIn(t *testing.T, dump string, code int) stand {
	t.Helper()
	dir := t.TempDir()
	s := stand{path: filepath.Join(dir, "chrome"), args: filepath.Join(dir, "args"), child: filepath.Join(dir, "child")}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %[1]q.tmp && mv %[1]q.tmp %[1]q
sleep 10 &
echo $! > %[2]q.tmp && mv %[2]q.tmp %[2]q
for a; do
	if [ "$a" = --dump-dom ] && [ %[3]q != hang ]; then
		printf '%%s' %[3]q
		exit %[4]d
	fi
done
wait
`, s.args, s.child, dump, code)
	if err := os.WriteFile(s.path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return s
}

// written is what the stand-in wrote to path, once it has.
func written(t *testing.T, path string) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
	}
	t.Fatalf("the stand-in never wrote %s", path)
	return ""
}

func gone(t *testing.T, path string) bool {
	t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(written(t, path)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
	}
	return false
}

func TestChromeIsRunAsTheFixturesWereMeasuredAndEndedWhole(t *testing.T) {
	s := standIn(t, "", 0)
	dir := t.TempDir()
	stop, err := Chrome{Path: s.path}.Open(context.Background(), "https://www.example.com:1/run/x", dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	args := strings.Split(strings.TrimSpace(written(t, s.args)), "\n")
	want := append(flags(dir, ""), "https://www.example.com:1/run/x")
	if !slices.Equal(args, want) {
		t.Errorf("run with %q,\nwant %q", args, want)
	}
	if !slices.Contains(args, "--headless=new") || !slices.Contains(args, "--user-data-dir="+dir) || !slices.Contains(args, "--lang=en-US") ||
		slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--ignore-certificate-errors-spki-list") }) {
		t.Errorf("run with %q", args)
	}
	// Once it has started a process of its own, it is stopped.
	written(t, s.child)
	stop()
	if !gone(t, s.child) {
		t.Error("what the browser started outlived it")
	}
	// Its context done, it is ended as well.
	other := standIn(t, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	stop, err = Chrome{Path: other.path}.Open(ctx, "https://www.example.com:1/", t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	written(t, other.child)
	cancel()
	if !gone(t, other.child) {
		t.Error("what the browser started outlived its context")
	}
	stop()
	if _, err := (Chrome{Path: filepath.Join(t.TempDir(), "none")}).Open(context.Background(), "x", t.TempDir()); err == nil ||
		!strings.HasPrefix(err.Error(), "harness: launching ") {
		t.Errorf("Open of no browser: %v", err)
	}
}

func TestChromeTrustingAServerTakesItsCertificateAsASites(t *testing.T) {
	s := standIn(t, "", 0)
	dir := t.TempDir()
	chrome := Chrome{Path: s.path}
	stop, err := chrome.trusting("a2V5").Open(context.Background(), "https://www.example.com:1/run/x", dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	args := strings.Split(strings.TrimSpace(written(t, s.args)), "\n")
	want := append(flags(dir, ""), "--ignore-certificate-errors-spki-list=a2V5", "https://www.example.com:1/run/x")
	if !slices.Equal(args, want) {
		t.Errorf("run with %q,\nwant %q", args, want)
	}
	stop()
	// The browser it was told by is as it was.
	if chrome.trusted != "" {
		t.Errorf("trusted %q", chrome.trusted)
	}
	dumping := standIn(t, "<p>x</p>", 0)
	if _, err := (Chrome{Path: dumping.path}).trusting("a2V5").DumpDOM(context.Background(), "http://127.0.0.1:1/a"); err != nil ||
		!strings.Contains(written(t, dumping.args), "--ignore-certificate-errors-spki-list=a2V5\n--dump-dom\n") {
		t.Errorf("DumpDOM: %v, run with %q", err, written(t, dumping.args))
	}
}

func TestADumpIsWhatTheBrowserWroteInAProfileMadeForIt(t *testing.T) {
	s := standIn(t, "<html>dumped</html>", 0)
	got, err := Chrome{Path: s.path}.DumpDOM(context.Background(), "http://127.0.0.1:1/a")
	if err != nil || string(got) != "<html>dumped</html>" {
		t.Fatalf("DumpDOM: %q, %v", got, err)
	}
	args := strings.Split(strings.TrimSpace(written(t, s.args)), "\n")
	if args[len(args)-2] != "--dump-dom" || args[len(args)-1] != "http://127.0.0.1:1/a" {
		t.Errorf("run with %q", args)
	}
	profile := strings.TrimPrefix(args[3], "--user-data-dir=")
	if _, err := os.Stat(filepath.Dir(profile)); !os.IsNotExist(err) {
		t.Errorf("the profile made for it is still there: %v", err)
	}
	// What it left running does not keep the dump waiting, and is ended.
	if !gone(t, s.child) {
		t.Error("what the browser started outlived the dump")
	}
}

func TestADumpThatFailsIsNoDump(t *testing.T) {
	failing := standIn(t, "half", 3)
	if _, err := (Chrome{Path: failing.path}).DumpDOM(context.Background(), "http://127.0.0.1:1/a"); err == nil ||
		!strings.Contains(err.Error(), "--dump-dom http://127.0.0.1:1/a: exit status 3") {
		t.Errorf("DumpDOM: %v", err)
	}
	if _, err := (Chrome{Path: filepath.Join(t.TempDir(), "none")}).DumpDOM(context.Background(), "x"); err == nil ||
		!strings.HasPrefix(err.Error(), "harness: launching ") {
		t.Errorf("DumpDOM of no browser: %v", err)
	}
	// One that does not end before its context does is ended with it. The
	// context ends once the stand-in has started its process, however long a
	// busy machine takes to start it.
	hanging := standIn(t, "hang", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dumped := make(chan error, 1)
	go func() {
		_, err := (Chrome{Path: hanging.path}).DumpDOM(ctx, "x")
		dumped <- err
	}()
	written(t, hanging.child)
	cancel()
	select {
	case err := <-dumped:
		if err == nil || !strings.Contains(err.Error(), "killed") {
			t.Errorf("DumpDOM past its context: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DumpDOM did not end with its context")
	}
	if !gone(t, hanging.child) {
		t.Error("what the hanging browser started outlived its context")
	}
	old := create
	create = func(string) (*os.File, error) { return nil, os.ErrPermission }
	if _, err := (Chrome{Path: failing.path}).DumpDOM(context.Background(), "x"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("DumpDOM with nowhere to write the dump: %v", err)
	}
	create = old
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "none"))
	if _, err := (Chrome{Path: failing.path}).DumpDOM(context.Background(), "x"); err == nil {
		t.Error("dumped with nowhere to keep a profile")
	}
}
