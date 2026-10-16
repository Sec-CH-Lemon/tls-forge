//go:build unix

package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// running says a process the test started is still there.
func running(pid int) bool { return syscall.Kill(pid, 0) == nil }

// gone waits for a process the test started to be gone, as a killed one is
// once whoever is its parent has reaped it.
func gone(t *testing.T, pid int) bool {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !running(pid) {
			return true
		}
	}
	return false
}

// treeBrowser is a fake browser that starts a process of its own, as every
// browser does, and says where the PIDs of both are: each waits ten seconds at
// most, so that one this package failed to end does not stay for long.
func treeBrowser(t *testing.T) (path, mainPID, childPID string) {
	t.Helper()
	dir := t.TempDir()
	mainPID, childPID = filepath.Join(dir, "main"), filepath.Join(dir, "child")
	path = fakeBrowser(t, "tree", fmt.Sprintf(`sleep 10 &
echo $! > %[1]q.tmp && mv %[1]q.tmp %[1]q
echo $$ > %[2]q.tmp && mv %[2]q.tmp %[2]q
wait
`, childPID, mainPID))
	return path, mainPID, childPID
}

// pidIn is the PID a fake wrote to path, once it has.
func pidIn(t *testing.T, path string) int {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(path); err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("%s holds %q", path, data)
			}
			return pid
		}
	}
	t.Fatalf("the fake never wrote %s", path)
	return 0
}

func TestOpenEndsEveryProcessTheBrowserStarted(t *testing.T) {
	// Closed, or its context done: the processes it started go with it. Only
	// its own were killed, which left the rest running, orphaned, after the
	// run that started them had ended.
	for _, tc := range []struct {
		name string
		end  func(stop func(), cancel context.CancelFunc)
	}{
		{"closed", func(stop func(), _ context.CancelFunc) { stop() }},
		{"its context done", func(_ func(), cancel context.CancelFunc) { cancel() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, mainFile, childFile := treeBrowser(t)
			found, err := Find(path)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop, err := found.Open(ctx, "https://localhost/", Options{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer stop()
			main, child := pidIn(t, mainFile), pidIn(t, childFile)
			if !running(child) {
				t.Fatal("the fake's own process was not running to begin with")
			}
			tc.end(stop, cancel)
			if !gone(t, child) {
				t.Errorf("the process the browser started, %d, outlived it", child)
			}
			stop()
			if !gone(t, main) {
				t.Errorf("the browser, %d, outlived its close", main)
			}
		})
	}
}
