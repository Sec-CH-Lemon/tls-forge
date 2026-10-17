//go:build unix

package proctree

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// running says a process the test started is still there.
func running(pid int) bool { return syscall.Kill(pid, 0) == nil }

// gone waits for a process to be gone, as a killed one is once whoever is its
// parent has reaped it.
func gone(pid int) bool {
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !running(pid) {
			return true
		}
	}
	return false
}

// pidIn is the PID a script wrote to path, once it has.
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
	t.Fatalf("the script never wrote %s", path)
	return 0
}

func TestKillEndsWhatTheProgramStartedToo(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	// A program that starts one of its own, as a browser does, and waits ten
	// seconds at most, so that one this failed to end does not stay long.
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep 10 & echo $! > %[1]q.tmp && mv %[1]q.tmp %[1]q; wait", child))
	Own(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("Own left %+v", cmd.SysProcAttr)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	started := pidIn(t, child)
	if !running(started) {
		t.Fatal("the program's own process was not running to begin with")
	}
	if err := Kill(cmd.Process); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := <-done; err == nil {
		t.Error("the program ended as though it had not been killed")
	}
	if !gone(started) {
		t.Errorf("the process the program started, %d, outlived it", started)
	}
	// A tree that is gone already is said to be.
	if err := Kill(cmd.Process); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("Kill of a tree that is gone: %v", err)
	}
}
