//go:build windows

package proctree

import (
	"os"
	"os/exec"
	"strconv"
)

// Own does nothing on Windows, where a process tree is found from its first
// process rather than from a group.
func Own(*exec.Cmd) {}

// Kill ends p and every process it started, which taskkill finds by their
// parent.
func Kill(p *os.Process) error {
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run()
}
