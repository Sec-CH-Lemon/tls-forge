//go:build windows

package browser

import (
	"os"
	"os/exec"
	"strconv"
)

// ownGroup does nothing on Windows, where a process tree is found from the
// browser's own process rather than from a group.
func ownGroup(*exec.Cmd) {}

// killTree ends the browser and every process it started, which taskkill finds
// by their parent: killing the browser alone left them running.
func killTree(p *os.Process) error {
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run()
}
