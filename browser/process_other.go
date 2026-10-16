//go:build !unix && !windows

package browser

import (
	"os"
	"os/exec"
)

// ownGroup does nothing where there are no process groups to start one in.
func ownGroup(*exec.Cmd) {}

// killTree ends the browser, which is all there is a way to end here.
func killTree(p *os.Process) error { return p.Kill() }
