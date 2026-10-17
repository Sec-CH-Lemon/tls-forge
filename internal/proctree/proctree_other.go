//go:build !unix && !windows

package proctree

import (
	"os"
	"os/exec"
)

// Own does nothing where there are no process groups to start one in.
func Own(*exec.Cmd) {}

// Kill ends p, which is all there is a way to end here.
func Kill(p *os.Process) error { return p.Kill() }
