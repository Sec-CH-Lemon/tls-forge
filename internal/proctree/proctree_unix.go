//go:build unix

package proctree

import (
	"os"
	"os/exec"
	"syscall"
)

// Own makes cmd, once started, the first of a process group of its own, which
// every process it starts joins unless it leaves.
func Own(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// Kill ends p and every process in its group: whatever it started, however
// deep.
func Kill(p *os.Process) error { return syscall.Kill(-p.Pid, syscall.SIGKILL) }
