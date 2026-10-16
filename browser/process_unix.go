//go:build unix

package browser

import (
	"os"
	"os/exec"
	"syscall"
)

// ownGroup starts the browser as the first of a process group of its own, which
// every process it starts joins unless it leaves.
func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// killTree ends the browser and every process in its group: the renderers, the
// GPU and network processes, whatever a fake started. Killing the browser alone
// left them running, orphaned, for as long as they cared to.
func killTree(p *os.Process) error { return syscall.Kill(-p.Pid, syscall.SIGKILL) }
