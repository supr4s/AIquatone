//go:build !windows

package agents

import (
	"os/exec"
	"syscall"
)

// configureChromeProcess runs Chrome in its own process group so the whole
// tree (renderer, gpu, zygote children) can be reaped on timeout instead of
// being leaked.
func configureChromeProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killChromeProcessTree kills the whole process group (negative PID) so
// Chrome's child processes are terminated too. Falls back to killing the
// main process only when the group cannot be resolved.
func killChromeProcessTree(cmd *exec.Cmd) {
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}
