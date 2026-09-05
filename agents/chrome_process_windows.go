//go:build windows

package agents

import (
	"os/exec"
	"strconv"
)

// configureChromeProcess is a no-op on Windows: there are no POSIX process
// groups, the process tree is terminated through taskkill instead.
func configureChromeProcess(cmd *exec.Cmd) {}

// killChromeProcessTree terminates Chrome and all of its child processes
// with taskkill /T, then falls back to killing the main process only.
func killChromeProcessTree(cmd *exec.Cmd) {
	pid := strconv.Itoa(cmd.Process.Pid)
	if err := exec.Command("taskkill", "/T", "/F", "/PID", pid).Run(); err == nil {
		return
	}
	_ = cmd.Process.Kill()
}
