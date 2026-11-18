//go:build unix

package recon

import (
	"os/exec"
	"syscall"
)

// configureAgentExecProcess puts the child in its own process group so a
// timeout or cancellation can terminate the child and everything it spawned.
func configureAgentExecProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killAgentExecProcess(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		return command.Process.Kill()
	}
	return nil
}
