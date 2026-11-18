//go:build !unix

package recon

import "os/exec"

func configureAgentExecProcess(*exec.Cmd) {}

func killAgentExecProcess(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}
