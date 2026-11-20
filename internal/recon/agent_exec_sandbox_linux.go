//go:build linux

package recon

import (
	"os/exec"
	"path/filepath"
)

// bubblewrapAgentExecSandbox runs the reviewed binary inside bubblewrap with a
// private network namespace, a read-only root and a read-write bind mount for
// the ephemeral work directory. Writes to the host are therefore impossible.
// Host files remain readable; reviewed binaries must not receive secret paths.
type bubblewrapAgentExecSandbox struct {
	binary string
}

func platformAgentExecSandbox() agentExecSandbox {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	probe := exec.Command(absolute, "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "/bin/true")
	if err := probe.Run(); err != nil {
		return nil
	}
	return bubblewrapAgentExecSandbox{binary: absolute}
}

func (bubblewrapAgentExecSandbox) Name() string { return "bubblewrap" }

func (sandbox bubblewrapAgentExecSandbox) Wrap(spec AgentExecSpec, argv []string, workDir string) (string, []string, error) {
	args := []string{
		"--unshare-net", "--die-with-parent",
		"--ro-bind", "/", "/",
		"--bind", workDir, workDir,
		"--chdir", workDir,
		"--dev", "/dev",
		"--proc", "/proc",
		spec.Binary,
	}
	args = append(args, argv...)
	return sandbox.binary, args, nil
}
