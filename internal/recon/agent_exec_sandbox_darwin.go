//go:build darwin

package recon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const agentExecDarwinSandboxExec = "/usr/bin/sandbox-exec"

// darwinAgentExecSandbox uses the system sandbox profile language to deny all
// network access and confine writes to the per-run directory. Reads of common
// credential roots are denied as defence in depth; the child also receives
// HOME and TMPDIR pointed at the ephemeral directory.
type darwinAgentExecSandbox struct{}

func platformAgentExecSandbox() agentExecSandbox {
	info, err := os.Stat(agentExecDarwinSandboxExec)
	if err != nil || info.IsDir() {
		return nil
	}
	return darwinAgentExecSandbox{}
}

func (darwinAgentExecSandbox) Name() string { return "sandbox-exec" }

func (darwinAgentExecSandbox) Wrap(spec AgentExecSpec, argv []string, workDir string) (string, []string, error) {
	profile, err := darwinAgentExecProfile(workDir)
	if err != nil {
		return "", nil, err
	}
	args := make([]string, 0, len(argv)+3)
	args = append(args, "-p", profile, spec.Binary)
	args = append(args, argv...)
	return agentExecDarwinSandboxExec, args, nil
}

func darwinAgentExecProfile(workDir string) (string, error) {
	quotedWorkDir, err := agentExecSBPLString(workDir)
	if err != nil {
		return "", fmt.Errorf("sandbox work dir: %w", err)
	}
	lines := []string{
		"(version 1)",
		"(allow default)",
		"(deny network*)",
		"(deny file-write*)",
		"(allow file-write* (subpath " + quotedWorkDir + "))",
		`(allow file-write* (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr"))`,
	}
	if denials := darwinAgentExecReadDenials(); len(denials) > 0 {
		lines = append(lines, "(deny file-read* "+strings.Join(denials, " ")+")")
	}
	return strings.Join(lines, "\n"), nil
}

func darwinAgentExecReadDenials() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".docker"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".heimdall"),
		filepath.Join(home, "Library", "Keychains"),
	}
	denials := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		quoted, err := agentExecSBPLString(candidate)
		if err != nil {
			continue
		}
		denials = append(denials, "(subpath "+quoted+")")
	}
	return denials
}

func agentExecSBPLString(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\n\r") {
		return "", errors.New("sandbox paths must be non-empty valid UTF-8 without line breaks")
	}
	return strconv.Quote(value), nil
}
