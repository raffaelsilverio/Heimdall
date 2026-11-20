package recon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// agentExecSandbox wraps one reviewed binary in an OS-enforced isolation
// profile. Implementations are compiled per platform; there is no dynamic
// sandbox loading and no caller-supplied wrapper.
type agentExecSandbox interface {
	Name() string
	Wrap(spec AgentExecSpec, argv []string, workDir string) (string, []string, error)
}

// AgentExecRunner is the only controlled subprocess entry point. It executes an
// absolute binary without a shell, wraps it in the platform sandbox, uses an
// ephemeral work directory, isolates the process group, enforces the timeout
// and output caps, and returns the exit code for audit.
type AgentExecRunner struct {
	// BaseEnv replaces the sanitized host environment when non-nil. It is meant
	// for embedding and tests; callers must not populate it with secrets.
	BaseEnv []string
	sandbox agentExecSandbox
}

// NewAgentExecRunner returns a runner backed by the reviewed sandbox for the
// current platform. Execute fails closed with ErrAgentExecSandboxUnavailable
// when the platform has no reviewed sandbox.
func NewAgentExecRunner() AgentExecRunner {
	return AgentExecRunner{sandbox: platformAgentExecSandbox()}
}

// Execute validates the spec and request, then runs the process once. The
// result is populated even when the process times out, is canceled, exceeds an
// output cap, or exits non-zero.
func (runner AgentExecRunner) Execute(ctx context.Context, spec AgentExecSpec, request AgentExecRequest) (AgentExecResult, error) {
	if err := spec.Validate(); err != nil {
		return AgentExecResult{}, fmt.Errorf("%w: %v", ErrAgentExecRejected, err)
	}
	if err := spec.ValidateRequest(request); err != nil {
		return AgentExecResult{}, fmt.Errorf("%w: %v", ErrAgentExecRejected, err)
	}
	if runner.sandbox == nil {
		return AgentExecResult{}, fmt.Errorf("%w: no reviewed sandbox is available on this host", ErrAgentExecSandboxUnavailable)
	}
	workDir, err := os.MkdirTemp("", "heimdall-agent-exec-")
	if err != nil {
		return AgentExecResult{}, fmt.Errorf("%w: create sandbox work dir: %v", ErrAgentExecRejected, err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(workDir); resolveErr == nil {
		workDir = resolved
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	launcher, argv, err := runner.sandbox.Wrap(spec, agentExecArgv(spec, request), workDir)
	if err != nil {
		return AgentExecResult{}, fmt.Errorf("%w: %v", ErrAgentExecSandboxUnavailable, err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = spec.Timeout
	}
	execContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(execContext, launcher, argv...) // #nosec G204 -- launcher is the reviewed platform sandbox and argv is exact-match allowlisted; no shell is used.
	command.Env = agentExecSandboxEnvironment(runner.BaseEnv, spec.Env, workDir)
	command.Dir = workDir
	if len(request.Stdin) > 0 {
		command.Stdin = bytes.NewReader(request.Stdin)
	}
	stdout := &limitedBuffer{limit: spec.MaxStdoutBytes}
	stderr := &limitedBuffer{limit: spec.MaxStderrBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	configureAgentExecProcess(command)
	command.Cancel = func() error { return killAgentExecProcess(command) }
	command.WaitDelay = 2 * time.Second
	started := time.Now()
	runErr := command.Run()
	result := newAgentExecResult(command, stdout, stderr, started)
	result.Sandbox = runner.sandbox.Name()
	if runErr == nil && !stdout.exceeded && !stderr.exceeded {
		return result, nil
	}
	runErr = agentExecRunError(ctx, execContext, timeout, stdout, stderr, runErr)
	result.TimedOut = errors.Is(runErr, ErrAgentExecTimeout)
	result.Canceled = errors.Is(runErr, ErrAgentExecCanceled)
	return result, runErr
}

func agentExecSandboxEnvironment(base, overrides []string, workDir string) []string {
	environment := agentExecEnvironment(base, overrides)
	return agentExecEnvironment(environment, []string{
		"HOME=" + workDir, "TMPDIR=" + workDir, "PYTHONDONTWRITEBYTECODE=1",
	})
}

func agentExecArgv(spec AgentExecSpec, request AgentExecRequest) []string {
	argv := make([]string, 0, len(spec.Argv)+len(request.Args))
	argv = append(argv, spec.Argv...)
	return append(argv, request.Args...)
}

func newAgentExecResult(command *exec.Cmd, stdout, stderr *limitedBuffer, started time.Time) AgentExecResult {
	result := AgentExecResult{
		Stdout: stdout.Bytes(), Stderr: stderr.Bytes(),
		StdoutTruncated: stdout.exceeded, StderrTruncated: stderr.exceeded,
		Duration: time.Since(started),
	}
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	return result
}

func agentExecRunError(ctx, execContext context.Context, timeout time.Duration, stdout, stderr *limitedBuffer, runErr error) error {
	if errors.Is(execContext.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %s", ErrAgentExecTimeout, timeout)
	}
	if execContext.Err() != nil || ctx.Err() != nil {
		cause := execContext.Err()
		if cause == nil {
			cause = ctx.Err()
		}
		return fmt.Errorf("%w: %v", ErrAgentExecCanceled, cause)
	}
	if stdout.exceeded || stderr.exceeded {
		return fmt.Errorf("%w: stdout=%t stderr=%t", ErrOutputLimit, stdout.exceeded, stderr.exceeded)
	}
	return fmt.Errorf("%w: %v", ErrAgentExecExit, runErr)
}

func agentExecEnvironment(base, overrides []string) []string {
	if base == nil {
		base = safeToolEnvironment()
	}
	values := make(map[string]string, len(base)+len(overrides))
	for _, entry := range base {
		key, value, found := strings.Cut(entry, "=")
		if found {
			values[key] = value
		}
	}
	for _, entry := range overrides {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}
