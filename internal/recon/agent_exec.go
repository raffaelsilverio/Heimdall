package recon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	agentExecMaxTimeout     = 10 * time.Minute
	agentExecMaxArgs        = 32
	agentExecMaxArgBytes    = 4096
	agentExecMaxOutputBytes = 8 << 20
	agentExecMaxStdinBytes  = 1 << 20
)

// AgentExecLanguage is the reviewed interpreter class of a controlled tool.
// The language is metadata only; the runner always executes the absolute
// binary directly and never invokes a shell to interpret a command string.
type AgentExecLanguage string

const (
	AgentExecGo     AgentExecLanguage = "go"
	AgentExecPython AgentExecLanguage = "python"
	AgentExecShell  AgentExecLanguage = "shell"
)

var (
	// ErrAgentExecRejected means the spec or request failed validation before
	// any process was started.
	ErrAgentExecRejected = errors.New("agent execution rejected")
	// ErrAgentExecTimeout means the process exceeded its execution deadline and
	// its process group was killed.
	ErrAgentExecTimeout = errors.New("agent execution timed out")
	// ErrAgentExecCanceled means the caller canceled the execution context.
	ErrAgentExecCanceled = errors.New("agent execution canceled")
	// ErrAgentExecExit means the process ran but returned a non-zero exit code
	// or failed to start.
	ErrAgentExecExit = errors.New("agent execution exited with an error")
)

// AgentExecSpec is the compiled, reviewed contract for one subprocess tool. It
// names an absolute binary, a fixed argv prefix, an exact allowlist of extra
// arguments, a bounded environment and hard resource limits. There is no shell
// interpolation and no dynamic tool discovery.
type AgentExecSpec struct {
	ID             string
	Language       AgentExecLanguage
	Binary         string
	Argv           []string
	AllowedArgs    []string
	Env            []string
	WorkDir        string
	AllowStdin     bool
	Timeout        time.Duration
	MaxStdinBytes  int
	MaxStdoutBytes int
	MaxStderrBytes int
}

// AgentExecRequest is one bounded invocation of an AgentExecSpec. Arguments
// must be exact members of the spec allowlist, stdin is optional and capped,
// and the caller may only shorten the spec timeout.
type AgentExecRequest struct {
	Args    []string
	Stdin   []byte
	Timeout time.Duration
}

// AgentExecResult records the bounded process outcome. Stdout and stderr never
// exceed the spec caps; the truncation flags report discarded bytes.
type AgentExecResult struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	TimedOut        bool
	Canceled        bool
	Duration        time.Duration
}

// Validate rejects incomplete or unsafe execution metadata. It must pass before
// a spec can be used to start a process.
func (spec AgentExecSpec) Validate() error {
	if err := spec.validateIdentity(); err != nil {
		return err
	}
	if err := spec.validateArguments(); err != nil {
		return err
	}
	if err := validateAgentExecEnv(spec.Env); err != nil {
		return fmt.Errorf("agent exec %q: %w", spec.ID, err)
	}
	return spec.validateLimits()
}

func (spec AgentExecSpec) validateIdentity() error {
	if spec.ID == "" || strings.TrimSpace(spec.ID) != spec.ID {
		return errors.New("agent exec ids must be non-empty without surrounding whitespace")
	}
	if !spec.Language.supported() {
		return fmt.Errorf("agent exec %q has unsupported language %q", spec.ID, spec.Language)
	}
	if spec.Binary == "" || !filepath.IsAbs(spec.Binary) || filepath.Clean(spec.Binary) != spec.Binary {
		return fmt.Errorf("agent exec %q requires a clean absolute binary path", spec.ID)
	}
	if !utf8.ValidString(spec.Binary) || strings.ContainsAny(spec.Binary, "\x00\n\r") {
		return fmt.Errorf("agent exec %q binary path contains control characters", spec.ID)
	}
	if spec.WorkDir != "" && (!filepath.IsAbs(spec.WorkDir) || filepath.Clean(spec.WorkDir) != spec.WorkDir) {
		return fmt.Errorf("agent exec %q requires a clean absolute work dir", spec.ID)
	}
	return nil
}

func (spec AgentExecSpec) validateArguments() error {
	rejectCommandStrings := spec.rejectsCommandStrings()
	for _, argument := range spec.Argv {
		if err := validateAgentExecArg(spec.ID, argument); err != nil {
			return err
		}
		if rejectCommandStrings && isAgentExecCommandString(argument) {
			return fmt.Errorf("agent exec %q does not permit command-string flags", spec.ID)
		}
	}
	if len(spec.AllowedArgs) > agentExecMaxArgs {
		return fmt.Errorf("agent exec %q allows at most %d extra arguments", spec.ID, agentExecMaxArgs)
	}
	seen := make(map[string]bool, len(spec.AllowedArgs))
	for _, argument := range spec.AllowedArgs {
		if err := validateAgentExecArg(spec.ID, argument); err != nil {
			return err
		}
		if rejectCommandStrings && isAgentExecCommandString(argument) {
			return fmt.Errorf("agent exec %q does not permit command-string flags", spec.ID)
		}
		if seen[argument] {
			return fmt.Errorf("agent exec %q allows argument %q more than once", spec.ID, argument)
		}
		seen[argument] = true
	}
	return nil
}

// rejectsCommandStrings identifies interpreter specs and mislabeled interpreter
// binaries. Reviewed Python and shell tools must name a script path instead of
// passing code through -c or --command.
func (spec AgentExecSpec) rejectsCommandStrings() bool {
	if spec.Language == AgentExecPython || spec.Language == AgentExecShell {
		return true
	}
	base := filepath.Base(spec.Binary)
	if strings.HasPrefix(base, "python3.") {
		return true
	}
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh", "python", "python3":
		return true
	default:
		return false
	}
}

// isAgentExecCommandString rejects short-flag clusters that contain c (for
// example -c and -ec) as well as --command. Interpreter flags are all short
// ASCII letters, so a path or a long option is never mistaken for a command.
func isAgentExecCommandString(argument string) bool {
	if argument == "--command" {
		return true
	}
	if len(argument) < 2 || argument[0] != '-' || argument[1] == '-' {
		return false
	}
	for _, character := range argument[1:] {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return strings.ContainsRune(argument[1:], 'c')
}

func (spec AgentExecSpec) validateLimits() error {
	if spec.Timeout <= 0 || spec.Timeout > agentExecMaxTimeout {
		return fmt.Errorf("agent exec %q timeout must be between 1ns and %s", spec.ID, agentExecMaxTimeout)
	}
	if spec.MaxStdoutBytes < 1 || spec.MaxStdoutBytes > agentExecMaxOutputBytes {
		return fmt.Errorf("agent exec %q stdout cap must be between 1 and %d bytes", spec.ID, agentExecMaxOutputBytes)
	}
	if spec.MaxStderrBytes < 1 || spec.MaxStderrBytes > agentExecMaxOutputBytes {
		return fmt.Errorf("agent exec %q stderr cap must be between 1 and %d bytes", spec.ID, agentExecMaxOutputBytes)
	}
	if spec.AllowStdin {
		if spec.MaxStdinBytes < 1 || spec.MaxStdinBytes > agentExecMaxStdinBytes {
			return fmt.Errorf("agent exec %q stdin cap must be between 1 and %d bytes", spec.ID, agentExecMaxStdinBytes)
		}
		return nil
	}
	if spec.MaxStdinBytes != 0 {
		return fmt.Errorf("agent exec %q must not declare a stdin cap when stdin is disabled", spec.ID)
	}
	return nil
}

// ValidateRequest checks a concrete invocation against the spec before the
// runner starts a process.
func (spec AgentExecSpec) ValidateRequest(request AgentExecRequest) error {
	if len(request.Args) > agentExecMaxArgs {
		return fmt.Errorf("agent exec %q accepts at most %d extra arguments", spec.ID, agentExecMaxArgs)
	}
	if request.Timeout < 0 || request.Timeout > spec.Timeout {
		return fmt.Errorf("agent exec %q timeout must be between 0 and %s", spec.ID, spec.Timeout)
	}
	if !spec.AllowStdin && len(request.Stdin) > 0 {
		return fmt.Errorf("agent exec %q does not accept stdin", spec.ID)
	}
	if len(request.Stdin) > spec.MaxStdinBytes {
		return fmt.Errorf("agent exec %q stdin exceeds %d bytes", spec.ID, spec.MaxStdinBytes)
	}
	allowed := make(map[string]bool, len(spec.AllowedArgs))
	for _, argument := range spec.AllowedArgs {
		allowed[argument] = true
	}
	for _, argument := range request.Args {
		if err := validateAgentExecArg(spec.ID, argument); err != nil {
			return err
		}
		if !allowed[argument] {
			return fmt.Errorf("agent exec %q does not allow argument %q", spec.ID, argument)
		}
	}
	return nil
}

func (language AgentExecLanguage) supported() bool {
	switch language {
	case AgentExecGo, AgentExecPython, AgentExecShell:
		return true
	default:
		return false
	}
}

func validateAgentExecArg(id, argument string) error {
	if argument == "" {
		return fmt.Errorf("agent exec %q arguments must be non-empty", id)
	}
	if len(argument) > agentExecMaxArgBytes {
		return fmt.Errorf("agent exec %q argument exceeds %d bytes", id, agentExecMaxArgBytes)
	}
	if !utf8.ValidString(argument) || strings.ContainsAny(argument, "\x00\n\r") {
		return fmt.Errorf("agent exec %q arguments must be valid UTF-8 without line breaks", id)
	}
	return nil
}

func validateAgentExecEnv(env []string) error {
	seen := make(map[string]bool, len(env))
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			return errors.New("agent exec environment entries must use KEY=VALUE")
		}
		if !validAgentExecEnvKey(key) {
			return fmt.Errorf("invalid environment key %q", key)
		}
		if agentExecReservedEnv[key] {
			return fmt.Errorf("environment key %q is reserved by the runtime", key)
		}
		if seen[key] {
			return fmt.Errorf("environment key %q is declared more than once", key)
		}
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("environment key %q contains line breaks", key)
		}
		seen[key] = true
	}
	return nil
}

func validAgentExecEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for index, character := range key {
		switch {
		case character == '_':
			continue
		case character >= 'A' && character <= 'Z':
			continue
		case index > 0 && character >= '0' && character <= '9':
			continue
		default:
			return false
		}
	}
	return true
}

var agentExecReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "TMPDIR": true, "SHELL": true,
	"BASH_ENV": true, "ENV": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true,
	"PYTHONPATH": true, "PYTHONSTARTUP": true, "GOFLAGS": true, "GOTOOLCHAIN": true,
}

// AgentExecRunner is the only controlled subprocess entry point. It executes an
// absolute binary without a shell, isolates the process group, enforces the
// timeout and output caps, and returns the exit code for audit.
type AgentExecRunner struct {
	// BaseEnv replaces the sanitized host environment when non-nil. It is meant
	// for embedding and tests; callers must not populate it with secrets.
	BaseEnv []string
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
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = spec.Timeout
	}
	execContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(execContext, spec.Binary, agentExecArgv(spec, request)...) // #nosec G204 -- binary is a reviewed clean absolute path, argv is exact-match allowlisted and no shell is used.
	command.Env = agentExecEnvironment(runner.BaseEnv, spec.Env)
	command.Dir = spec.WorkDir
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
	if runErr == nil && !stdout.exceeded && !stderr.exceeded {
		return result, nil
	}
	runErr = agentExecRunError(ctx, execContext, timeout, stdout, stderr, runErr)
	result.TimedOut = errors.Is(runErr, ErrAgentExecTimeout)
	result.Canceled = errors.Is(runErr, ErrAgentExecCanceled)
	return result, runErr
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
