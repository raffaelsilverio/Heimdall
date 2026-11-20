package recon

import (
	"errors"
	"fmt"
	"path/filepath"
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

// AgentExecNetwork is the reviewed network policy of a controlled tool. Only
// network denial is admitted today; network-capable subprocesses require the
// metered proxy profile described in roadmap/24.
type AgentExecNetwork string

const (
	AgentExecNetworkNone AgentExecNetwork = "none"
)

// AgentExecFilesystem is the reviewed filesystem policy of a controlled tool.
// Only an ephemeral per-run directory is admitted today.
type AgentExecFilesystem string

const (
	AgentExecFilesystemEphemeralTmp AgentExecFilesystem = "ephemeral_tmp"
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
	// ErrAgentExecSandboxUnavailable means no reviewed sandbox could enforce
	// the requested network/filesystem policy, so no process was started.
	ErrAgentExecSandboxUnavailable = errors.New("agent execution sandbox unavailable")
)

// AgentExecSpec is the compiled, reviewed contract for one subprocess tool. It
// names an absolute binary, a fixed argv prefix, an exact allowlist of extra
// arguments, a bounded environment, an explicit isolation profile and hard
// resource limits. There is no shell interpolation and no dynamic tool
// discovery.
type AgentExecSpec struct {
	ID             string
	Language       AgentExecLanguage
	Binary         string
	Argv           []string
	AllowedArgs    []string
	Env            []string
	Network        AgentExecNetwork
	Filesystem     AgentExecFilesystem
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
// exceed the spec caps; the truncation flags report discarded bytes. Sandbox
// names the reviewed isolation implementation that wrapped the process.
type AgentExecResult struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	TimedOut        bool
	Canceled        bool
	Sandbox         string
	Duration        time.Duration
}

// Validate rejects incomplete or unsafe execution metadata. It must pass before
// a spec can be used to start a process.
func (spec AgentExecSpec) Validate() error {
	if err := spec.validateIdentity(); err != nil {
		return err
	}
	if err := spec.validateIsolation(); err != nil {
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

func (spec AgentExecSpec) validateIsolation() error {
	if spec.Network != AgentExecNetworkNone {
		return fmt.Errorf("agent exec %q has unsupported network policy %q", spec.ID, spec.Network)
	}
	if spec.Filesystem != AgentExecFilesystemEphemeralTmp {
		return fmt.Errorf("agent exec %q has unsupported filesystem policy %q", spec.ID, spec.Filesystem)
	}
	return nil
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
