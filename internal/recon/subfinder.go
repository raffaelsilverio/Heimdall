package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

const maxToolOutput = 8 << 20

var ErrOutputLimit = errors.New("tool output exceeded the configured limit")

type CommandRunner interface {
	Run(ctx context.Context, executable string, args ...string) (stdout, stderr []byte, err error)
	RunWithInput(ctx context.Context, executable string, input []byte, args ...string) (stdout, stderr []byte, err error)
}

type ExecCommandRunner struct {
	MaxOutput int
	Env       []string
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (r ExecCommandRunner) Run(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	return r.run(ctx, executable, nil, args...)
}

func (r ExecCommandRunner) RunWithInput(ctx context.Context, executable string, input []byte, args ...string) ([]byte, []byte, error) {
	return r.run(ctx, executable, input, args...)
}

func (r ExecCommandRunner) run(ctx context.Context, executable string, input []byte, args ...string) ([]byte, []byte, error) {
	limit := r.MaxOutput
	if limit <= 0 {
		limit = maxToolOutput
	}
	command := exec.CommandContext(ctx, executable, args...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	if r.Env != nil {
		command.Env = append([]string(nil), r.Env...)
	} else {
		command.Env = safeToolEnvironment()
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: limit}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return stdout.Bytes(), stderr.Bytes(), ErrOutputLimit
	}
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("run %s: %w", executable, err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.exceeded = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.buffer.Write(data[:remaining])
		b.exceeded = true
		return len(data), nil
	}
	return b.buffer.Write(data)
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

type SubfinderAdapter struct{}

func (SubfinderAdapter) Spec() ToolSpec {
	return ToolSpec{ID: "subfinder", Stage: StageOSINT, Binary: "subfinder", BinaryEnv: "HEIMDALL_SUBFINDER", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute}
}

func (SubfinderAdapter) Supports(program assessment.Program) bool {
	return len(program.Scope.DiscoveryDomains()) > 0
}

func (SubfinderAdapter) Collect(ctx context.Context, program assessment.Program, binary string, runner CommandRunner, limits StageLimits) ([]Observation, []Artifact, error) {
	domains := program.Scope.DiscoveryDomains()
	observations := make([]Observation, 0)
	var output bytes.Buffer
	maxMinutes := (limits.TimeoutSeconds + 59) / 60
	if maxMinutes < 1 {
		maxMinutes = 1
	}
	for _, domain := range domains {
		stdout, stderr, err := runner.Run(ctx, binary, "-d", domain, "-silent", "-oJ", "-cs", "-duc",
			"-rl", strconv.Itoa(limits.RateLimitPerSecond), "-max-time", strconv.Itoa(maxMinutes))
		if err != nil {
			return observations, sanitizedArtifacts("subfinder", "application/x-ndjson", output.Bytes()),
				fmt.Errorf("enumerate %s: %w: %s", domain, err, strings.TrimSpace(string(stderr)))
		}
		found, safeJSONL, err := parseSubfinderOutput(stdout, program.Scope)
		if err != nil {
			return observations, sanitizedArtifacts("subfinder", "application/x-ndjson", output.Bytes()),
				fmt.Errorf("parse output for %s: %w", domain, err)
		}
		observations = append(observations, found...)
		if err := appendArtifactOutput(&output, safeJSONL); err != nil {
			return observations, sanitizedArtifacts("subfinder", "application/x-ndjson", output.Bytes()), err
		}
	}
	return observations, sanitizedArtifacts("subfinder", "application/x-ndjson", output.Bytes()), nil
}

func parseSubfinderOutput(output []byte, scope assessment.Scope) ([]Observation, []byte, error) {
	observations := make([]Observation, 0)
	var safeOutput bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result struct {
			Host    string   `json:"host"`
			Sources []string `json:"sources"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		if strings.TrimSpace(result.Host) == "" {
			return nil, nil, errors.New("JSONL record has no host")
		}
		host, err := assessment.NormalizeHost(result.Host)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid discovered host %q: %w", result.Host, err)
		}
		if !scope.AllowsHost(host) {
			continue
		}
		observations = append(observations, Observation{Category: CategoryHostname, StableKey: host, Value: host, Source: "subfinder"})
		encoded, err := json.Marshal(struct {
			Host    string   `json:"host"`
			Sources []string `json:"sources,omitempty"`
		}{Host: host, Sources: result.Sources})
		if err != nil {
			return nil, nil, fmt.Errorf("encode sanitized output: %w", err)
		}
		safeOutput.Write(encoded)
		safeOutput.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read JSONL output: %w", err)
	}
	return observations, safeOutput.Bytes(), nil
}

func sanitizedArtifacts(toolID, mediaType string, data []byte) []Artifact {
	if len(data) == 0 {
		return nil
	}
	return []Artifact{{Name: toolID + ".jsonl", MediaType: mediaType, Data: append([]byte(nil), data...)}}
}
