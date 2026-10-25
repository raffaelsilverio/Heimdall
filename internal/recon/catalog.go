package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type ToolSpec struct {
	ID          string
	Stage       string
	Binary      string
	BinaryEnv   string
	VersionArgs []string
	Timeout     time.Duration
}

type ToolAdapter interface {
	Spec() ToolSpec
	Supports(program assessment.Program) bool
	Collect(ctx context.Context, program assessment.Program, binary string, runner CommandRunner, limits StageLimits) ([]Observation, []Artifact, error)
}

type LimitAwareCollector interface {
	CollectWithLimits(ctx context.Context, program assessment.Program, limits StageLimits) (Collection, error)
}

type BinaryResolver func(name string) (string, error)

type Registry struct {
	Adapters []ToolAdapter
	Runner   CommandRunner
	Resolve  BinaryResolver
	Enabled  map[string]bool
}

func NewDefaultOSINTRegistry() Registry {
	adapters := []ToolAdapter{
		SubfinderAdapter{},
		AmassAdapter{},
		UncoverAdapter{},
		GauAdapter{},
	}
	enabled := make(map[string]bool, len(adapters))
	configured := strings.TrimSpace(os.Getenv("HEIMDALL_OSINT_TOOLS"))
	if configured == "" {
		for _, adapter := range adapters {
			enabled[adapter.Spec().ID] = true
		}
	} else {
		for _, id := range strings.Split(configured, ",") {
			id = strings.TrimSpace(strings.ToLower(id))
			if id != "" {
				enabled[id] = true
			}
		}
	}
	return Registry{Adapters: adapters, Runner: ExecCommandRunner{}, Resolve: exec.LookPath, Enabled: enabled}
}

func NewDefaultStageSet() StageSet {
	return StageSet{OSINT: NewDefaultOSINTRegistry(), DNS: DNSCollector{}, Web: WebCollector{}, Nmap: NmapCollector{}, Crawl: KatanaCollector{}, FFUF: FFUFCollector{}, Nuclei: NucleiCollector{}}
}

func (r Registry) Specs() []ToolSpec {
	result := make([]ToolSpec, 0, len(r.Adapters))
	for _, adapter := range r.Adapters {
		result = append(result, adapter.Spec())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (r Registry) Doctor(ctx context.Context) []ToolResult {
	runner := r.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := r.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	results := make([]ToolResult, 0, len(r.Adapters))
	for _, adapter := range r.Adapters {
		spec := adapter.Spec()
		result := ToolResult{ID: spec.ID, Binary: spec.Binary}
		if len(r.Enabled) > 0 && !r.Enabled[spec.ID] {
			result.Status = "disabled"
			results = append(results, result)
			continue
		}
		results = append(results, CheckTool(ctx, spec, runner, resolve))
	}
	return results
}

func CheckTool(ctx context.Context, spec ToolSpec, runner CommandRunner, resolve BinaryResolver) ToolResult {
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	if resolve == nil {
		resolve = exec.LookPath
	}
	result := ToolResult{ID: spec.ID, Binary: spec.Binary}
	binary := spec.Binary
	if configured := strings.TrimSpace(os.Getenv(spec.BinaryEnv)); spec.BinaryEnv != "" && configured != "" {
		binary = configured
	}
	resolved, err := resolve(binary)
	if err != nil {
		result.Binary = binary
		result.Status = "missing"
		result.Error = err.Error()
		return result
	}
	result.Binary = resolved
	versionContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	stdout, stderr, err := runner.Run(versionContext, resolved, spec.VersionArgs...)
	cancel()
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}
	result.Status = "complete"
	result.Version = strings.TrimSpace(string(stdout) + " " + string(stderr))
	if result.Version == "" {
		result.Version = "unknown"
	}
	return result
}

func (r Registry) Collect(ctx context.Context, program assessment.Program) (Collection, error) {
	return r.CollectWithLimits(ctx, program, DefaultStageLimits(StageOSINT))
}

func (r Registry) CollectWithLimits(ctx context.Context, program assessment.Program, limits StageLimits) (Collection, error) {
	defaults := DefaultStageLimits(StageOSINT)
	if limits.RateLimitPerSecond == 0 {
		limits.RateLimitPerSecond = defaults.RateLimitPerSecond
	}
	if limits.MaxConcurrency == 0 {
		limits.MaxConcurrency = defaults.MaxConcurrency
	}
	if limits.MaxTargets == 0 {
		limits.MaxTargets = defaults.MaxTargets
	}
	if limits.TimeoutSeconds == 0 {
		limits.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if err := limits.Validate(); err != nil {
		return Collection{}, err
	}
	stageContext, cancelStage := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancelStage()
	ctx = stageContext
	if len(program.Scope.DiscoveryDomains()) > limits.MaxTargets {
		return Collection{}, fmt.Errorf("OSINT scope has more than the configured %d domain targets", limits.MaxTargets)
	}
	runner := r.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := r.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	adapters := append([]ToolAdapter(nil), r.Adapters...)
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].Spec().ID < adapters[j].Spec().ID })
	knownTools := make(map[string]struct{}, len(adapters))
	for _, adapter := range adapters {
		knownTools[adapter.Spec().ID] = struct{}{}
	}
	for id := range r.Enabled {
		if _, ok := knownTools[id]; !ok {
			return Collection{}, fmt.Errorf("unknown OSINT tool %q in HEIMDALL_OSINT_TOOLS", id)
		}
	}

	collection := Collection{Tools: make([]ToolResult, 0, len(adapters))}
	profileParts := make([]string, 0, len(adapters))
	var failures []error
	available := 0
	for _, adapter := range adapters {
		spec := adapter.Spec()
		if spec.ID == "" || spec.Binary == "" {
			return collection, errors.New("tool adapter is missing its id or binary")
		}
		if len(r.Enabled) > 0 && !r.Enabled[spec.ID] {
			continue
		}
		toolResult := ToolResult{ID: spec.ID, Binary: spec.Binary}
		if !adapter.Supports(program) {
			toolResult.Status = "not_applicable"
			collection.Tools = append(collection.Tools, toolResult)
			profileParts = append(profileParts, spec.ID+":not_applicable")
			continue
		}
		binary := spec.Binary
		if configured := strings.TrimSpace(os.Getenv(spec.BinaryEnv)); spec.BinaryEnv != "" && configured != "" {
			binary = configured
		}
		resolved, err := resolve(binary)
		if err != nil {
			toolResult.Binary = binary
			toolResult.Status = "missing"
			toolResult.Error = err.Error()
			collection.Tools = append(collection.Tools, toolResult)
			profileParts = append(profileParts, spec.ID+":missing")
			continue
		}
		toolResult.Binary = resolved
		versionTimeout := spec.Timeout
		if versionTimeout <= 0 || versionTimeout > 10*time.Second {
			versionTimeout = 10 * time.Second
		}
		versionContext, cancel := context.WithTimeout(ctx, versionTimeout)
		versionOut, versionErrOut, err := runner.Run(versionContext, resolved, spec.VersionArgs...)
		cancel()
		if err != nil {
			toolResult.Status = "failed"
			toolResult.Error = fmt.Sprintf("read version: %v", err)
			collection.Tools = append(collection.Tools, toolResult)
			profileParts = append(profileParts, spec.ID+":failed-version")
			failures = append(failures, fmt.Errorf("%s version: %w", spec.ID, err))
			continue
		}
		toolResult.Version = strings.TrimSpace(string(versionOut) + " " + string(versionErrOut))
		if toolResult.Version == "" {
			toolResult.Version = "unknown"
		}
		toolTimeout := spec.Timeout
		if toolTimeout <= 0 {
			toolTimeout = 10 * time.Minute
		}
		toolContext, cancel := context.WithTimeout(ctx, toolTimeout)
		observations, artifacts, err := adapter.Collect(toolContext, program, resolved, runner, limits)
		cancel()
		for index := range observations {
			if observations[index].ToolVersion == "" {
				observations[index].ToolVersion = toolResult.Version
			}
		}
		collection.Observations = append(collection.Observations, observations...)
		collection.Artifacts = append(collection.Artifacts, artifacts...)
		if len(collection.Observations) > limits.MaxTargets {
			toolResult.Status = "failed"
			toolResult.Error = "OSINT results exceeded the configured target limit"
			failures = append(failures, fmt.Errorf("%s produced more than %d observations", spec.ID, limits.MaxTargets))
		}
		if err != nil {
			toolResult.Status = "failed"
			toolResult.Error = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", spec.ID, err))
		} else if toolResult.Status != "failed" {
			toolResult.Status = "complete"
			available++
		}
		collection.Tools = append(collection.Tools, toolResult)
		profileParts = append(profileParts, spec.ID+":"+toolResult.Status+":"+toolResult.Version)
	}

	if available == 0 && len(failures) == 0 {
		return collection, errors.New("no applicable OSINT tools are installed and enabled")
	}
	profileMaterial := fmt.Sprintf("%s\nrate=%d\nconcurrency=%d\ntargets=%d\ntimeout=%d\n%s", ProfileOSINTVersion,
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds, strings.Join(profileParts, "\n"))
	profileHash := sha256.Sum256([]byte(profileMaterial))
	collection.ProfileVersion = ProfileOSINTVersion + "-" + hex.EncodeToString(profileHash[:8])
	return collection, errors.Join(failures...)
}
