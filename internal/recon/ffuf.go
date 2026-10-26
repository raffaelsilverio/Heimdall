package recon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type FFUFCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (FFUFCollector) ToolSpecs() []ToolSpec {
	return []ToolSpec{{ID: "ffuf", Stage: StageFFUF, Binary: "ffuf", BinaryEnv: "HEIMDALL_FFUF", VersionArgs: []string{"-V"}, Timeout: 10 * time.Minute}}
}

func (c FFUFCollector) Collect(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{}
	limits := request.Limits
	defaults := DefaultStageLimits(StageFFUF)
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
		return collection, err
	}
	baseTargets := activeWebTargets(request.Program.Scope, request.Targets)
	if len(baseTargets) == 0 {
		return collection, errors.New("ffuf has no authorized web URLs to fuzz")
	}
	if len(baseTargets) > limits.MaxTargets {
		return collection, fmt.Errorf("ffuf has %d base URLs, exceeding max-targets %d", len(baseTargets), limits.MaxTargets)
	}
	wordlist := strings.TrimSpace(os.Getenv("HEIMDALL_FFUF_WORDLIST"))
	if wordlist == "" {
		return collection, errors.New("HEIMDALL_FFUF_WORDLIST must point to a trusted wordlist before scheduling ffuf")
	}
	perTargetBudget := limits.MaxTargets / len(baseTargets)
	if perTargetBudget < 1 {
		return collection, errors.New("ffuf max-targets budget is too small for the in-scope base URLs")
	}

	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	spec := (FFUFCollector{}).ToolSpecs()[0]
	binary := strings.TrimSpace(os.Getenv(spec.BinaryEnv))
	if binary == "" {
		binary = spec.Binary
	}
	resolved, err := resolve(binary)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: binary, Status: "missing", Error: err.Error()}}
		return collection, fmt.Errorf("ffuf is required for this stage: %w", err)
	}
	version, err := readToolVersion(ctx, runner, resolved, spec.VersionArgs...)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Status: "failed", Error: err.Error()}}
		return collection, fmt.Errorf("check ffuf version: %w", err)
	}
	collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Version: version, Status: "complete"}}
	configPath, cleanupConfig, err := emptyToolConfig()
	if err != nil {
		return collection, err
	}
	defer cleanupConfig()
	stageContext, cancelStage := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancelStage()
	requestTimeout := minInt(limits.TimeoutSeconds, 10)
	var totalObservations []Observation
	var artifacts bytes.Buffer
	var wordlistProfile []string
	selectedWordsTotal := 0
	for _, base := range baseTargets {
		fuzzURL, err := fuzzURL(base)
		if err != nil {
			return collection, err
		}
		tempWordlist, wordlistHash, selectedWords, cleanupWordlist, err := prepareFFUFWordlistForTarget(wordlist, perTargetBudget, fuzzURL, request.Program.Scope)
		if err != nil {
			return collection, fmt.Errorf("prepare scoped FFUF wordlist for %s: %w", base, err)
		}
		output, stderr, err := runner.Run(stageContext, resolved,
			"-config", configPath, "-w", tempWordlist, "-u", fuzzURL, "-rate", strconv.Itoa(limits.RateLimitPerSecond),
			"-t", strconv.Itoa(limits.MaxConcurrency), "-timeout", strconv.Itoa(requestTimeout),
			"-maxtime", strconv.Itoa(limits.TimeoutSeconds), "-noninteractive", "-s", "-json", "-ignore-body", "-r=false")
		cleanupWordlist()
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, fmt.Errorf("ffuf against %s: %w: %s", base, err, strings.TrimSpace(string(stderr)))
		}
		selectedWordsTotal += selectedWords
		wordlistProfile = append(wordlistProfile, base+":"+wordlistHash+":"+strconv.Itoa(selectedWords))
		observations, sanitized, err := parseFFUFOutput(output, request.Program.Scope)
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, fmt.Errorf("parse ffuf output: %w", err)
		}
		totalObservations = append(totalObservations, observations...)
		if err := appendArtifactOutput(&artifacts, sanitized); err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, err
		}
	}
	if len(totalObservations) > limits.MaxTargets {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = "ffuf findings exceeded max-targets budget"
		return collection, fmt.Errorf("ffuf returned more than max-targets %d findings", limits.MaxTargets)
	}
	collection.Observations = totalObservations
	if artifacts.Len() > 0 {
		collection.Artifacts = []Artifact{{Name: "ffuf.jsonl", MediaType: "application/x-ndjson", Data: artifacts.Bytes()}}
	}
	sort.Strings(wordlistProfile)
	combinedWordlistHash := sha256.Sum256([]byte(strings.Join(wordlistProfile, "\n")))
	collection.ProfileVersion = ffufProfileVersion(version, hex.EncodeToString(combinedWordlistHash[:]), selectedWordsTotal, limits)
	return collection, nil
}

func activeWebTargets(scope assessment.Scope, seeds []string) []string {
	targets, _, _ := katanaTargets(scope, seeds)
	return targets
}

func fuzzURL(base string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid ffuf base URL %q", base)
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	path := strings.TrimSuffix(parsed.Path, "/")
	parsed.Path = path + "/FUZZ"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func prepareFFUFWordlist(path string, limit int) (tempPath, digest string, selected int, cleanup func(), err error) {
	return prepareFFUFWordlistFiltered(path, limit, nil)
}

func prepareFFUFWordlistForTarget(path string, limit int, fuzzURL string, scope assessment.Scope) (string, string, int, func(), error) {
	return prepareFFUFWordlistFiltered(path, limit, func(word string) bool {
		if !safeFuzzSegment(word) {
			return false
		}
		candidate := strings.Replace(fuzzURL, "FUZZ", word, 1)
		return scope.AllowsActiveURL(candidate)
	})
}

func prepareFFUFWordlistFiltered(path string, limit int, include func(string) bool) (tempPath, digest string, selected int, cleanup func(), err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("stat ffuf wordlist: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", "", 0, nil, errors.New("ffuf wordlist must be a regular, non-symlink file")
	}
	if info.Size() > 32<<20 {
		return "", "", 0, nil, errors.New("ffuf wordlist exceeds the 32 MiB limit")
	}
	input, err := os.Open(path)
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("open ffuf wordlist: %w", err)
	}
	defer closeFFUFWordlistInput(input, &err, &tempPath, &digest, &selected, &cleanup)
	directory, err := os.MkdirTemp("", "heimdall-ffuf-")
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("create ffuf work directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(directory) }
	tempPath = filepath.Join(directory, "wordlist.txt")
	output, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return "", "", 0, nil, fmt.Errorf("create bounded ffuf wordlist: %w", err)
	}
	hasher := sha256.New()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if include != nil && !include(word) {
			continue
		}
		if selected >= limit {
			break
		}
		line := []byte(word + "\n")
		if _, err := output.Write(line); err != nil {
			_ = output.Close()
			cleanup()
			return "", "", 0, nil, fmt.Errorf("write bounded ffuf wordlist: %w", err)
		}
		_, _ = hasher.Write(line)
		selected++
	}
	if err := scanner.Err(); err != nil {
		_ = output.Close()
		cleanup()
		return "", "", 0, nil, fmt.Errorf("read ffuf wordlist: %w", err)
	}
	if err := output.Close(); err != nil {
		cleanup()
		return "", "", 0, nil, fmt.Errorf("close bounded ffuf wordlist: %w", err)
	}
	if selected == 0 {
		cleanup()
		return "", "", 0, nil, errors.New("ffuf wordlist contains no usable entries")
	}
	return tempPath, hex.EncodeToString(hasher.Sum(nil)), selected, cleanup, nil
}

func closeFFUFWordlistInput(input *os.File, resultErr *error, tempPath, digest *string, selected *int, cleanup *func()) {
	if closeErr := input.Close(); closeErr != nil {
		*resultErr = errors.Join(*resultErr, fmt.Errorf("close ffuf wordlist: %w", closeErr))
		if *cleanup != nil {
			(*cleanup)()
		}
		*tempPath, *digest, *selected, *cleanup = "", "", 0, nil
	}
}

func safeFuzzSegment(word string) bool {
	if word == "." || word == ".." || word == "" {
		return false
	}
	for _, character := range word {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' && character != '.' && character != '~' {
			return false
		}
	}
	return true
}

func parseFFUFOutput(output []byte, scope assessment.Scope) ([]Observation, []byte, error) {
	type ffufResult struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Length int    `json:"length"`
		Words  int    `json:"words"`
		Lines  int    `json:"lines"`
	}
	observations := make([]Observation, 0)
	seen := make(map[string]struct{})
	var sanitized bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result ffufResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		endpoint, _, err := normalizeEndpoint(result.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid ffuf result URL %q: %w", result.URL, err)
		}
		if !scope.AllowsActiveURL(endpoint) {
			continue
		}
		value, err := json.Marshal(struct {
			Status int `json:"status"`
			Length int `json:"length"`
			Words  int `json:"words"`
			Lines  int `json:"lines"`
		}{result.Status, result.Length, result.Words, result.Lines})
		if err != nil {
			return nil, nil, err
		}
		if _, exists := seen[endpoint]; !exists {
			seen[endpoint] = struct{}{}
			observations = append(observations, Observation{Category: CategoryHTTPEndpoint, StableKey: endpoint, Value: string(value), Source: "ffuf"})
		}
		writeJSONLine(&sanitized, struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"length"`
			Words  int    `json:"words"`
			Lines  int    `json:"lines"`
		}{endpoint, result.Status, result.Length, result.Words, result.Lines})
		if sanitized.Len() > maxArtifactOutput {
			return nil, nil, fmt.Errorf("ffuf sanitized output exceeds %d bytes", maxArtifactOutput)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read ffuf output: %w", err)
	}
	return observations, sanitized.Bytes(), nil
}

func ffufProfileVersion(toolVersion, wordlistHash string, words int, limits StageLimits) string {
	material := fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d", ProfileFFUFVersion, toolVersion, wordlistHash, words,
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	sum := sha256.Sum256([]byte(material))
	return ProfileFFUFVersion + "-" + hex.EncodeToString(sum[:8])
}
