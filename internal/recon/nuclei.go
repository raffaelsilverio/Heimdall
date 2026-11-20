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
	"io"
	"io/fs"
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

type NucleiCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (NucleiCollector) ToolSpecs() []ToolSpec {
	return []ToolSpec{{ID: "nuclei", Stage: StageNuclei, Binary: "nuclei", BinaryEnv: "HEIMDALL_NUCLEI", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute}}
}

func (c NucleiCollector) Collect(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{}
	limits, err := resolveStageLimits(StageNuclei, request.Limits)
	if err != nil {
		return collection, err
	}
	profile, profileArgs, err := requestProfileForStage("nuclei", request.RequestProfile)
	if err != nil {
		return collection, err
	}
	targets := activeWebTargets(request.Program.Scope, request.Targets)
	if len(targets) == 0 {
		return collection, errors.New("nuclei has no authorized URLs to scan")
	}
	if len(targets) > limits.MaxTargets {
		return collection, fmt.Errorf("nuclei has %d URLs, exceeding max-targets %d", len(targets), limits.MaxTargets)
	}
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil || !request.Program.Scope.AllowsActivePort(parsed.Hostname(), activeURLPort(parsed)) {
			return collection, fmt.Errorf("nuclei requires an explicit host-wide authorized port for %s; a path-only URL scope is not sufficient", target)
		}
		if request.Program.Scope.HasURLExclusionForHost(parsed.Hostname()) {
			return collection, fmt.Errorf("nuclei template requests cannot be safely constrained around path exclusions for %s", target)
		}
	}
	templatePath := strings.TrimSpace(os.Getenv("HEIMDALL_NUCLEI_TEMPLATES"))
	if templatePath == "" {
		return collection, errors.New("HEIMDALL_NUCLEI_TEMPLATES must point to a curated, pinned templates directory")
	}
	templateHash, templateCount, err := fingerprintTemplateDirectory(templatePath)
	if err != nil {
		return collection, fmt.Errorf("validate curated Nuclei templates: %w", err)
	}
	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	spec := (NucleiCollector{}).ToolSpecs()[0]
	binary := strings.TrimSpace(os.Getenv(spec.BinaryEnv))
	if binary == "" {
		binary = spec.Binary
	}
	resolved, err := resolve(binary)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: binary, Status: "missing", Error: err.Error()}}
		return collection, fmt.Errorf("nuclei is required for the nuclei stage: %w", err)
	}
	version, err := readToolVersion(ctx, runner, resolved, spec.VersionArgs...)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Status: "failed", Error: err.Error()}}
		return collection, fmt.Errorf("check nuclei version: %w", err)
	}
	collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Version: version, Status: "complete"}}
	configPath, cleanup, err := emptyToolConfig()
	if err != nil {
		return collection, err
	}
	defer cleanup()
	requestTimeout := minInt(limits.TimeoutSeconds, 10)
	stageContext, cancel := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancel()
	args := []string{
		"-config", configPath, "-templates", templatePath, "-jsonl", "-silent", "-omit-raw", "-disable-update-check",
		"-disable-unsigned-templates", "-no-interactsh", "-disable-redirects", "-severity", "info,low,medium",
		"-exclude-tags", "dos,intrusive,fuzz,bruteforce,headless", "-type", "http", "-rate-limit", strconv.Itoa(limits.RateLimitPerSecond),
		"-concurrency", strconv.Itoa(limits.MaxConcurrency), "-bulk-size", strconv.Itoa(limits.MaxConcurrency),
		"-timeout", strconv.Itoa(requestTimeout), "-retries", "0", "-max-host-error", "3",
	}
	args = append(args, profileArgs...)
	output, stderr, err := runner.RunWithInput(stageContext, resolved, []byte(strings.Join(targets, "\n")+"\n"), args...)
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("run curated Nuclei scan: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	observations, artifact, err := parseNucleiOutput(output, request.Program.Scope, version)
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("parse Nuclei output: %w", err)
	}
	collection.Observations = observations
	if len(artifact) > 0 {
		collection.Artifacts = []Artifact{{Name: "nuclei.jsonl", MediaType: "application/x-ndjson", Data: artifact}}
	}
	collection.ProfileVersion = nucleiProfileVersion(version, templateHash, templateCount, limits, profile)
	return collection, nil
}

func fingerprintTemplateDirectory(path string) (string, int, error) {
	rootInfo, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", 0, errors.New("template path must be a real directory, not a symlink")
	}
	hasher := sha256.New()
	count := 0
	yamlCount := 0
	totalBytes := int64(0)
	err = filepath.WalkDir(path, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template tree contains symlink %q", filePath)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(path, filePath)
		if err != nil {
			return err
		}
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hasher, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		_, _ = io.WriteString(hasher, "\x00"+filepath.ToSlash(relative)+"\n")
		count++
		extension := strings.ToLower(filepath.Ext(relative))
		if extension == ".yaml" || extension == ".yml" {
			yamlCount++
		}
		totalBytes += info.Size()
		if count > 20000 || totalBytes > 512<<20 {
			return errors.New("template directory exceeds 20,000 files or 512 MiB")
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if count == 0 || yamlCount == 0 {
		return "", 0, errors.New("template directory contains no YAML templates")
	}
	return hex.EncodeToString(hasher.Sum(nil)), count, nil
}

func parseNucleiOutput(output []byte, scope assessment.Scope, version string) ([]Observation, []byte, error) {
	type nucleiInfo struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	}
	type nucleiResult struct {
		TemplateID  string     `json:"template-id"`
		MatchedAt   string     `json:"matched-at"`
		Type        string     `json:"type"`
		MatcherName string     `json:"matcher-name"`
		Info        nucleiInfo `json:"info"`
	}
	observations := make([]Observation, 0)
	seen := make(map[string]struct{})
	var artifact bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		endpoint, _, err := normalizeEndpoint(result.MatchedAt)
		if err != nil || !scope.AllowsActiveURL(endpoint) {
			continue
		}
		tags := append([]string(nil), result.Info.Tags...)
		sort.Strings(tags)
		tags = uniqueStrings(tags)
		value, err := json.Marshal(struct {
			TemplateID  string   `json:"template_id"`
			Name        string   `json:"name"`
			Severity    string   `json:"severity"`
			Type        string   `json:"type,omitempty"`
			MatcherName string   `json:"matcher_name,omitempty"`
			Tags        []string `json:"tags,omitempty"`
		}{result.TemplateID, result.Info.Name, result.Info.Severity, result.Type, result.MatcherName, tags})
		if err != nil {
			return nil, nil, err
		}
		key := endpoint + "|" + result.TemplateID + "|" + result.MatcherName
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		observations = append(observations, Observation{Category: CategoryVulnFinding, StableKey: key, Value: string(value), Source: "nuclei", ToolVersion: version})
		writeJSONLine(&artifact, struct {
			Endpoint    string   `json:"endpoint"`
			TemplateID  string   `json:"template_id"`
			Name        string   `json:"name"`
			Severity    string   `json:"severity"`
			MatcherName string   `json:"matcher_name,omitempty"`
			Tags        []string `json:"tags,omitempty"`
		}{endpoint, result.TemplateID, result.Info.Name, result.Info.Severity, result.MatcherName, tags})
		if artifact.Len() > maxArtifactOutput {
			return nil, nil, fmt.Errorf("nuclei sanitized artifact exceeds %d bytes", maxArtifactOutput)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read Nuclei output: %w", err)
	}
	return observations, artifact.Bytes(), nil
}

func nucleiProfileVersion(toolVersion, templatesHash string, templateCount int, limits StageLimits, profile assessment.RequestProfile) string {
	material := fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d\n%s", ProfileNucleiVersion, toolVersion,
		templatesHash, templateCount, limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds,
		requestProfileFingerprint(profile))
	sum := sha256.Sum256([]byte(material))
	return ProfileNucleiVersion + "-" + hex.EncodeToString(sum[:8])
}
