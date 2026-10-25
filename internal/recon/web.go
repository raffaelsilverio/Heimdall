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

type WebCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (WebCollector) ToolSpecs() []ToolSpec {
	return []ToolSpec{
		{ID: "httpx", Stage: StageWeb, Binary: "httpx", BinaryEnv: "HEIMDALL_HTTPX", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute},
		{ID: "tlsx", Stage: StageWeb, Binary: "tlsx", BinaryEnv: "HEIMDALL_TLSX", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute},
	}
}

func (c WebCollector) Collect(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{}
	limits := request.Limits
	defaults := DefaultStageLimits(StageWeb)
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
	stageContext, cancelStage := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancelStage()

	targets := make(map[string]struct{})
	for _, host := range request.Targets {
		for _, target := range request.Program.Scope.ActiveURLsForHost(host) {
			targets[target] = struct{}{}
		}
	}
	for _, host := range request.Program.Scope.DiscoveryDomains() {
		for _, target := range request.Program.Scope.ActiveURLsForHost(host) {
			targets[target] = struct{}{}
		}
	}
	for _, entry := range request.Program.Scope.Entries {
		if entry.Effect == assessment.ScopeInclude && entry.Type == assessment.ScopeIP {
			for _, target := range request.Program.Scope.ActiveURLsForHost(entry.Value) {
				targets[target] = struct{}{}
			}
		}
	}
	orderedTargets := make([]string, 0, len(targets))
	for target := range targets {
		orderedTargets = append(orderedTargets, target)
	}
	sort.Strings(orderedTargets)
	if len(orderedTargets) == 0 {
		return collection, errors.New("web stage has no active targets: add explicit ports to domain scopes or an in-scope URL")
	}
	if len(orderedTargets) > limits.MaxTargets {
		return collection, fmt.Errorf("web stage has %d targets, exceeding the configured limit of %d", len(orderedTargets), limits.MaxTargets)
	}

	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	specs := (WebCollector{}).ToolSpecs()
	resolved := make([]string, len(specs))
	versions := make([]string, len(specs))
	for index, spec := range specs {
		binary := spec.Binary
		if override := strings.TrimSpace(os.Getenv(spec.BinaryEnv)); override != "" {
			binary = override
		}
		path, err := resolve(binary)
		if err != nil {
			tool := ToolResult{ID: spec.ID, Binary: binary, Status: "missing", Error: err.Error()}
			collection.Tools = append(collection.Tools, tool)
			return collection, fmt.Errorf("%s is required by the web stage: %w", spec.ID, err)
		}
		resolved[index] = path
		version, err := readToolVersion(ctx, runner, path, spec.VersionArgs...)
		if err != nil {
			collection.Tools = append(collection.Tools, ToolResult{ID: spec.ID, Binary: path, Status: "failed", Error: err.Error()})
			return collection, fmt.Errorf("check %s version: %w", spec.ID, err)
		}
		versions[index] = version
		collection.Tools = append(collection.Tools, ToolResult{ID: spec.ID, Binary: path, Version: version, Status: "complete"})
	}
	configPath, cleanupConfig, err := emptyToolConfig()
	if err != nil {
		return collection, err
	}
	defer cleanupConfig()

	input := []byte(strings.Join(orderedTargets, "\n") + "\n")
	httpTimeout := limits.TimeoutSeconds
	if httpTimeout > 10 {
		httpTimeout = 10
	}
	httpOutput, httpStderr, err := runner.RunWithInput(stageContext, resolved[0], input,
		"-config", configPath, "-silent", "-json", "-status-code", "-title", "-tech-detect", "-web-server", "-ip", "-cname", "-ob",
		"-nfs", "-duc", "-no-color", "-threads", strconv.Itoa(limits.MaxConcurrency),
		"-rate-limit", strconv.Itoa(limits.RateLimitPerSecond), "-timeout", strconv.Itoa(httpTimeout))
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("probe authorized HTTP targets: %w: %s", err, strings.TrimSpace(string(httpStderr)))
	}
	httpObservations, httpArtifact, err := parseHTTPXOutput(httpOutput, request.Program.Scope, versions[0])
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("parse httpx output: %w", err)
	}
	collection.Observations = append(collection.Observations, httpObservations...)
	if len(httpArtifact) > 0 {
		collection.Artifacts = append(collection.Artifacts, Artifact{Name: "httpx.jsonl", MediaType: "application/x-ndjson", Data: httpArtifact})
	}

	tlsTargets := make([]string, 0)
	for _, target := range orderedTargets {
		parsed, _ := url.Parse(target)
		if parsed != nil && strings.EqualFold(parsed.Scheme, "https") && request.Program.Scope.AllowsActiveURL(target) {
			tlsTargets = append(tlsTargets, target)
		}
	}
	if len(tlsTargets) == 0 {
		collection.Tools[1].Status = "not_applicable"
		collection.ProfileVersion = webProfileVersion(versions, limits)
		return collection, nil
	}
	tlsInput := []byte(strings.Join(tlsTargets, "\n") + "\n")
	tlsTimeout := limits.TimeoutSeconds
	if tlsTimeout > 5 {
		tlsTimeout = 5
	}
	delay := time.Duration(limits.MaxConcurrency) * time.Second / time.Duration(limits.RateLimitPerSecond)
	tlsOutput, tlsStderr, err := runner.RunWithInput(stageContext, resolved[1], tlsInput,
		"-config", configPath, "-silent", "-json", "-san", "-cn", "-hash", "sha256", "-tls-version", "-duc",
		"-c", strconv.Itoa(limits.MaxConcurrency), "-timeout", strconv.Itoa(tlsTimeout), "-delay", delay.String())
	if err != nil {
		collection.Tools[1].Status = "failed"
		collection.Tools[1].Error = err.Error()
		return collection, fmt.Errorf("collect TLS metadata for authorized targets: %w: %s", err, strings.TrimSpace(string(tlsStderr)))
	}
	tlsObservations, tlsArtifact, err := parseTLSXOutput(tlsOutput, request.Program.Scope, versions[1], tlsTargets)
	if err != nil {
		collection.Tools[1].Status = "failed"
		collection.Tools[1].Error = err.Error()
		return collection, fmt.Errorf("parse tlsx output: %w", err)
	}
	collection.Observations = append(collection.Observations, tlsObservations...)
	if len(tlsArtifact) > 0 {
		collection.Artifacts = append(collection.Artifacts, Artifact{Name: "tlsx.jsonl", MediaType: "application/x-ndjson", Data: tlsArtifact})
	}
	collection.ProfileVersion = webProfileVersion(versions, limits)
	return collection, nil
}

func parseHTTPXOutput(output []byte, scope assessment.Scope, version string) ([]Observation, []byte, error) {
	type httpxResult struct {
		URL       string   `json:"url"`
		Input     string   `json:"input"`
		Status    int      `json:"status_code"`
		Title     string   `json:"title"`
		WebServer string   `json:"webserver"`
		Tech      []string `json:"tech"`
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
		var result httpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		rawURL := result.URL
		if rawURL == "" {
			rawURL = result.Input
		}
		endpoint, host, err := normalizeEndpoint(rawURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid endpoint %q: %w", rawURL, err)
		}
		if !scope.AllowsActiveURL(endpoint) {
			continue
		}
		tech := append([]string(nil), result.Tech...)
		sort.Strings(tech)
		tech = uniqueStrings(tech)
		value, err := json.Marshal(struct {
			Status    int      `json:"status_code"`
			Title     string   `json:"title,omitempty"`
			WebServer string   `json:"webserver,omitempty"`
			Tech      []string `json:"tech,omitempty"`
		}{Status: result.Status, Title: strings.TrimSpace(result.Title), WebServer: strings.TrimSpace(result.WebServer), Tech: tech})
		if err != nil {
			return nil, nil, fmt.Errorf("encode HTTP observation: %w", err)
		}
		if _, exists := seen[endpoint]; !exists {
			seen[endpoint] = struct{}{}
			observations = append(observations, Observation{Category: CategoryHTTPEndpoint, StableKey: endpoint, Value: string(value), Source: "httpx", ToolVersion: version})
		}
		writeJSONLine(&artifact, struct {
			URL       string   `json:"url"`
			Host      string   `json:"host"`
			Status    int      `json:"status_code"`
			Title     string   `json:"title,omitempty"`
			WebServer string   `json:"webserver,omitempty"`
			Tech      []string `json:"tech,omitempty"`
		}{URL: endpoint, Host: host, Status: result.Status, Title: strings.TrimSpace(result.Title), WebServer: strings.TrimSpace(result.WebServer), Tech: tech})
		if artifact.Len() > maxArtifactOutput {
			return nil, nil, fmt.Errorf("HTTPX sanitized artifact exceeds %d bytes", maxArtifactOutput)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read httpx output: %w", err)
	}
	return observations, artifact.Bytes(), nil
}

func parseTLSXOutput(output []byte, scope assessment.Scope, version string, authorizedTargets []string) ([]Observation, []byte, error) {
	type tlsxResult struct {
		Host       string   `json:"host"`
		Port       string   `json:"port"`
		Probe      bool     `json:"probe_status"`
		SubjectCN  string   `json:"subject_cn"`
		SubjectAN  []string `json:"subject_an"`
		IssuerDN   string   `json:"issuer_dn"`
		NotAfter   string   `json:"not_after"`
		TLSVersion string   `json:"tls_version"`
		Hashes     struct {
			SHA256 string `json:"sha256"`
		} `json:"fingerprint_hash"`
	}
	observations := make([]Observation, 0)
	var artifact bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result tlsxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		if !result.Probe {
			continue
		}
		host, err := assessment.NormalizeHost(result.Host)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid TLS host %q: %w", result.Host, err)
		}
		port, err := strconv.ParseUint(result.Port, 10, 16)
		if err != nil || port == 0 {
			return nil, nil, fmt.Errorf("invalid TLS port %q", result.Port)
		}
		activeURL, ok := authorizedTLSEndpoint(scope, host, uint16(port), authorizedTargets)
		if !ok {
			continue
		}
		sans := make([]string, 0, len(result.SubjectAN))
		for _, san := range result.SubjectAN {
			if normalized, err := assessment.NormalizeHost(san); err == nil && scope.AllowsHost(normalized) {
				sans = append(sans, normalized)
			}
		}
		sort.Strings(sans)
		sans = uniqueStrings(sans)
		commonName := strings.TrimSpace(result.SubjectCN)
		if normalized, err := assessment.NormalizeHost(commonName); err == nil {
			if scope.AllowsHost(normalized) {
				commonName = normalized
			} else {
				commonName = ""
			}
		}
		value, err := json.Marshal(struct {
			Fingerprint string   `json:"sha256,omitempty"`
			SubjectCN   string   `json:"subject_cn,omitempty"`
			SubjectAN   []string `json:"subject_an,omitempty"`
			IssuerDN    string   `json:"issuer_dn,omitempty"`
			NotAfter    string   `json:"not_after,omitempty"`
			TLSVersion  string   `json:"tls_version,omitempty"`
		}{result.Hashes.SHA256, commonName, sans, result.IssuerDN, result.NotAfter, result.TLSVersion})
		if err != nil {
			return nil, nil, fmt.Errorf("encode TLS observation: %w", err)
		}
		observations = append(observations, Observation{Category: "tls_certificate", StableKey: activeURL, Value: string(value), Source: "tlsx", ToolVersion: version})
		writeJSONLine(&artifact, struct {
			URL         string   `json:"url"`
			Fingerprint string   `json:"sha256,omitempty"`
			SubjectCN   string   `json:"subject_cn,omitempty"`
			SubjectAN   []string `json:"subject_an,omitempty"`
			IssuerDN    string   `json:"issuer_dn,omitempty"`
			NotAfter    string   `json:"not_after,omitempty"`
			TLSVersion  string   `json:"tls_version,omitempty"`
		}{activeURL, result.Hashes.SHA256, commonName, sans, result.IssuerDN, result.NotAfter, result.TLSVersion})
		if artifact.Len() > maxArtifactOutput {
			return nil, nil, fmt.Errorf("TLSX sanitized artifact exceeds %d bytes", maxArtifactOutput)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read tlsx output: %w", err)
	}
	return observations, artifact.Bytes(), nil
}

func authorizedTLSEndpoint(scope assessment.Scope, host string, port uint16, targets []string) (string, bool) {
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") || !scope.AllowsActiveURL(target) {
			continue
		}
		targetHost, err := assessment.NormalizeHost(parsed.Hostname())
		if err != nil || targetHost != host || activeURLPort(parsed) != port {
			continue
		}
		return target, true
	}
	return "", false
}

func activeURLPort(parsed *url.URL) uint16 {
	if value := parsed.Port(); value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return 0
		}
		return uint16(port)
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return 443
	}
	if strings.EqualFold(parsed.Scheme, "http") {
		return 80
	}
	return 0
}

func webProfileVersion(versions []string, limits StageLimits) string {
	material := fmt.Sprintf("%s\n%s\n%d\n%d\n%d\n%d", ProfileWebVersion, strings.Join(versions, "\n"),
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	sum := sha256.Sum256([]byte(material))
	return ProfileWebVersion + "-" + hex.EncodeToString(sum[:8])
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func emptyToolConfig() (string, func(), error) {
	directory, err := os.MkdirTemp("", "heimdall-web-")
	if err != nil {
		return "", nil, fmt.Errorf("create isolated tool configuration directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", nil, fmt.Errorf("restrict tool configuration directory: %w", err)
	}
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		_ = os.RemoveAll(directory)
		return "", nil, fmt.Errorf("write isolated tool configuration: %w", err)
	}
	return path, func() { _ = os.RemoveAll(directory) }, nil
}
