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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type KatanaCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (KatanaCollector) ToolSpecs() []ToolSpec {
	return []ToolSpec{{ID: "katana", Stage: StageCrawl, Binary: "katana", BinaryEnv: "HEIMDALL_KATANA", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute}}
}

func (c KatanaCollector) Collect(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{}
	limits := request.Limits
	defaults := DefaultStageLimits(StageCrawl)
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
	targets, scopes, outOfScopes := katanaTargets(request.Program.Scope, request.Targets)
	if len(targets) == 0 {
		return collection, errors.New("Katana has no in-scope URL targets; run web inventory first or configure an in-scope URL")
	}
	if len(targets) > limits.MaxTargets {
		return collection, fmt.Errorf("Katana has %d targets, exceeding the configured limit of %d", len(targets), limits.MaxTargets)
	}
	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	spec := (KatanaCollector{}).ToolSpecs()[0]
	binary := strings.TrimSpace(os.Getenv(spec.BinaryEnv))
	if binary == "" {
		binary = spec.Binary
	}
	resolved, err := resolve(binary)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: binary, Status: "missing", Error: err.Error()}}
		return collection, fmt.Errorf("katana is required for the crawl stage: %w", err)
	}
	version, err := readToolVersion(ctx, runner, resolved, spec.VersionArgs...)
	if err != nil {
		collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Status: "failed", Error: err.Error()}}
		return collection, fmt.Errorf("check katana version: %w", err)
	}
	collection.Tools = []ToolResult{{ID: spec.ID, Binary: resolved, Version: version, Status: "complete"}}
	configPath, cleanup, err := emptyToolConfig()
	if err != nil {
		return collection, err
	}
	defer cleanup()
	pagesPerDomain := limits.MaxTargets / len(targets)
	if pagesPerDomain < 1 {
		pagesPerDomain = 1
	}
	args := []string{
		"-config", configPath, "-jsonl", "-silent", "-omit-raw", "-omit-body", "-disable-update-check", "-disable-redirects", "-no-scope",
		"-depth", "2", "-max-domain-pages", strconv.Itoa(pagesPerDomain),
		"-concurrency", strconv.Itoa(limits.MaxConcurrency), "-parallelism", "1", "-rate-limit", strconv.Itoa(limits.RateLimitPerSecond),
		"-timeout", strconv.Itoa(minInt(limits.TimeoutSeconds, 10)), "-crawl-duration", strconv.Itoa(limits.TimeoutSeconds) + "s",
	}
	for _, pattern := range scopes {
		args = append(args, "-crawl-scope", pattern)
	}
	for _, pattern := range outOfScopes {
		args = append(args, "-crawl-out-scope", pattern)
	}
	stageContext, cancel := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancel()
	output, stderr, err := runner.RunWithInput(stageContext, resolved, []byte(strings.Join(targets, "\n")+"\n"), args...)
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("crawl authorized URLs with Katana: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	observations, artifact, err := parseKatanaOutput(output, request.Program.Scope, version, limits.MaxTargets)
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("parse Katana output: %w", err)
	}
	collection.Observations = observations
	if len(artifact) > 0 {
		collection.Artifacts = []Artifact{{Name: "katana.jsonl", MediaType: "application/x-ndjson", Data: artifact}}
	}
	collection.ProfileVersion = crawlProfileVersion(version, limits)
	return collection, nil
}

func katanaTargets(scope assessment.Scope, seeds []string) ([]string, []string, []string) {
	seedSet := make(map[string]struct{})
	for _, seed := range seeds {
		endpoint, _, err := normalizeEndpoint(seed)
		if err == nil && scope.AllowsActiveURL(endpoint) {
			seedSet[endpoint] = struct{}{}
		}
	}
	for _, host := range scope.DiscoveryDomains() {
		for _, target := range scope.ActiveURLsForHost(host) {
			seedSet[target] = struct{}{}
		}
	}
	for _, entry := range scope.Entries {
		if entry.Effect == assessment.ScopeInclude && entry.Type == assessment.ScopeIP {
			for _, target := range scope.ActiveURLsForHost(entry.Value) {
				seedSet[target] = struct{}{}
			}
		}
	}
	targets := make([]string, 0, len(seedSet))
	for target := range seedSet {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	scopePatterns := make(map[string]struct{})
	outOfScopePatterns := make(map[string]struct{})
	for _, target := range targets {
		for _, pattern := range katanaIncludePatterns(scope, target) {
			scopePatterns[pattern] = struct{}{}
		}
		for _, pattern := range katanaExcludePatterns(scope, target) {
			outOfScopePatterns[pattern] = struct{}{}
		}
	}
	return targets, sortedKeys(scopePatterns), sortedKeys(outOfScopePatterns)
}

func katanaIncludePatterns(scope assessment.Scope, target string) []string {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	host, err := assessment.NormalizeHost(parsed.Hostname())
	if err != nil {
		return nil
	}
	port := activeURLPort(parsed)
	pathPrefixes := make(map[string]struct{})
	for _, entry := range scope.Entries {
		if entry.Effect != assessment.ScopeInclude {
			continue
		}
		if entry.Type == assessment.ScopeURL {
			scopeURL, err := url.Parse(entry.Value)
			if err == nil && strings.EqualFold(scopeURL.Scheme, parsed.Scheme) && assessmentHost(scopeURL.Hostname()) == host && activeURLPort(scopeURL) == port && scope.AllowsActiveURL(scopeURL.String()) {
				path := scopeURL.Path
				if path == "" {
					path = "/"
				}
				pathPrefixes[path] = struct{}{}
			}
			continue
		}
		if hasAllowedPort(scope.AllowedPortsForHost(host), port) {
			pathPrefixes["/"] = struct{}{}
		}
	}
	if len(pathPrefixes) == 0 {
		return nil
	}
	authority := regexp.QuoteMeta(host)
	if strings.Contains(host, ":") {
		authority = regexp.QuoteMeta("[" + host + "]")
	}
	if explicitPort := parsed.Port(); explicitPort != "" {
		authority += ":" + regexp.QuoteMeta(explicitPort)
	} else if (parsed.Scheme == "https" && port == 443) || (parsed.Scheme == "http" && port == 80) {
		authority += "(?::" + strconv.Itoa(int(port)) + ")?"
	}
	paths := make([]string, 0, len(pathPrefixes))
	for path := range pathPrefixes {
		path = strings.TrimSuffix(path, "/")
		if path == "" {
			paths = append(paths, `(?:/.*)?`)
		} else {
			paths = append(paths, regexp.QuoteMeta(path)+`(?:/.*)?`)
		}
	}
	sort.Strings(paths)
	patterns := make([]string, 0, len(paths))
	for _, path := range paths {
		patterns = append(patterns, "^"+regexp.QuoteMeta(strings.ToLower(parsed.Scheme))+"://"+authority+path+`(?:\?.*)?$`)
	}
	return patterns
}

func katanaExcludePatterns(scope assessment.Scope, target string) []string {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	targetHost := assessmentHost(parsed.Hostname())
	targetPort := activeURLPort(parsed)
	patterns := make([]string, 0)
	for _, entry := range scope.Entries {
		if entry.Effect != assessment.ScopeExclude || entry.Type != assessment.ScopeURL {
			continue
		}
		excluded, err := url.Parse(entry.Value)
		if err != nil || !strings.EqualFold(excluded.Scheme, parsed.Scheme) || assessmentHost(excluded.Hostname()) != targetHost || activeURLPort(excluded) != targetPort {
			continue
		}
		host := regexp.QuoteMeta(targetHost)
		if strings.Contains(targetHost, ":") {
			host = regexp.QuoteMeta("[" + targetHost + "]")
		}
		authority := host
		if explicitPort := excluded.Port(); explicitPort != "" {
			authority += ":" + regexp.QuoteMeta(explicitPort)
		} else if (parsed.Scheme == "https" && targetPort == 443) || (parsed.Scheme == "http" && targetPort == 80) {
			authority += "(?::" + strconv.Itoa(int(targetPort)) + ")?"
		}
		path := strings.TrimSuffix(excluded.Path, "/")
		if path == "" {
			path = "/"
		}
		patterns = append(patterns, "^"+regexp.QuoteMeta(strings.ToLower(parsed.Scheme))+"://"+authority+regexp.QuoteMeta(path)+`(?:/.*)?(?:\?.*)?$`)
	}
	return patterns
}

func parseKatanaOutput(output []byte, scope assessment.Scope, version string, maxTargets int) ([]Observation, []byte, error) {
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
		var record struct {
			URL     string `json:"url"`
			Request struct {
				Endpoint string `json:"endpoint"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		rawURL := record.URL
		if rawURL == "" {
			rawURL = record.Request.Endpoint
		}
		endpoint, host, err := normalizeEndpoint(rawURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid crawled URL %q: %w", rawURL, err)
		}
		if !scope.AllowsActiveURL(endpoint) {
			continue
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		observations = append(observations, Observation{Category: CategoryHTTPEndpoint, StableKey: endpoint,
			Value: `{"source":"katana"}`, Source: "katana", ToolVersion: version})
		if len(observations) > maxTargets {
			return nil, nil, fmt.Errorf("Katana produced more than %d in-scope endpoints", maxTargets)
		}
		writeJSONLine(&artifact, struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		}{URL: endpoint, Host: host})
		if artifact.Len() > maxArtifactOutput {
			return nil, nil, fmt.Errorf("Katana sanitized artifact exceeds %d bytes", maxArtifactOutput)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read Katana output: %w", err)
	}
	return observations, artifact.Bytes(), nil
}

func hasAllowedPort(ports []uint16, wanted uint16) bool {
	for _, port := range ports {
		if port == wanted {
			return true
		}
	}
	return false
}

func crawlProfileVersion(version string, limits StageLimits) string {
	material := fmt.Sprintf("%s\n%s\n%d\n%d\n%d\n%d", ProfileCrawlVersion, version,
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	sum := sha256.Sum256([]byte(material))
	return ProfileCrawlVersion + "-" + hex.EncodeToString(sum[:8])
}

func assessmentHost(host string) string {
	normalized, _ := assessment.NormalizeHost(host)
	return normalized
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
