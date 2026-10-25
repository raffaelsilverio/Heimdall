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
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

const maxAlteredHosts = 5000

type DNSCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (DNSCollector) Specs() []ToolSpec {
	return []ToolSpec{
		{ID: "alterx", Stage: StageDNS, Binary: "alterx", BinaryEnv: "HEIMDALL_ALTERX", VersionArgs: []string{"-version"}, Timeout: 2 * time.Minute},
		{ID: "dnsx", Stage: StageDNS, Binary: "dnsx", BinaryEnv: "HEIMDALL_DNSX", VersionArgs: []string{"-version"}, Timeout: 10 * time.Minute},
	}
}

func (c DNSCollector) Collect(ctx context.Context, program assessment.Program) (Collection, error) {
	return c.CollectWithLimits(ctx, program, DefaultStageLimits(StageDNS))
}

func (c DNSCollector) CollectWithLimits(ctx context.Context, program assessment.Program, limits StageLimits) (Collection, error) {
	var collection Collection
	defaults := DefaultStageLimits(StageDNS)
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
	stageContext, cancel := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancel()
	ctx = stageContext
	domains := program.Scope.DiscoveryDomains()
	if len(domains) == 0 {
		return collection, errors.New("DNS stage requires an included domain or URL scope")
	}
	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	alterx, err := resolveConfiguredBinary("alterx", "HEIMDALL_ALTERX", resolve)
	if err != nil {
		collection.Tools = append(collection.Tools, ToolResult{ID: "alterx", Binary: "alterx", Status: "missing", Error: err.Error()})
		return collection, fmt.Errorf("alterx is required for the DNS stage: %w", err)
	}
	dnsx, err := resolveConfiguredBinary("dnsx", "HEIMDALL_DNSX", resolve)
	if err != nil {
		collection.Tools = append(collection.Tools, ToolResult{ID: "dnsx", Binary: "dnsx", Status: "missing", Error: err.Error()})
		return collection, fmt.Errorf("dnsx is required for the DNS stage: %w", err)
	}

	alterxVersion, err := readToolVersion(ctx, runner, alterx, "-version")
	if err != nil {
		collection.Tools = append(collection.Tools, ToolResult{ID: "alterx", Binary: alterx, Status: "failed", Error: err.Error()})
		return collection, fmt.Errorf("check alterx version: %w", err)
	}
	dnsxVersion, err := readToolVersion(ctx, runner, dnsx, "-version")
	if err != nil {
		collection.Tools = append(collection.Tools, ToolResult{ID: "alterx", Binary: alterx, Version: alterxVersion, Status: "complete"})
		collection.Tools = append(collection.Tools, ToolResult{ID: "dnsx", Binary: dnsx, Status: "failed", Error: err.Error()})
		return collection, fmt.Errorf("check dnsx version: %w", err)
	}
	collection.Tools = append(collection.Tools,
		ToolResult{ID: "alterx", Binary: alterx, Version: alterxVersion, Status: "complete"},
		ToolResult{ID: "dnsx", Binary: dnsx, Version: dnsxVersion, Status: "complete"},
	)

	altered, alterxStderr, err := runner.RunWithInput(ctx, alterx, []byte(strings.Join(domains, "\n")+"\n"),
		"-enrich", "-limit", fmt.Sprint(limits.MaxTargets), "-silent", "-duc")
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("generate DNS candidates with alterx: %w: %s", err, strings.TrimSpace(string(alterxStderr)))
	}
	candidates, err := parseAlterxOutput(altered, program.Scope, limits.MaxTargets)
	if err != nil {
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("parse alterx output: %w", err)
	}
	if len(candidates) == 0 {
		collection.Tools[1].Status = "not_applicable"
		collection.ProfileVersion = dnsProfileVersion(alterxVersion, dnsxVersion, limits)
		return collection, nil
	}
	collection.Artifacts = append(collection.Artifacts, Artifact{
		Name: "alterx.txt", MediaType: "text/plain; charset=utf-8", Data: []byte(strings.Join(candidates, "\n") + "\n"),
	})
	dnsInput := []byte(strings.Join(candidates, "\n") + "\n")
	dnsOutput, stderr, err := runner.RunWithInput(ctx, dnsx, dnsInput,
		"-silent", "-json", "-omit-raw", "-a", "-aaaa", "-cname", "-rcode", "noerror,nxdomain", "-rl", strconv.Itoa(limits.RateLimitPerSecond),
		"-t", strconv.Itoa(limits.MaxConcurrency), "-timeout", "3s", "-duc")
	if err != nil {
		collection.Tools[1].Status = "failed"
		collection.Tools[1].Error = err.Error()
		return collection, fmt.Errorf("resolve DNS candidates with dnsx: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	observations, sanitized, responded, err := parseDNSXOutput(dnsOutput, program.Scope, dnsxVersion)
	if err != nil {
		collection.Tools[1].Status = "failed"
		collection.Tools[1].Error = err.Error()
		return collection, fmt.Errorf("parse dnsx output: %w", err)
	}
	for _, candidate := range candidates {
		if !responded[candidate] {
			collection.Tools[1].Status = "failed"
			collection.Tools[1].Error = "DNS response missing for one or more candidates"
			return collection, fmt.Errorf("dnsx returned no complete response for candidate %s", candidate)
		}
	}
	collection.Observations = observations
	if len(sanitized) > 0 {
		collection.Artifacts = append(collection.Artifacts, Artifact{Name: "dnsx.jsonl", MediaType: "application/x-ndjson", Data: sanitized})
	}
	collection.ProfileVersion = dnsProfileVersion(alterxVersion, dnsxVersion, limits)
	return collection, nil
}

func resolveConfiguredBinary(defaultBinary, environmentVariable string, resolve BinaryResolver) (string, error) {
	binary := strings.TrimSpace(os.Getenv(environmentVariable))
	if binary == "" {
		binary = defaultBinary
	}
	return resolve(binary)
}

func readToolVersion(ctx context.Context, runner CommandRunner, binary string, args ...string) (string, error) {
	versionContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stdout, stderr, err := runner.Run(versionContext, binary, args...)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(stdout) + " " + string(stderr))
	if version == "" {
		version = "unknown"
	}
	return version, nil
}

func parseAlterxOutput(output []byte, scope assessment.Scope, maxAllowed ...int) ([]string, error) {
	limit := maxAlteredHosts
	if len(maxAllowed) > 0 && maxAllowed[0] > 0 {
		limit = maxAllowed[0]
	}
	set := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host, err := assessment.NormalizeHost(line)
		if err != nil {
			return nil, fmt.Errorf("invalid generated hostname %q: %w", line, err)
		}
		if scope.AllowsHost(host) {
			set[host] = struct{}{}
		}
		if len(set) > limit {
			return nil, fmt.Errorf("alterx produced more than %d in-scope candidates", limit)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read altered hosts: %w", err)
	}
	result := make([]string, 0, len(set))
	for host := range set {
		result = append(result, host)
	}
	sort.Strings(result)
	return result, nil
}

func parseDNSXOutput(output []byte, scope assessment.Scope, version string) ([]Observation, []byte, map[string]bool, error) {
	observations := make([]Observation, 0)
	seen := make(map[string]struct{})
	responded := make(map[string]bool)
	var sanitized bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result struct {
			Host       string          `json:"host"`
			StatusCode json.RawMessage `json:"status_code"`
			A          []string        `json:"a"`
			AAAA       []string        `json:"aaaa"`
			CNAME      []string        `json:"cname"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid JSONL record: %w", err)
		}
		host, err := assessment.NormalizeHost(result.Host)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid DNS response host %q: %w", result.Host, err)
		}
		if !scope.AllowsHost(host) {
			continue
		}
		status := strings.ToUpper(strings.Trim(string(result.StatusCode), `"`))
		if status == "" && (len(result.A)+len(result.AAAA)+len(result.CNAME) > 0) {
			status = "NOERROR"
		}
		if status != "NOERROR" && status != "NXDOMAIN" && status != "0" && status != "3" {
			return nil, nil, nil, fmt.Errorf("dnsx returned incomplete status %q for %s", status, host)
		}
		responded[host] = true
		if status != "NXDOMAIN" && status != "3" && len(result.A)+len(result.AAAA)+len(result.CNAME) > 0 {
			addDNSObservation(&observations, seen, CategoryHostname, host, host, version)
		}
		sanitizedRecord := struct {
			Host  string   `json:"host"`
			A     []string `json:"a,omitempty"`
			AAAA  []string `json:"aaaa,omitempty"`
			CNAME []string `json:"cname,omitempty"`
		}{Host: host}
		for _, value := range result.A {
			address, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil || !address.Is4() {
				return nil, nil, nil, fmt.Errorf("invalid A record %q for %s", value, host)
			}
			value = address.String()
			sanitizedRecord.A = append(sanitizedRecord.A, value)
			addDNSObservation(&observations, seen, "dns_record", host+"|A|"+value, value, version)
		}
		for _, value := range result.AAAA {
			address, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil || !address.Is6() {
				return nil, nil, nil, fmt.Errorf("invalid AAAA record %q for %s", value, host)
			}
			value = address.String()
			sanitizedRecord.AAAA = append(sanitizedRecord.AAAA, value)
			addDNSObservation(&observations, seen, "dns_record", host+"|AAAA|"+value, value, version)
		}
		for _, value := range result.CNAME {
			cname, err := assessment.NormalizeHost(strings.TrimSuffix(strings.TrimSpace(value), "."))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("invalid CNAME record %q for %s", value, host)
			}
			sanitizedRecord.CNAME = append(sanitizedRecord.CNAME, cname)
			addDNSObservation(&observations, seen, "dns_record", host+"|CNAME|"+cname, cname, version)
		}
		if err := writeDNSJSONLine(&sanitized, sanitizedRecord); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("read dnsx output: %w", err)
	}
	return observations, sanitized.Bytes(), responded, nil
}

func addDNSObservation(observations *[]Observation, seen map[string]struct{}, category, key, value, version string) {
	identity := category + "\x00" + key
	if _, exists := seen[identity]; exists {
		return
	}
	seen[identity] = struct{}{}
	*observations = append(*observations, Observation{
		Category: category, StableKey: key, Value: value, Source: "dnsx", ToolVersion: version, ObservedAt: time.Now().UTC(),
	})
}

func writeDNSJSONLine(output *bytes.Buffer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := appendArtifactOutput(output, encoded); err != nil {
		return err
	}
	return appendArtifactOutput(output, []byte{'\n'})
}

func dnsProfileVersion(alterxVersion, dnsxVersion string, limits StageLimits) string {
	material := fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%d\n%d", ProfileDNSVersion, alterxVersion, dnsxVersion,
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	sum := sha256.Sum256([]byte(material))
	return ProfileDNSVersion + "-" + hex.EncodeToString(sum[:8])
}
