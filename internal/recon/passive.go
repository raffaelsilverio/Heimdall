package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

type AmassAdapter struct{}

func (AmassAdapter) Spec() ToolSpec {
	return ToolSpec{ID: "amass", Stage: StageOSINT, Binary: "amass", BinaryEnv: "HEIMDALL_AMASS", VersionArgs: []string{"-version"}, Timeout: 20 * time.Minute}
}

func (AmassAdapter) Supports(program assessment.Program) bool {
	return len(program.Scope.DiscoveryDomains()) > 0
}

func (AmassAdapter) Collect(ctx context.Context, program assessment.Program, binary string, runner CommandRunner, limits StageLimits) ([]Observation, []Artifact, error) {
	var observations []Observation
	var safeOutput bytes.Buffer
	maxMinutes := (limits.TimeoutSeconds + 59) / 60
	if maxMinutes < 1 {
		maxMinutes = 1
	}
	for _, domain := range program.Scope.DiscoveryDomains() {
		stdout, stderr, err := runner.Run(ctx, binary, "enum", "-passive", "-d", domain, "-timeout", strconv.Itoa(maxMinutes))
		if err != nil {
			return observations, sanitizedArtifacts("amass", "application/x-ndjson", safeOutput.Bytes()),
				fmt.Errorf("passive enumeration for %s: %w: %s", domain, err, strings.TrimSpace(string(stderr)))
		}
		found, sanitized, err := parseAmassOutput(stdout, program.Scope)
		if err != nil {
			return observations, sanitizedArtifacts("amass", "application/x-ndjson", safeOutput.Bytes()),
				fmt.Errorf("parse output for %s: %w", domain, err)
		}
		observations = append(observations, found...)
		if err := appendArtifactOutput(&safeOutput, sanitized); err != nil {
			return observations, sanitizedArtifacts("amass", "application/x-ndjson", safeOutput.Bytes()), err
		}
	}
	return observations, sanitizedArtifacts("amass", "application/x-ndjson", safeOutput.Bytes()), nil
}

var domainCandidate = regexp.MustCompile(`(?i)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]{2,}`)

func parseAmassOutput(output []byte, scope assessment.Scope) ([]Observation, []byte, error) {
	observations := make([]Observation, 0)
	seen := make(map[string]struct{})
	var sanitized bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		for _, candidate := range domainCandidate.FindAllString(scanner.Text(), -1) {
			host, err := assessment.NormalizeHost(candidate)
			if err != nil || isIPAddress(host) || !scope.AllowsHost(host) {
				continue
			}
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			observations = append(observations, Observation{Category: CategoryHostname, StableKey: host, Value: host, Source: "amass"})
			writeJSONLine(&sanitized, struct {
				Host string `json:"host"`
			}{Host: host})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read output: %w", err)
	}
	return observations, sanitized.Bytes(), nil
}

func isIPAddress(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

type UncoverAdapter struct{}

func (UncoverAdapter) Spec() ToolSpec {
	return ToolSpec{ID: "uncover", Stage: StageOSINT, Binary: "uncover", BinaryEnv: "HEIMDALL_UNCOVER", VersionArgs: []string{"-version"}, Timeout: 5 * time.Minute}
}

func (UncoverAdapter) Supports(program assessment.Program) bool {
	return len(program.Scope.DiscoveryDomains()) > 0
}

func (UncoverAdapter) Collect(ctx context.Context, program assessment.Program, binary string, runner CommandRunner, limits StageLimits) ([]Observation, []Artifact, error) {
	var observations []Observation
	var sanitized bytes.Buffer
	seen := make(map[string]struct{})
	for _, domain := range program.Scope.DiscoveryDomains() {
		requestLimit := limits.RateLimitPerSecond * 60
		stdout, stderr, err := runner.Run(ctx, binary, "-q", "hostname:"+domain, "-e", "shodan", "-f", "host",
			"-l", strconv.Itoa(limits.MaxTargets), "-rl", strconv.Itoa(limits.RateLimitPerSecond), "-rlm", strconv.Itoa(requestLimit),
			"-timeout", strconv.Itoa(limits.TimeoutSeconds), "-silent")
		if err != nil {
			return observations, sanitizedArtifacts("uncover.jsonl", "application/x-ndjson", sanitized.Bytes()),
				fmt.Errorf("search hostname %s: %w: %s", domain, err, strings.TrimSpace(string(stderr)))
		}
		found, artifact, err := parseHostnameLines(stdout, program.Scope, "uncover", seen)
		if err != nil {
			return observations, sanitizedArtifacts("uncover.jsonl", "application/x-ndjson", sanitized.Bytes()), err
		}
		observations = append(observations, found...)
		if err := appendArtifactOutput(&sanitized, artifact); err != nil {
			return observations, sanitizedArtifacts("uncover", "application/x-ndjson", sanitized.Bytes()), err
		}
	}
	return observations, sanitizedArtifacts("uncover.jsonl", "application/x-ndjson", sanitized.Bytes()), nil
}

type GauAdapter struct{}

func (GauAdapter) Spec() ToolSpec {
	return ToolSpec{ID: "gau", Stage: StageOSINT, Binary: "gau", BinaryEnv: "HEIMDALL_GAU", VersionArgs: []string{"--version"}, Timeout: 10 * time.Minute}
}

func (GauAdapter) Supports(program assessment.Program) bool {
	return len(program.Scope.DiscoveryDomains()) > 0
}

func (GauAdapter) Collect(ctx context.Context, program assessment.Program, binary string, runner CommandRunner, limits StageLimits) ([]Observation, []Artifact, error) {
	var observations []Observation
	var sanitized bytes.Buffer
	seen := make(map[string]struct{})
	for _, domain := range program.Scope.DiscoveryDomains() {
		stdout, stderr, err := runner.Run(ctx, binary, domain, "--subs", "--threads", strconv.Itoa(limits.MaxConcurrency), "--timeout", strconv.Itoa(limits.TimeoutSeconds))
		if err != nil {
			return observations, sanitizedArtifacts("gau.jsonl", "application/x-ndjson", sanitized.Bytes()),
				fmt.Errorf("archive lookup for %s: %w: %s", domain, err, strings.TrimSpace(string(stderr)))
		}
		found, artifact, err := parseGauOutput(stdout, program.Scope, seen)
		if err != nil {
			return observations, sanitizedArtifacts("gau.jsonl", "application/x-ndjson", sanitized.Bytes()), err
		}
		observations = append(observations, found...)
		if err := appendArtifactOutput(&sanitized, artifact); err != nil {
			return observations, sanitizedArtifacts("gau", "application/x-ndjson", sanitized.Bytes()), err
		}
	}
	return observations, sanitizedArtifacts("gau.jsonl", "application/x-ndjson", sanitized.Bytes()), nil
}

func parseHostnameLines(output []byte, scope assessment.Scope, source string, seen map[string]struct{}) ([]Observation, []byte, error) {
	observations := make([]Observation, 0)
	var sanitized bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host, err := assessment.NormalizeHost(line)
		if err != nil {
			// Search tools can print a warning line despite silent mode. It is
			// not an observation, so ignore it; non-zero exit status is an error.
			continue
		}
		if !scope.AllowsHost(host) {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		observations = append(observations, Observation{Category: CategoryHostname, StableKey: host, Value: host, Source: source})
		writeJSONLine(&sanitized, struct {
			Host string `json:"host"`
		}{Host: host})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read hostname output: %w", err)
	}
	return observations, sanitized.Bytes(), nil
}

func parseGauOutput(output []byte, scope assessment.Scope, seen map[string]struct{}) ([]Observation, []byte, error) {
	observations := make([]Observation, 0)
	var sanitized bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), maxToolOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		endpoint, host, err := normalizeEndpoint(line)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid gau URL %q: %w", line, err)
		}
		if !scope.AllowsURL(endpoint) {
			continue
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		observations = append(observations, Observation{Category: CategoryHTTPEndpoint, StableKey: endpoint, Value: endpoint, Source: "gau"})
		writeJSONLine(&sanitized, struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		}{URL: endpoint, Host: host})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read gau output: %w", err)
	}
	return observations, sanitized.Bytes(), nil
}

func normalizeEndpoint(rawURL string) (string, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return "", "", errors.New("expected an absolute HTTP(S) URL without credentials")
	}
	host, err := assessment.NormalizeHost(parsed.Hostname())
	if err != nil {
		return "", "", err
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", "", fmt.Errorf("invalid port: %w", err)
		}
		if parsedPort == 0 {
			return "", "", errors.New("port must be between 1 and 65535")
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if port == "" || (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		parsed.Host = host
	} else {
		parsed.Host = net.JoinHostPort(host, port)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String(), host, nil
}

func writeJSONLine(output *bytes.Buffer, value any) {
	encoded, _ := json.Marshal(value)
	output.Write(encoded)
	output.WriteByte('\n')
}
