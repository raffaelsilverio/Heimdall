package recon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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

type NmapCollector struct {
	Runner  CommandRunner
	Resolve BinaryResolver
}

func (NmapCollector) ToolSpecs() []ToolSpec {
	return []ToolSpec{{ID: "nmap", Stage: StageNmap, Binary: "nmap", BinaryEnv: "HEIMDALL_NMAP", VersionArgs: []string{"--version"}, Timeout: 20 * time.Minute}}
}

func (c NmapCollector) Collect(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{}
	limits := request.Limits
	defaults := DefaultStageLimits(StageNmap)
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
	targets, err := buildNmapTargets(request.Program.Scope, request.Targets, limits.MaxTargets)
	if err != nil {
		return collection, err
	}
	if len(targets) == 0 {
		return collection, errors.New("nmap stage has no targets with explicitly authorized ports")
	}
	runner := c.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	resolve := c.Resolve
	if resolve == nil {
		resolve = exec.LookPath
	}
	binary := strings.TrimSpace(os.Getenv("HEIMDALL_NMAP"))
	if binary == "" {
		binary = "nmap"
	}
	resolved, err := resolve(binary)
	if err != nil {
		collection.Tools = []ToolResult{{ID: "nmap", Binary: binary, Status: "missing", Error: err.Error()}}
		return collection, fmt.Errorf("nmap is required for the nmap stage: %w", err)
	}
	version, err := readToolVersion(ctx, runner, resolved, "--version")
	if err != nil {
		collection.Tools = []ToolResult{{ID: "nmap", Binary: resolved, Status: "failed", Error: err.Error()}}
		return collection, fmt.Errorf("check nmap version: %w", err)
	}
	collection.Tools = []ToolResult{{ID: "nmap", Binary: resolved, Version: version, Status: "complete"}}
	stageContext, cancel := context.WithTimeout(ctx, time.Duration(limits.TimeoutSeconds)*time.Second)
	defer cancel()
	hostTimeout := limits.TimeoutSeconds
	if hostTimeout > 120 {
		hostTimeout = 120
	}
	var artifact bytes.Buffer
	for _, target := range targets {
		ports := uint16List(target.ports)
		stdout, stderr, err := runner.Run(stageContext, resolved,
			"-sT", "-Pn", "--max-retries", "1", "--max-rate", strconv.Itoa(limits.RateLimitPerSecond),
			"--max-parallelism", strconv.Itoa(limits.MaxConcurrency), "--host-timeout", strconv.Itoa(hostTimeout)+"s",
			"-p", ports, "-oX", "-", target.host)
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, fmt.Errorf("nmap connect scan for %s: %w: %s", target.host, err, strings.TrimSpace(string(stderr)))
		}
		facts, sanitized, err := parseNmapXML(stdout, target, version)
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, fmt.Errorf("parse nmap XML for %s: %w", target.host, err)
		}
		collection.Observations = append(collection.Observations, facts...)
		if err := appendArtifactOutput(&artifact, sanitized); err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, err
		}
	}
	if artifact.Len() > 0 {
		collection.Artifacts = append(collection.Artifacts, Artifact{Name: "nmap.jsonl", MediaType: "application/x-ndjson", Data: artifact.Bytes()})
	}
	collection.ProfileVersion = nmapProfileVersion(version, limits)
	return collection, nil
}

type nmapTarget struct {
	host  string
	ports []uint16
}

func buildNmapTargets(scope assessment.Scope, seeds []string, maxTargets int) ([]nmapTarget, error) {
	portMap := make(map[string]map[uint16]struct{})
	add := func(host string) {
		normalized, err := assessment.NormalizeHost(host)
		if err != nil || !scope.AllowsHost(normalized) {
			return
		}
		ports := scope.AllowedPortsForHost(normalized)
		if len(ports) == 0 {
			return
		}
		if portMap[normalized] == nil {
			portMap[normalized] = make(map[uint16]struct{})
		}
		for _, port := range ports {
			portMap[normalized][port] = struct{}{}
		}
	}
	for _, host := range seeds {
		add(host)
	}
	for _, host := range scope.DiscoveryDomains() {
		add(host)
	}
	for _, entry := range scope.Entries {
		if entry.Effect == assessment.ScopeInclude && entry.Type == assessment.ScopeIP {
			add(entry.Value)
		}
		if entry.Effect == assessment.ScopeInclude && entry.Type == assessment.ScopeCIDR && len(entry.Ports) > 0 {
			addresses, err := expandPrefix(entry.Value, maxTargets)
			if err != nil {
				return nil, err
			}
			for _, address := range addresses {
				add(address)
			}
		}
		if len(portMap) > maxTargets {
			return nil, fmt.Errorf("nmap scope exceeds the configured target limit of %d", maxTargets)
		}
	}
	if len(portMap) > maxTargets {
		return nil, fmt.Errorf("nmap scope exceeds the configured target limit of %d", maxTargets)
	}
	targets := make([]nmapTarget, 0, len(portMap))
	for host, set := range portMap {
		ports := make([]uint16, 0, len(set))
		for port := range set {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		targets = append(targets, nmapTarget{host: host, ports: ports})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].host < targets[j].host })
	return targets, nil
}

func expandPrefix(raw string, maxTargets int) ([]string, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return nil, err
	}
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits >= 31 {
		return nil, fmt.Errorf("CIDR %s is too large to enumerate within the target limit", raw)
	}
	count := 1 << bits
	if count > maxTargets {
		return nil, fmt.Errorf("CIDR %s contains %d addresses, exceeding max-targets %d", raw, count, maxTargets)
	}
	addresses := make([]string, 0, count)
	address := prefix.Masked().Addr()
	for index := 0; index < count; index++ {
		addresses = append(addresses, address.String())
		address = address.Next()
	}
	return addresses, nil
}

func parseNmapXML(data []byte, target nmapTarget, version string) ([]Observation, []byte, error) {
	var result struct {
		Hosts []struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   uint16 `xml:"portid,attr"`
				State    struct {
					Name string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name string `xml:"name,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &result); err != nil {
		return nil, nil, err
	}
	allowed := make(map[uint16]struct{}, len(target.ports))
	for _, port := range target.ports {
		allowed[port] = struct{}{}
	}
	observations := make([]Observation, 0)
	var artifact bytes.Buffer
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.Name != "open" {
				continue
			}
			if _, ok := allowed[port.PortID]; !ok {
				return nil, nil, fmt.Errorf("nmap returned unauthorized port %d for %s", port.PortID, target.host)
			}
			protocol := strings.ToLower(port.Protocol)
			service := strings.TrimSpace(port.Service.Name)
			key := fmt.Sprintf("%s|%s|%d", target.host, protocol, port.PortID)
			value, err := json.Marshal(struct {
				State   string `json:"state"`
				Service string `json:"service,omitempty"`
			}{State: "open", Service: service})
			if err != nil {
				return nil, nil, err
			}
			observations = append(observations, Observation{Category: "service", StableKey: key, Value: string(value), Source: "nmap", ToolVersion: version})
			writeJSONLine(&artifact, struct {
				Target   string `json:"target"`
				Protocol string `json:"protocol"`
				Port     uint16 `json:"port"`
				State    string `json:"state"`
				Service  string `json:"service,omitempty"`
			}{target.host, protocol, port.PortID, "open", service})
			if artifact.Len() > maxArtifactOutput {
				return nil, nil, fmt.Errorf("Nmap sanitized artifact exceeds %d bytes", maxArtifactOutput)
			}
		}
	}
	return observations, artifact.Bytes(), nil
}

func uint16List(values []uint16) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, ",")
}

func nmapProfileVersion(version string, limits StageLimits) string {
	material := fmt.Sprintf("%s\n%s\n%d\n%d\n%d\n%d", ProfileNmapVersion, version,
		limits.RateLimitPerSecond, limits.MaxConcurrency, limits.MaxTargets, limits.TimeoutSeconds)
	sum := sha256.Sum256([]byte(material))
	return ProfileNmapVersion + "-" + hex.EncodeToString(sum[:8])
}
