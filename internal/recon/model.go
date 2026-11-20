package recon

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

const (
	StageOSINT           = "osint"
	StageDNS             = "dns"
	StageWeb             = "web"
	StageNmap            = "nmap"
	StageCrawl           = "crawl"
	StageFFUF            = "ffuf"
	StageNuclei          = "nuclei"
	ProfileOSINTVersion  = "osint-v2"
	ProfileDNSVersion    = "dns-v1"
	ProfileWebVersion    = "web-v1"
	ProfileNmapVersion   = "nmap-v1"
	ProfileCrawlVersion  = "crawl-v1"
	ProfileFFUFVersion   = "ffuf-v1"
	ProfileNucleiVersion = "nuclei-v1"
	NormalizerVersion    = "observations-v1"
	CategoryHostname     = "hostname"
	CategoryHTTPEndpoint = "http_endpoint"
	CategoryVulnFinding  = "vulnerability_finding"
	CategoryHTTPProbe    = "http_probe_result"
	CategoryTLSProbe     = "tls_probe_result"
	maxArtifactOutput    = 32 << 20
)

type Observation struct {
	Category    string
	StableKey   string
	Value       string
	Source      string
	ToolVersion string
	ObservedAt  time.Time
}

func appendArtifactOutput(destination *bytes.Buffer, data []byte) error {
	if destination.Len()+len(data) > maxArtifactOutput {
		return fmt.Errorf("sanitized tool artifact exceeds %d bytes", maxArtifactOutput)
	}
	_, err := destination.Write(data)
	return err
}

type Artifact struct {
	Name      string
	MediaType string
	Data      []byte
}

type ToolResult struct {
	ID      string
	Binary  string
	Version string
	Status  string
	Error   string
}

type Collection struct {
	Observations   []Observation
	Artifacts      []Artifact
	Tools          []ToolResult
	Outcomes       []AgentOutcome
	Logs           []LogEntry
	ProfileVersion string
}

type Collector interface {
	Collect(ctx context.Context, program assessment.Program) (Collection, error)
}

type StageRunner interface {
	Run(ctx context.Context, request StageRequest) (Collection, error)
}

type StageLimits struct {
	RateLimitPerSecond int
	MaxConcurrency     int
	MaxTargets         int
	TimeoutSeconds     int
}

type StageRequest struct {
	Program        assessment.Program
	Stage          string
	Targets        []string
	Limits         StageLimits
	RequestMeter   RequestMeter
	RequestBudget  int
	RequestProfile assessment.RequestProfile
}

func DefaultStageLimits(stage string) StageLimits {
	switch stage {
	case StageOSINT:
		return StageLimits{RateLimitPerSecond: 2, MaxConcurrency: 2, MaxTargets: 5000, TimeoutSeconds: 1200}
	case StageDNS:
		return StageLimits{RateLimitPerSecond: 10, MaxConcurrency: 10, MaxTargets: 5000, TimeoutSeconds: 600}
	case StageWeb:
		return StageLimits{RateLimitPerSecond: 2, MaxConcurrency: 2, MaxTargets: 1000, TimeoutSeconds: 600}
	case StageNmap:
		return StageLimits{RateLimitPerSecond: 5, MaxConcurrency: 1, MaxTargets: 256, TimeoutSeconds: 1200}
	case StageCrawl:
		return StageLimits{RateLimitPerSecond: 2, MaxConcurrency: 2, MaxTargets: 1000, TimeoutSeconds: 600}
	case StageFFUF, StageNuclei:
		return StageLimits{RateLimitPerSecond: 2, MaxConcurrency: 2, MaxTargets: 100, TimeoutSeconds: 600}
	default:
		return StageLimits{}
	}
}

// resolveStageLimits fills unset fields with the stage defaults and rejects an
// invalid configuration before a collector resolves a binary or opens a
// connection. Collectors share it to keep their dispatch paths small.
func resolveStageLimits(stage string, limits StageLimits) (StageLimits, error) {
	defaults := DefaultStageLimits(stage)
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
		return StageLimits{}, err
	}
	return limits, nil
}

func (l StageLimits) Validate() error {
	if l.RateLimitPerSecond < 1 || l.RateLimitPerSecond > 1000 {
		return fmt.Errorf("rate limit must be between 1 and 1000 requests per second")
	}
	if l.MaxConcurrency < 1 || l.MaxConcurrency > 100 {
		return fmt.Errorf("max concurrency must be between 1 and 100")
	}
	if l.MaxTargets < 1 || l.MaxTargets > 50000 {
		return fmt.Errorf("max targets must be between 1 and 50000")
	}
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}
	return nil
}

type StageSet struct {
	OSINT  Collector
	DNS    DNSCollector
	Web    WebCollector
	Nmap   NmapCollector
	Crawl  KatanaCollector
	FFUF   FFUFCollector
	Nuclei NucleiCollector
}

func (s StageSet) Run(ctx context.Context, request StageRequest) (Collection, error) {
	switch request.Stage {
	case StageOSINT:
		if s.OSINT == nil {
			return Collection{}, fmt.Errorf("no collector configured for stage %q", request.Stage)
		}
		if limitAware, ok := s.OSINT.(LimitAwareCollector); ok {
			return limitAware.CollectWithLimits(ctx, request.Program, request.Limits)
		}
		return s.OSINT.Collect(ctx, request.Program)
	case StageDNS:
		return s.DNS.CollectWithLimits(ctx, request.Program, request.Limits)
	case StageWeb:
		return s.Web.Collect(ctx, request)
	case StageNmap:
		return s.Nmap.Collect(ctx, request)
	case StageCrawl:
		return s.Crawl.Collect(ctx, request)
	case StageFFUF:
		return s.FFUF.Collect(ctx, request)
	case StageNuclei:
		return s.Nuclei.Collect(ctx, request)
	default:
		return Collection{}, fmt.Errorf("no collector registered for stage %q", request.Stage)
	}
}

func DefaultProfileVersion(stage string) string {
	switch stage {
	case StageOSINT:
		return ProfileOSINTVersion
	case StageDNS:
		return ProfileDNSVersion
	case StageWeb:
		return ProfileWebVersion
	case StageNmap:
		return ProfileNmapVersion
	case StageCrawl:
		return ProfileCrawlVersion
	case StageFFUF:
		return ProfileFFUFVersion
	case StageNuclei:
		return ProfileNucleiVersion
	default:
		return "unknown"
	}
}
