package recon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// NativeHTTPProbe performs exactly one HEAD request per authorized target. It
// does not follow redirects, retry, persist response bodies, or invoke a shell.
type NativeHTTPProbe struct {
	Transport http.RoundTripper
	Now       func() time.Time
}

const agentHTTPProbeVersion = "native-http-v1"

func (NativeHTTPProbe) Spec() AgentToolSpec {
	return AgentToolSpec{
		ID: AgentHTTPProbeID, Version: agentHTTPProbeVersion,
		Stage: StageWeb, Class: AgentToolClassSafeActive, Origin: AgentToolOriginCompiled,
		Isolation:   AgentToolIsolationNativeMetered,
		Description: "Send one bounded HEAD request per authorized target without redirects, bodies, retries, or a shell.",
		TargetTypes: []string{AgentToolTargetHTTPURL}, ScopeRule: AgentToolScopeProgramActiveURL,
		MaxTargets: AgentHTTPProbeMaxTargets, MaxRequests: AgentHTTPProbeMaxTargets,
		Arguments: []ToolArgument{{
			Name: "targets", Type: ToolArgumentStringList, Required: true,
			MaxItems: AgentHTTPProbeMaxTargets, MaxLength: AgentHTTPProbeMaxURLBytes,
		}},
		Accounting: AgentToolAccountingOnePerTarget,
	}
}

func (probe NativeHTTPProbe) Execute(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{Tools: []ToolResult{{
		ID: AgentHTTPProbeID, Binary: "builtin", Version: agentHTTPProbeVersion, Status: "running",
	}}}
	probe.appendLog(&collection, "info", "probe_started", "", "native HTTP HEAD probe started")
	targets, err := validateNativeHTTPProbeRequest(request)
	if err != nil {
		probe.appendLog(&collection, "error", "probe_rejected", "", err.Error())
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, err
	}
	profile, err := assessment.NormalizeRequestProfile(request.RequestProfile)
	if err != nil {
		probe.appendLog(&collection, "error", "probe_rejected", "", "invalid request profile")
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, fmt.Errorf("native HTTP probe request profile: %w", err)
	}
	probe.appendLog(&collection, "info", "request_profile", "", RequestProfileSummary(profile))
	stageContext, cancel := context.WithTimeout(ctx, time.Duration(request.Limits.TimeoutSeconds)*time.Second)
	defer cancel()
	client := &http.Client{
		Transport: MeteredRoundTripper{Meter: request.RequestMeter, Base: probe.Transport},
		Timeout:   time.Duration(request.Limits.TimeoutSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	interval := time.Second / time.Duration(request.Limits.RateLimitPerSecond)
	for _, target := range targets {
		timer := time.NewTimer(interval)
		select {
		case <-stageContext.Done():
			timer.Stop()
			probe.recordFailure(&collection, target, "timeout", stageContext.Err())
			return collection, stageContext.Err()
		case <-timer.C:
		}
		req, err := http.NewRequestWithContext(stageContext, http.MethodHead, target, nil)
		if err != nil {
			probe.recordFailure(&collection, target, "request_error", errors.New("could not build authorized HEAD request"))
			return collection, errors.New("could not build authorized HEAD request")
		}
		if err := ApplyRequestProfile(req, profile); err != nil {
			probe.recordFailure(&collection, target, "request_error", errors.New("could not apply the program request profile"))
			return collection, fmt.Errorf("native HTTP probe request profile: %w", err)
		}
		response, err := client.Do(req)
		if err != nil {
			probe.recordFailure(&collection, target, "request_error", err)
			return collection, fmt.Errorf("native HTTP probe request failed: %w", err)
		}
		_ = response.Body.Close()
		observedAt := probe.now()
		collection.Observations = append(collection.Observations, Observation{
			Category: CategoryHTTPProbe, StableKey: target,
			Value: fmt.Sprintf("HEAD status=%d", response.StatusCode), Source: AgentHTTPProbeID,
			ToolVersion: agentHTTPProbeVersion, ObservedAt: observedAt,
		})
		collection.Outcomes = append(collection.Outcomes, AgentOutcome{
			Target: target, Method: http.MethodHead, StatusCode: response.StatusCode, Result: "http_response",
		})
		collection.Logs = append(collection.Logs, LogEntry{
			At: observedAt, Level: "info", Event: "request_completed", Target: target,
			Detail: fmt.Sprintf("HEAD status=%d", response.StatusCode),
		})
	}
	collection.ProfileVersion = agentHTTPProbeVersion
	collection.Tools[0].Status = "complete"
	probe.appendLog(&collection, "info", "probe_completed", "", fmt.Sprintf("HEAD requests completed=%d", len(collection.Outcomes)))
	return collection, nil
}

func (probe NativeHTTPProbe) recordFailure(collection *Collection, target, result string, failure error) {
	event := "request_failed"
	if result == "timeout" {
		event = "request_timeout"
	}
	collection.Tools[0].Status = "failed"
	collection.Tools[0].Error = failure.Error()
	collection.Outcomes = append(collection.Outcomes, AgentOutcome{
		Target: target, Method: http.MethodHead, Result: result,
	})
	probe.appendLog(collection, "error", event, target, failure.Error())
}

func (probe NativeHTTPProbe) appendLog(collection *Collection, level, event, target, detail string) {
	collection.Logs = append(collection.Logs, LogEntry{
		At: probe.now(), Level: level, Event: event, Target: target, Detail: detail,
	})
}

func (probe NativeHTTPProbe) now() time.Time {
	if probe.Now != nil {
		return probe.Now().UTC()
	}
	return time.Now().UTC()
}

func validateNativeHTTPProbeRequest(request StageRequest) ([]string, error) {
	return validateNativeProbeEnvelope(request, "native HTTP probe", "one HEAD per target", validateNativeProbeTargets)
}

func validateNativeProbeTargets(scope assessment.Scope, proposed []string) ([]string, error) {
	seen := make(map[string]struct{}, len(proposed))
	targets := make([]string, 0, len(proposed))
	for _, raw := range proposed {
		target := strings.TrimSpace(raw)
		parsed, err := url.Parse(target)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") || !scope.AllowsActiveURL(target) {
			return nil, fmt.Errorf("native HTTP probe target %q is outside the authorized active scope", target)
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("native HTTP probe target %q is duplicated", target)
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}
