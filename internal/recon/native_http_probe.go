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
}

func (NativeHTTPProbe) Spec() ToolSpec {
	return ToolSpec{ID: AgentHTTPProbeID, Stage: StageWeb, Binary: "builtin", Timeout: time.Minute}
}

func (probe NativeHTTPProbe) Execute(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{Tools: []ToolResult{{ID: AgentHTTPProbeID, Binary: "builtin", Version: "native-http-v1", Status: "running"}}}
	targets, err := validateNativeHTTPProbeRequest(request)
	if err != nil {
		return collection, err
	}
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
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = stageContext.Err().Error()
			return collection, stageContext.Err()
		case <-timer.C:
		}
		req, err := http.NewRequestWithContext(stageContext, http.MethodHead, target, nil)
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = "could not build authorized HEAD request"
			return collection, errors.New("could not build authorized HEAD request")
		}
		response, err := client.Do(req)
		if err != nil {
			collection.Tools[0].Status = "failed"
			collection.Tools[0].Error = err.Error()
			return collection, fmt.Errorf("native HTTP probe request failed: %w", err)
		}
		_ = response.Body.Close()
		collection.Observations = append(collection.Observations, Observation{
			Category: CategoryHTTPProbe, StableKey: target,
			Value: fmt.Sprintf("HEAD status=%d", response.StatusCode), Source: AgentHTTPProbeID,
		})
	}
	collection.ProfileVersion = "native-http-v1"
	collection.Tools[0].Status = "complete"
	return collection, nil
}

func validateNativeHTTPProbeRequest(request StageRequest) ([]string, error) {
	if request.Stage != StageWeb {
		return nil, fmt.Errorf("native HTTP probe only supports the %q stage", StageWeb)
	}
	if request.RequestMeter == nil {
		return nil, errors.New("native HTTP probe requires a durable request meter")
	}
	if request.Program.ID == "" || request.Program.Status != assessment.ProgramActive || !request.Program.ExpiresAt.After(time.Now().UTC()) {
		return nil, errors.New("native HTTP probe requires an active program with current authorization")
	}
	fingerprint, err := assessment.ScopeFingerprint(request.Program.Scope)
	if err != nil || fingerprint != request.Program.ScopeHash {
		return nil, errors.New("native HTTP probe received an invalid or stale scope")
	}
	limits := request.Limits
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("validate native HTTP probe limits: %w", err)
	}
	if len(request.Targets) == 0 || len(request.Targets) > limits.MaxTargets {
		return nil, errors.New("native HTTP probe targets are empty or exceed the configured target limit")
	}
	targets, err := validateNativeProbeTargets(request.Program.Scope, request.Targets)
	if err != nil {
		return nil, err
	}
	if request.RequestBudget < len(targets) {
		return nil, errors.New("native HTTP probe request budget must cover one HEAD per target")
	}
	return targets, nil
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
