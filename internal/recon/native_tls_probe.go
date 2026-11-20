package recon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// NativeTLSProbe performs exactly one bounded TLS handshake per authorized
// HTTPS target and records certificate metadata. It does not send an HTTP
// request, follow redirects, persist certificates or bodies, or invoke a shell.
type NativeTLSProbe struct {
	Now func() time.Time
}

const agentTLSProbeVersion = "native-tls-v1"

func (NativeTLSProbe) Spec() AgentToolSpec {
	return AgentToolSpec{
		ID: AgentTLSProbeID, Version: agentTLSProbeVersion,
		Stage: StageWeb, Class: AgentToolClassSafeActive, Origin: AgentToolOriginCompiled,
		Isolation:   AgentToolIsolationNativeMetered,
		Description: "Perform one bounded TLS handshake per authorized HTTPS target and record certificate metadata, without HTTP requests, bodies, redirects, retries, or a shell.",
		TargetTypes: []string{AgentToolTargetHTTPURL}, ScopeRule: AgentToolScopeProgramActiveURL,
		MaxTargets: AgentTLSProbeMaxTargets, MaxRequests: AgentTLSProbeMaxTargets,
		Arguments: []ToolArgument{{
			Name: "targets", Type: ToolArgumentStringList, Required: true,
			MaxItems: AgentTLSProbeMaxTargets, MaxLength: AgentTLSProbeMaxURLBytes,
		}},
		Accounting: AgentToolAccountingOnePerTarget,
	}
}

func (probe NativeTLSProbe) Execute(ctx context.Context, request StageRequest) (Collection, error) {
	collection := Collection{Tools: []ToolResult{{
		ID: AgentTLSProbeID, Binary: "builtin", Version: agentTLSProbeVersion, Status: "running",
	}}}
	probe.appendLog(&collection, "info", "tls_probe_started", "", "native TLS handshake probe started")
	targets, err := validateNativeTLSProbeRequest(request)
	if err != nil {
		probe.appendLog(&collection, "error", "tls_probe_rejected", "", err.Error())
		collection.Tools[0].Status = "failed"
		collection.Tools[0].Error = err.Error()
		return collection, err
	}
	timeout := time.Duration(request.Limits.TimeoutSeconds) * time.Second
	stageContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
		if err := probe.probeTarget(stageContext, request, target, timeout, &collection); err != nil {
			return collection, err
		}
	}
	collection.ProfileVersion = agentTLSProbeVersion
	collection.Tools[0].Status = "complete"
	probe.appendLog(&collection, "info", "tls_probe_completed", "", fmt.Sprintf("TLS handshakes completed=%d", len(collection.Outcomes)))
	return collection, nil
}

func (probe NativeTLSProbe) probeTarget(ctx context.Context, request StageRequest, target string, timeout time.Duration, collection *Collection) error {
	parsed, err := url.Parse(target)
	if err != nil {
		probe.recordFailure(collection, target, "tls_error", errors.New("could not parse authorized TLS target"))
		return errors.New("could not parse authorized TLS target")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(parsed.Hostname(), port)
	if err := request.RequestMeter.ConsumeRequest(ctx); err != nil {
		probe.recordFailure(collection, target, "request_error", err)
		return fmt.Errorf("native TLS probe request meter: %w", err)
	}
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		probe.recordFailure(collection, target, tlsFailureResult(ctx, err), err)
		return fmt.Errorf("native TLS probe connection failed: %w", err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	// #nosec G402 -- the probe records certificate metadata and intentionally
	// does not authenticate the peer; it sends no application data.
	connection := tls.Client(raw, &tls.Config{
		ServerName: parsed.Hostname(), InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13,
	})
	if err := connection.HandshakeContext(ctx); err != nil {
		probe.recordFailure(collection, target, tlsFailureResult(ctx, err), err)
		return fmt.Errorf("native TLS probe handshake failed: %w", err)
	}
	state := connection.ConnectionState()
	value := tlsObservationValue(state)
	observedAt := probe.now()
	collection.Observations = append(collection.Observations, Observation{
		Category: CategoryTLSProbe, StableKey: target, Value: value,
		Source: AgentTLSProbeID, ToolVersion: agentTLSProbeVersion, ObservedAt: observedAt,
	})
	collection.Outcomes = append(collection.Outcomes, AgentOutcome{
		Target: target, Method: "TLS", Result: "tls_handshake",
	})
	collection.Logs = append(collection.Logs, LogEntry{
		At: observedAt, Level: "info", Event: "tls_handshake_completed", Target: target, Detail: value,
	})
	return nil
}

func tlsFailureResult(ctx context.Context, err error) string {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "tls_error"
}

func tlsObservationValue(state tls.ConnectionState) string {
	value := "TLS " + tlsVersionLabel(state.Version)
	if len(state.PeerCertificates) == 0 {
		return value + " certificates=0"
	}
	certificate := state.PeerCertificates[0]
	value += " expires=" + certificate.NotAfter.UTC().Format(time.RFC3339)
	if issuer := truncateAgentText(certificate.Issuer.String(), 200); issuer != "" {
		value += " issuer=" + issuer
	}
	return value
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func (probe NativeTLSProbe) recordFailure(collection *Collection, target, result string, failure error) {
	event := "tls_handshake_failed"
	if result == "timeout" {
		event = "tls_handshake_timeout"
	}
	collection.Tools[0].Status = "failed"
	collection.Tools[0].Error = failure.Error()
	collection.Outcomes = append(collection.Outcomes, AgentOutcome{
		Target: target, Method: "TLS", Result: result,
	})
	probe.appendLog(collection, "error", event, target, failure.Error())
}

func (probe NativeTLSProbe) appendLog(collection *Collection, level, event, target, detail string) {
	collection.Logs = append(collection.Logs, LogEntry{
		At: probe.now(), Level: level, Event: event, Target: target, Detail: detail,
	})
}

func (probe NativeTLSProbe) now() time.Time {
	if probe.Now != nil {
		return probe.Now().UTC()
	}
	return time.Now().UTC()
}

func validateNativeTLSProbeRequest(request StageRequest) ([]string, error) {
	return validateNativeProbeEnvelope(request, "native TLS probe", "one handshake per target", validateNativeTLSTargets)
}

func validateNativeTLSTargets(scope assessment.Scope, proposed []string) ([]string, error) {
	seen := make(map[string]struct{}, len(proposed))
	targets := make([]string, 0, len(proposed))
	for _, raw := range proposed {
		target := strings.TrimSpace(raw)
		parsed, err := url.Parse(target)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
			parsed.Scheme != "https" || parsed.Hostname() == "" || !scope.AllowsActiveURL(target) {
			return nil, fmt.Errorf("native TLS probe target %q is outside the authorized active HTTPS scope", target)
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("native TLS probe target %q is duplicated", target)
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}
