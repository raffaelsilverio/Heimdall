package recon

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func nativeTLSProbeProgram(t *testing.T, serverURL string) (assessment.Program, string) {
	t.Helper()
	parsed, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(parsed.Port)
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeIP, Value: "127.0.0.1", Ports: []uint16{port},
	}}}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	program := assessment.Program{
		ID: "local-tls-probe-test", Status: assessment.ProgramActive, ExpiresAt: time.Now().Add(time.Hour),
		Scope: scope, ScopeHash: scopeHash,
	}
	target := "https://127.0.0.1:" + strconv.Itoa(int(port)) + "/health"
	return program, target
}

func TestNativeTLSProbePerformsOneMeteredHandshakePerTarget(t *testing.T) {
	var applicationRequests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		applicationRequests.Add(1)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()

	program, target := nativeTLSProbeProgram(t, server.URL)
	meter := &nativeProbeMeter{limit: 1}
	fixed := time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)
	probe := NativeTLSProbe{Now: func() time.Time { return fixed }}
	collection, err := probe.Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target},
		Limits:       StageLimits{RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5},
		RequestMeter: meter, RequestBudget: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if meter.used.Load() != 1 {
		t.Fatalf("request meter used = %d, want 1", meter.used.Load())
	}
	if applicationRequests.Load() != 0 {
		t.Fatal("TLS probe sent an HTTP request after the handshake")
	}
	if collection.ProfileVersion != agentTLSProbeVersion {
		t.Fatalf("profile version = %q, want %q", collection.ProfileVersion, agentTLSProbeVersion)
	}
	if len(collection.Observations) != 1 {
		t.Fatalf("observations = %+v, want one TLS observation", collection.Observations)
	}
	observation := collection.Observations[0]
	if observation.Category != CategoryTLSProbe || observation.StableKey != target ||
		observation.Source != AgentTLSProbeID || observation.ToolVersion != agentTLSProbeVersion {
		t.Fatalf("unexpected TLS observation: %+v", observation)
	}
	if !strings.HasPrefix(observation.Value, "TLS ") || !strings.Contains(observation.Value, "expires=") ||
		!strings.Contains(observation.Value, "issuer=") {
		t.Fatalf("TLS observation omitted certificate metadata: %q", observation.Value)
	}
	if strings.Contains(observation.Value, "BEGIN CERTIFICATE") || strings.Contains(observation.Value, "PRIVATE KEY") {
		t.Fatalf("TLS observation leaked raw certificate material: %q", observation.Value)
	}
	if len(collection.Outcomes) != 1 || collection.Outcomes[0].Method != "TLS" || collection.Outcomes[0].Result != "tls_handshake" {
		t.Fatalf("unexpected TLS outcomes: %+v", collection.Outcomes)
	}
	if len(collection.Logs) < 2 || collection.Tools[0].Status != "complete" {
		t.Fatalf("TLS probe logs or status are incomplete: %+v", collection)
	}
}

func TestNativeTLSProbeMetersBeforeConnecting(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	program, target := nativeTLSProbeProgram(t, server.URL)
	meter := &nativeProbeMeter{limit: 0}
	_, err := (NativeTLSProbe{}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target},
		Limits:       StageLimits{RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5},
		RequestMeter: meter, RequestBudget: 1,
	})
	if err == nil {
		t.Fatal("TLS probe proceeded after the request meter rejected the handshake")
	}
	if meter.used.Load() != 1 {
		t.Fatalf("request meter used = %d, want the rejected attempt to be counted", meter.used.Load())
	}
	if connections.Load() != 0 {
		t.Fatal("TLS probe connected before the request meter approved the handshake")
	}
}

func TestNativeTLSProbeRejectsNonHTTPSAndOutOfScopeTargets(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	program, target := nativeTLSProbeProgram(t, server.URL)
	meter := &nativeProbeMeter{limit: 1}
	limits := StageLimits{RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 4, TimeoutSeconds: 5}
	tests := []struct {
		name    string
		targets []string
	}{
		{name: "plain http", targets: []string{strings.Replace(target, "https://", "http://", 1)}},
		{name: "query string", targets: []string{target + "?token=secret"}},
		{name: "duplicate", targets: []string{target, target}},
		{name: "outside scope", targets: []string{"https://example.invalid/"}},
		{name: "userinfo", targets: []string{"https://user:pass@" + strings.Split(strings.TrimPrefix(target, "https://"), "/")[0] + "/health"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (NativeTLSProbe{}).Execute(context.Background(), StageRequest{
				Program: program, Stage: StageWeb, Targets: test.targets, Limits: limits,
				RequestMeter: meter, RequestBudget: len(test.targets),
			})
			if err == nil {
				t.Fatalf("TLS probe accepted targets %v", test.targets)
			}
			if meter.used.Load() != 0 {
				t.Fatalf("request meter was charged %d times for a rejected target list", meter.used.Load())
			}
			if connections.Load() != 0 {
				t.Fatalf("rejected target list %v opened a TLS connection", test.targets)
			}
		})
	}
}
