package recon

import (
	"context"
	"errors"
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

type nativeProbeMeter struct {
	used  atomic.Int64
	limit int64
}

func (meter *nativeProbeMeter) ConsumeRequest(context.Context) error {
	if meter.used.Add(1) > meter.limit {
		return errors.New("request budget exhausted")
	}
	return nil
}

func TestNativeHTTPProbeMakesOneMeteredHeadAndDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("request method = %s, want HEAD", request.Method)
		}
		writer.Header().Set("Location", "http://outside.invalid/redirect")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	program, target := nativeProbeProgram(t, server.URL)
	meter := &nativeProbeMeter{limit: 1}
	fixed := time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)
	probe := NativeHTTPProbe{Transport: server.Client().Transport, Now: func() time.Time { return fixed }}
	collection, err := probe.Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target}, Limits: StageLimits{
			RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5,
		}, RequestMeter: meter, RequestBudget: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || meter.used.Load() != 1 {
		t.Fatalf("probe request counts: server=%d meter=%d", requests.Load(), meter.used.Load())
	}
	if len(collection.Observations) != 1 || collection.Observations[0].Category != CategoryHTTPProbe ||
		collection.Observations[0].Value != "HEAD status=302" || len(collection.Artifacts) != 0 {
		t.Fatalf("probe persisted unexpected response data: %+v", collection)
	}
	observation := collection.Observations[0]
	if observation.ToolVersion != agentHTTPProbeVersion || !observation.ObservedAt.Equal(fixed) {
		t.Fatalf("observation metadata was not normalized: %+v", observation)
	}
	if collection.ProfileVersion != agentHTTPProbeVersion || len(collection.Outcomes) != 1 ||
		collection.Outcomes[0].Target != target || collection.Outcomes[0].Method != http.MethodHead ||
		collection.Outcomes[0].StatusCode != http.StatusFound || collection.Outcomes[0].Result != "http_response" {
		t.Fatalf("probe outcome was not normalized: %+v", collection.Outcomes)
	}
	events := make([]string, 0, len(collection.Logs))
	for _, entry := range collection.Logs {
		events = append(events, entry.Event)
	}
	if strings.Join(events, ",") != "probe_started,request_profile,request_completed,probe_completed" {
		t.Fatalf("probe logs are incomplete or out of order: %+v", collection.Logs)
	}
}

func TestNativeHTTPProbeRejectsUnmeteredAndOutOfScopeRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	program, target := nativeProbeProgram(t, server.URL)
	limits := StageLimits{RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5}

	if _, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target}, Limits: limits,
	}); err == nil {
		t.Fatal("native probe proceeded without a request meter")
	}
	if requests.Load() != 0 {
		t.Fatal("unmetered request reached the test server")
	}
	meter := &nativeProbeMeter{limit: 1}
	if _, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target}, Limits: limits, RequestMeter: meter, RequestBudget: 0,
	}); err == nil {
		t.Fatal("native probe accepted a request budget below its one-request-per-target cost")
	}
	if requests.Load() != 0 || meter.used.Load() != 0 {
		t.Fatal("request reached meter or server despite insufficient reserved budget")
	}

	program, _ = nativeProbeProgram(t, "http://127.0.0.1:8080")
	if _, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{server.URL + "/?token=secret"}, Limits: limits,
		RequestMeter: &nativeProbeMeter{limit: 1}, RequestBudget: 1,
	}); err == nil {
		t.Fatal("out-of-scope or query-bearing target was accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("out-of-scope request reached the test server")
	}
}

func TestAgentActionRegistryRejectsUnregisteredAdapters(t *testing.T) {
	registry := NewDefaultAgentActionRegistry()
	specs := registry.Specs()
	if len(specs) != 2 || specs[0].ID != AgentHTTPProbeID || specs[1].ID != AgentTLSProbeID {
		t.Fatalf("default agent registry is not the expected minimal catalog: %+v", specs)
	}
	if _, err := registry.Execute(context.Background(), "arbitrary-command", StageRequest{}); err == nil {
		t.Fatal("unregistered action was dispatched")
	}
}

func nativeProbeProgram(t *testing.T, serverURL string) (assessment.Program, string) {
	t.Helper()
	parsed, err := http.NewRequest(http.MethodHead, serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveTCPAddr("tcp", parsed.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(address.Port)
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeIP, Value: "127.0.0.1", Ports: []uint16{port},
	}}}
	scopeHash, err := assessment.ScopeFingerprint(scope)
	if err != nil {
		t.Fatal(err)
	}
	program := assessment.Program{
		ID: "local-probe-test", Status: assessment.ProgramActive, ExpiresAt: time.Now().Add(time.Hour),
		Scope: scope, ScopeHash: scopeHash,
	}
	target := "http://127.0.0.1:" + strconv.Itoa(int(port)) + "/health"
	return program, target
}

func TestNativeHTTPProbeAppliesTheProgramRequestProfileWithoutLoggingValues(t *testing.T) {
	received := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	program, target := nativeProbeProgram(t, server.URL)
	profile := assessment.RequestProfile{
		UserAgent: "Heimdall-Test/2.0",
		Headers: []assessment.RequestHeader{
			{Name: "x-bug-bounty", Value: "researcher-one"},
			{Name: "X-Program", Value: "example"},
		},
	}
	meter := &nativeProbeMeter{limit: 1}
	collection, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target}, Limits: StageLimits{
			RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5,
		}, RequestMeter: meter, RequestBudget: 1, RequestProfile: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := <-received
	if headers.Get("User-Agent") != "Heimdall-Test/2.0" ||
		headers.Get("X-Bug-Bounty") != "researcher-one" || headers.Get("X-Program") != "example" {
		t.Fatalf("request profile was not applied: %v", headers)
	}
	if meter.used.Load() != 1 || len(collection.Outcomes) != 1 {
		t.Fatalf("profile request accounting is unexpected: meter=%d outcomes=%+v", meter.used.Load(), collection.Outcomes)
	}
	for _, entry := range collection.Logs {
		if strings.Contains(entry.Detail, "researcher-one") || strings.Contains(entry.Detail, "example") {
			t.Fatalf("request profile value leaked into logs: %+v", entry)
		}
	}
	if !strings.Contains(collection.Logs[1].Detail, "revision=1") || !strings.Contains(collection.Logs[1].Detail, "headers=2") {
		t.Fatalf("request profile summary is missing: %+v", collection.Logs[1])
	}
}

func TestNativeHTTPProbeRejectsAnInvalidProfileBeforeTheMeter(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	program, target := nativeProbeProgram(t, server.URL)
	meter := &nativeProbeMeter{limit: 1}
	_, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
		Program: program, Stage: StageWeb, Targets: []string{target}, Limits: StageLimits{
			RateLimitPerSecond: 1000, MaxConcurrency: 1, MaxTargets: 1, TimeoutSeconds: 5,
		}, RequestMeter: meter, RequestBudget: 1,
		RequestProfile: assessment.RequestProfile{Headers: []assessment.RequestHeader{{Name: "Authorization", Value: "secret"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "managed by the request middleware") {
		t.Fatalf("invalid request profile error = %v", err)
	}
	if requests.Load() != 0 || meter.used.Load() != 0 {
		t.Fatalf("invalid profile reached the server or meter: requests=%d meter=%d", requests.Load(), meter.used.Load())
	}
}
