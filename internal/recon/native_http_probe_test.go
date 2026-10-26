package recon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	collection, err := (NativeHTTPProbe{Transport: server.Client().Transport}).Execute(context.Background(), StageRequest{
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
	if len(registry.Specs()) != 1 || registry.Specs()[0].ID != AgentHTTPProbeID {
		t.Fatalf("default agent registry is not the expected minimal catalog: %+v", registry.Specs())
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
