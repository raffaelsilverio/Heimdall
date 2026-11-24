package execution

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
)

type adaptiveModelStub struct {
	responses []string
	requests  []providers.Request
}

func (m *adaptiveModelStub) Name() string { return "adaptive-test-model" }

func (m *adaptiveModelStub) Generate(_ context.Context, request providers.Request) (providers.Response, error) {
	m.requests = append(m.requests, request)
	if len(m.requests) > len(m.responses) {
		return providers.Response{}, errors.New("adaptive model response sequence exhausted")
	}
	return providers.Response{Content: m.responses[len(m.requests)-1]}, nil
}

func TestExecutorRunsOnlyMeteredNativeProbeAndRejectsReplay(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("request method = %q, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	if _, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 1, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	actionRunID := uuid.NewString()
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, ScopeHash: program.ScopeHash, Targets: []string{server.URL + "/health"},
		EstimatedCalls: 1, Rationale: "Single bounded HEAD probe",
	}
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	result, err := executor.ExecuteOne(context.Background(), program.ID, actionRunID, proposal, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || result.Status != "completed" || result.RequestsUsed != 1 || !result.Executed ||
		len(result.Observations) != 1 || result.Observations[0].Value != "HEAD status=204" ||
		len(result.Outcomes) != 1 || result.Outcomes[0].StatusCode != http.StatusNoContent ||
		result.Outcomes[0].Result != "http_response" ||
		result.Observations[0].ToolVersion != "native-http-v1" || result.Observations[0].ObservedAt.IsZero() ||
		len(result.Logs) < 3 {
		t.Fatalf("native action result is unexpected: requests=%d result=%+v", requests.Load(), result)
	}

	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].Status != "completed" || runs[0].RequestsConsumed != 1 {
		t.Fatalf("action ledger did not persist execution lifecycle: runs=%+v err=%v", runs, err)
	}
	reservations, err := database.ListAgentActionReservations(context.Background(), program.ID, actionRunID)
	if err != nil || len(reservations) != 1 || reservations[0].Status != "completed" || reservations[0].RequestsConsumed != 1 {
		t.Fatalf("action reservation did not persist result and request usage: actions=%+v err=%v", reservations, err)
	}
	var persisted struct {
		Notice         string               `json:"notice"`
		ProfileVersion string               `json:"profile_version"`
		Observations   []recon.Observation  `json:"observations"`
		Outcomes       []recon.AgentOutcome `json:"outcomes"`
		Logs           []recon.LogEntry     `json:"logs"`
	}
	if err := json.Unmarshal([]byte(reservations[0].ResultJSON), &persisted); err != nil ||
		len(persisted.Observations) != 1 || persisted.Notice == "" ||
		persisted.ProfileVersion != "native-http-v1" || len(persisted.Outcomes) != 1 || len(persisted.Logs) < 3 {
		t.Fatalf("persisted result is not auditable or structured: result=%s err=%v", reservations[0].ResultJSON, err)
	}
	if _, err := executor.ExecuteOne(context.Background(), program.ID, actionRunID, proposal, now.Add(3*time.Second)); err == nil {
		t.Fatal("completed action run was replayed")
	}
	if requests.Load() != 1 {
		t.Fatalf("replayed action sent another request: %d", requests.Load())
	}
}

func TestExecutorRefusesOutOfScopeBeforeCreatingAnActionRun(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	if _, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 2, MaxRequestsPerAction: 2, MaxTargetsPerAction: 2,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, ScopeHash: program.ScopeHash, Targets: []string{"http://outside.invalid/"}, EstimatedCalls: 1,
	}
	_, err = (Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry()}).ExecuteOne(
		context.Background(), program.ID, uuid.NewString(), proposal, now.Add(2*time.Second))
	if err == nil {
		t.Fatal("out-of-scope proposal unexpectedly executed")
	}
	runs, listErr := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if listErr != nil || len(runs) != 0 || requests.Load() != 0 {
		t.Fatalf("rejected proposal created ledger entries or sent traffic: runs=%+v requests=%d err=%v", runs, requests.Load(), listErr)
	}
}

func TestExecutorRunsPrevalidatedActionsSequentiallyWithinOneRunBudget(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	if _, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 2, MaxRequestsPerRun: 2, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	proposals := []agent.ActionProposal{
		{Stage: recon.StageWeb, ScopeHash: program.ScopeHash, Targets: []string{server.URL + "/one"}, EstimatedCalls: 1},
		{Stage: recon.StageWeb, ScopeHash: program.ScopeHash, Targets: []string{server.URL + "/two"}, EstimatedCalls: 1},
	}
	result, err := (Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry()}).ExecutePlan(
		context.Background(), program.ID, uuid.NewString(), proposals, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || len(result.Actions) != 2 || result.RequestsUsed != 2 || result.Status != "completed" {
		t.Fatalf("multi-action execution did not stay within one sequential cycle: requests=%d result=%+v", requests.Load(), result)
	}
	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].ActionsReserved != 2 || runs[0].RequestsReserved != 2 || runs[0].RequestsConsumed != 2 {
		t.Fatalf("multi-action budgets were not aggregated in the shared ledger: runs=%+v err=%v", runs, err)
	}
}

func TestExecutorRequiresAndConsumesScopedApproval(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	policy, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		ApprovalRequiredClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun:        1, MaxRequestsPerRun: 1, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, ScopeHash: program.ScopeHash, Targets: []string{server.URL + "/approval"},
		EstimatedCalls: 1, Rationale: "One approved probe",
	}
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	if _, err := executor.ExecuteOne(context.Background(), program.ID, uuid.NewString(), proposal, now.Add(2*time.Second)); err == nil ||
		!strings.Contains(err.Error(), "requires a scoped approval") {
		t.Fatalf("unapproved action error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("unapproved action sent a request")
	}
	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("unapproved action created a run: runs=%+v err=%v", runs, err)
	}

	subject, err := contract.NewApprovalSubject(program.ID, program.ScopeHash, policy.Revision, recon.StageWeb,
		recon.AgentHTTPProbeID, contract.ActionSafeActive, proposal.Targets, proposal.EstimatedCalls)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := database.CreateAgentApprovalRequest(context.Background(), program.ID, subject, "operator",
		now.Add(time.Hour), now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.DecideAgentApproval(context.Background(), program.ID, approval.ID, true, "reviewer",
		"exact target and budget reviewed", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err := executor.ExecuteOne(context.Background(), program.ID, uuid.NewString(), proposal, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || result.Status != "completed" || len(result.Actions) != 1 {
		t.Fatalf("approved action did not run exactly once: requests=%d result=%+v", requests.Load(), result)
	}
	consumed, err := database.GetAgentApproval(context.Background(), program.ID, approval.ID)
	if err != nil || consumed.Status != contract.ApprovalConsumed || consumed.ConsumedAt == nil {
		t.Fatalf("approval was not consumed: approval=%+v err=%v", consumed, err)
	}
	if _, err := executor.ExecuteOne(context.Background(), program.ID, uuid.NewString(), proposal, now.Add(6*time.Second)); err == nil ||
		!strings.Contains(err.Error(), "requires a scoped approval") {
		t.Fatalf("consumed approval was reused: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("consumed approval sent another request: %d", requests.Load())
	}
}

func TestAdaptiveCycleUsesOnlyBoundedResultsAndStopsAtModelDecision(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	if _, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 3, MaxRequestsPerRun: 3, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	memoryRecord, err := database.AddProgramMemory(context.Background(), store.AddProgramMemoryParams{
		ProgramID: program.ID, Kind: "fact", Title: "Current note", Content: "A local test memory note.",
		SourceKind: "operator", ScopeHash: program.ScopeHash, Confidence: 1,
	}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	model := &adaptiveModelStub{responses: []string{
		`{"actions":[{"stage":"web","scope_hash":"` + program.ScopeHash + `","targets":["` + server.URL + `/one"],"estimated_calls":1,"rationale":"Probe the first route"}]}`,
		`{"actions":[{"stage":"web","scope_hash":"` + program.ScopeHash + `","targets":["` + server.URL + `/two"],"estimated_calls":1,"rationale":"Use first result to probe a second route"}]}`,
		`{"actions":[]}`,
	}}
	result, err := (Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}).
		RunAdaptive(context.Background(), program.ID, uuid.NewString(), model, model.Name(), true, 4, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || result.Status != "completed" || result.StopReason != "planner_stopped" ||
		result.ModelCalls != 3 || result.MemoryItemsSent != 3 || len(result.Actions) != 2 || result.RequestsUsed != 2 {
		t.Fatalf("adaptive cycle exceeded or failed to use its bounds: requests=%d result=%+v", requests.Load(), result)
	}
	if len(model.requests) != 3 || !strings.Contains(model.requests[1].Messages[1].Content, "HEAD status=204") ||
		!strings.Contains(model.requests[1].Messages[1].Content, "local test memory note") ||
		!strings.Contains(model.requests[1].Messages[1].Content, server.URL+"/one") ||
		!strings.Contains(model.requests[1].Messages[1].Content, `"requests_remaining":2`) ||
		!strings.Contains(model.requests[1].Messages[1].Content, `"max_actions_this_response":1`) {
		t.Fatalf("second adaptive model call did not receive its bounded same-program feedback: %+v", model.requests)
	}
	if !strings.Contains(model.requests[2].Messages[1].Content, server.URL+"/two") ||
		!strings.Contains(model.requests[2].Messages[1].Content, `"requests_remaining":1`) {
		t.Fatalf("third adaptive model call omitted recent results or remaining budget: %+v", model.requests[2])
	}
	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].PlannerCalls != 3 || runs[0].MemoryItemsSent != 3 ||
		runs[0].ActionsReserved != 2 || runs[0].RequestsConsumed != 2 || len(runs[0].MemoryIDsSent) != 3 {
		t.Fatalf("adaptive model egress/action usage was not audited: runs=%+v err=%v", runs, err)
	}
	for _, memoryID := range runs[0].MemoryIDsSent {
		if memoryID != memoryRecord.ID {
			t.Fatalf("adaptive run audited a foreign memory ID: %v", runs[0].MemoryIDsSent)
		}
	}
}

type cancelingModel struct {
	cancel context.CancelFunc
}

func (model cancelingModel) Name() string { return "canceling-model" }

func (model cancelingModel) Generate(_ context.Context, _ providers.Request) (providers.Response, error) {
	model.cancel()
	return providers.Response{}, context.Canceled
}

func TestAdaptiveCycleClosesFailedRunOnCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	if _, err := database.SetProgramAgentPolicy(context.Background(), program.ID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 1, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result, err := (Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}).
		RunAdaptive(ctx, program.ID, uuid.NewString(), cancelingModel{cancel: cancel}, "canceling-model", false, 1, now.Add(2*time.Second))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunAdaptive error = %v, want context.Canceled", err)
	}
	if result.ActionRunID == "" || result.Status != "failed" {
		t.Fatalf("cancelled cycle result = %+v, want a failed run with an action run id", result)
	}

	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil {
		t.Fatalf("list action runs: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != result.ActionRunID || runs[0].Status != "failed" {
		t.Fatalf("cancelled action run was not persisted as failed: %+v", runs)
	}
}

func createExecutableProgram(t *testing.T, database *store.Store, now time.Time, targetURL string) assessment.Program {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, targetURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveTCPAddr("tcp", req.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeIP, Value: "127.0.0.1", Ports: []uint16{uint16(address.Port)},
	}}}
	program, err := database.CreateProgram(context.Background(), store.CreateProgramParams{
		Name: "Native HTTP executor test", AuthorizationReference: "internal:native-executor-test",
		ExpiresAt: now.Add(time.Hour), Timezone: "UTC", Scope: scope,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(context.Background(), program.ID, recon.StageWeb, "* * * * *", "UTC", true, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, now); err != nil {
		t.Fatal(err)
	}
	return program
}
