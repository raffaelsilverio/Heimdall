package execution

import (
	"context"
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
)

func setSingleActionWebPolicy(t *testing.T, database *store.Store, programID string, now time.Time) {
	t.Helper()
	if _, err := database.SetProgramAgentPolicy(context.Background(), programID, contract.ProgramAgentPolicy{
		AllowedStages: []string{recon.StageWeb}, AllowedClasses: []contract.ActionClass{contract.ActionSafeActive},
		MaxActionsPerRun: 1, MaxRequestsPerRun: 1, MaxRequestsPerAction: 1, MaxTargetsPerAction: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorDispatchesTheProposedNativeTLSTool(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	setSingleActionWebPolicy(t, database, program.ID, now.Add(time.Second))
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, Tool: recon.AgentTLSProbeID, ScopeHash: program.ScopeHash,
		Targets: []string{server.URL + "/health"}, EstimatedCalls: 1, Rationale: "TLS handshake probe",
	}
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	result, err := executor.ExecuteOne(context.Background(), program.ID, uuid.NewString(), proposal, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if connections.Load() == 0 {
		t.Fatal("TLS dispatch did not open a connection to the test server")
	}
	if result.Status != "completed" || result.RequestsUsed != 1 || !result.Executed || len(result.Actions) != 1 {
		t.Fatalf("unexpected TLS action result: %+v", result)
	}
	action := result.Actions[0]
	if action.Tool != recon.AgentTLSProbeID || action.ProfileVersion != "native-tls-v1" {
		t.Fatalf("executor did not dispatch the proposed TLS tool: %+v", action)
	}
	if len(result.Observations) != 1 || result.Observations[0].Category != recon.CategoryTLSProbe {
		t.Fatalf("TLS observation was not recorded: %+v", result.Observations)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Method != "TLS" {
		t.Fatalf("TLS outcome was not recorded: %+v", result.Outcomes)
	}
}

func TestExecutorRejectsUnknownToolBeforeCreatingAnActionRun(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()

	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	setSingleActionWebPolicy(t, database, program.ID, now.Add(time.Second))
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, Tool: "unregistered_probe", ScopeHash: program.ScopeHash,
		Targets: []string{server.URL + "/health"}, EstimatedCalls: 1,
	}
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	actionRunID := uuid.NewString()
	_, err = executor.ExecuteOne(context.Background(), program.ID, actionRunID, proposal, now.Add(2*time.Second))
	if err == nil || !strings.Contains(err.Error(), "not in the compiled registry") {
		t.Fatalf("ExecuteOne error = %v, want an unregistered-tool rejection", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("unregistered tool reached the test server %d times", requests.Load())
	}
	runs, err := database.ListAgentActionRuns(context.Background(), program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("unregistered tool created an action run: %+v", runs)
	}
	if _, err := database.GetAgentActionRun(context.Background(), program.ID, actionRunID); err == nil {
		t.Fatal("unregistered tool persisted an action run")
	}
}

func createMixedProbeProgram(t *testing.T, database *store.Store, now time.Time, ports ...uint16) assessment.Program {
	t.Helper()
	scope := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeIP, Value: "127.0.0.1", Ports: ports,
	}}}
	program, err := database.CreateProgram(context.Background(), store.CreateProgramParams{
		Name: "Mixed native probe executor test", AuthorizationReference: "internal:mixed-probe-test",
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

func TestExecutorRunsMixedHTTPAndTLSPlanUnderOneBudget(t *testing.T) {
	var httpRequests atomic.Int64
	httpServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		httpRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer httpServer.Close()
	var tlsConnections atomic.Int64
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			tlsConnections.Add(1)
		}
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	httpPort := uint16(httpServer.Listener.Addr().(*net.TCPAddr).Port)
	tlsPort := uint16(tlsServer.Listener.Addr().(*net.TCPAddr).Port)
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	program := createMixedProbeProgram(t, database, now, httpPort, tlsPort)
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
		{
			Stage: recon.StageWeb, ScopeHash: program.ScopeHash,
			Targets: []string{httpServer.URL + "/health"}, EstimatedCalls: 1, Rationale: "HTTP probe",
		},
		{
			Stage: recon.StageWeb, Tool: recon.AgentTLSProbeID, ScopeHash: program.ScopeHash,
			Targets: []string{tlsServer.URL + "/health"}, EstimatedCalls: 1, Rationale: "TLS probe",
		},
	}
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	result, err := executor.ExecutePlan(context.Background(), program.ID, uuid.NewString(), proposals, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if httpRequests.Load() != 1 || tlsConnections.Load() == 0 {
		t.Fatalf("mixed plan did not reach both probes: http=%d tls=%d", httpRequests.Load(), tlsConnections.Load())
	}
	if result.Status != "completed" || result.RequestsUsed != 2 || len(result.Actions) != 2 {
		t.Fatalf("mixed plan accounting is unexpected: %+v", result)
	}
	if result.Actions[0].Tool != recon.AgentHTTPProbeID || result.Actions[1].Tool != recon.AgentTLSProbeID {
		t.Fatalf("mixed plan tools are unexpected: %+v", result.Actions)
	}
	for _, action := range result.Actions {
		if action.RequestsUsed != 1 || action.Status != "completed" {
			t.Fatalf("mixed plan action accounting is unexpected: %+v", action)
		}
	}
	categories := map[string]bool{}
	for _, observation := range result.Observations {
		categories[observation.Category] = true
	}
	if !categories[recon.CategoryHTTPProbe] || !categories[recon.CategoryTLSProbe] {
		t.Fatalf("mixed plan observations are incomplete: %+v", result.Observations)
	}
}

func TestExecutorAppliesTheProgramRequestProfileAndPersistsItsRevision(t *testing.T) {
	received := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	program := createExecutableProgram(t, database, now, server.URL)
	setSingleActionWebPolicy(t, database, program.ID, now.Add(time.Second))
	program, err = database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.SetProgramRequestProfile(context.Background(), program.ID, assessment.RequestProfile{
		UserAgent: "Heimdall-Executor/2.0",
		Headers: []assessment.RequestHeader{
			{Name: "X-Bug-Bounty", Value: "researcher-one"},
			{Name: "X-Program", Value: "example"},
		},
	}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	proposal := agent.ActionProposal{
		Stage: recon.StageWeb, ScopeHash: program.ScopeHash,
		Targets: []string{server.URL + "/health"}, EstimatedCalls: 1,
	}
	actionRunID := uuid.NewString()
	executor := Executor{Store: database, Registry: recon.NewDefaultAgentActionRegistry(), Policy: agent.ScopeActionPolicy{}}
	result, err := executor.ExecuteOne(context.Background(), program.ID, actionRunID, proposal, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	headers := <-received
	if headers.Get("User-Agent") != "Heimdall-Executor/2.0" ||
		headers.Get("X-Bug-Bounty") != "researcher-one" || headers.Get("X-Program") != "example" {
		t.Fatalf("executor did not apply the request profile: %v", headers)
	}
	if result.Actions[0].RequestProfileRevision != 2 {
		t.Fatalf("action result omitted the request profile revision: %+v", result.Actions[0])
	}
	reservations, err := database.ListAgentActionReservations(context.Background(), program.ID, actionRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reservations) != 1 || !strings.Contains(reservations[0].ResultJSON, `"request_profile_revision":2`) {
		t.Fatalf("stored action result omitted the request profile revision: %+v", reservations)
	}
}
