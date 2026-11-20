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
