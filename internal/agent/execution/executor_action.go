package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

func (e Executor) executeAction(ctx context.Context, program assessment.Program, cycle store.AgentActionRun, sequence int, proposal agent.ActionProposal, grant agent.AuthorizedAction, result *Result, guard func(context.Context) error) error {
	if guard != nil {
		if err := guard(ctx); err != nil {
			return err
		}
	}
	actionID, err := e.reserveAction(ctx, cycle, sequence, grant)
	if err != nil {
		return err
	}
	meter := AgentActionRequestMeter{Ledger: e.Store, ProgramID: cycle.ProgramID, RunID: cycle.ID, ActionID: actionID, Now: e.now}
	var requestMeter recon.RequestMeter = meter
	if guard != nil {
		requestMeter = guardedRequestMeter{Base: meter, Guard: guard}
	}
	collection, runErr := e.Registry.Execute(ctx, actionToolID(grant), recon.StageRequest{
		Program: program, Stage: grant.Stage, Targets: grant.Targets, Limits: grant.Limits,
		RequestMeter: requestMeter, RequestBudget: grant.RequestBudget,
	})
	collection = recon.NormalizeAgentCollection(collection, e.now())
	return e.persistActionResult(ctx, cycle, sequence, grant, actionID, collection, runErr, result)
}

// actionToolID resolves the reviewed adapter named by the grant. The policy
// normalizes empty tool ids to the native HTTP probe, but the fallback keeps
// persisted grants written before the tool field existed executable.
func actionToolID(grant agent.AuthorizedAction) string {
	if grant.Proposal.Tool != "" {
		return grant.Proposal.Tool
	}
	return recon.AgentHTTPProbeID
}

func (e Executor) reserveAction(ctx context.Context, cycle store.AgentActionRun, sequence int, grant agent.AuthorizedAction) (string, error) {
	actionID := uuid.NewString()
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("encode authorized action grant: %w", err)
	}
	_, _, err = e.Store.ReserveAgentAction(ctx, store.ReserveAgentActionParams{
		ID: actionID, ActionRunID: cycle.ID, ProgramID: cycle.ProgramID, Sequence: sequence,
		Stage: grant.Stage, ActionClass: grant.Class, ProposalJSON: grantJSON, ScopeHash: grant.ScopeHash,
		PolicyRevision: grant.PolicyRevision, RequestBudget: grant.RequestBudget, TargetCount: len(grant.Targets),
		Limits: grant.Limits, GrantValidUntil: grant.ValidUntil,
	}, e.now())
	if err != nil {
		return "", fmt.Errorf("reserve authorized action %d: %w", sequence, err)
	}
	actionLease := time.Duration(grant.Limits.TimeoutSeconds) * time.Second
	if actionLease > 10*time.Minute {
		actionLease = 10 * time.Minute
	}
	_, err = e.Store.StartAgentAction(ctx, cycle.ProgramID, cycle.ID, actionID, actionLease, e.now())
	if err != nil {
		_ = e.Store.CancelReservedAgentAction(ctx, cycle.ProgramID, cycle.ID, actionID, e.now())
		return "", fmt.Errorf("revalidate action %d before execution: %w", sequence, err)
	}
	return actionID, nil
}

func (e Executor) persistActionResult(ctx context.Context, cycle store.AgentActionRun, sequence int, grant agent.AuthorizedAction, actionID string, collection recon.Collection, runErr error, result *Result) error {
	item := ActionResult{
		ActionID: actionID, Sequence: sequence, Stage: grant.Stage, Tool: actionToolID(grant),
		ActionClass:   grant.Class,
		RequestBudget: grant.RequestBudget, Status: "completed", ProfileVersion: collection.ProfileVersion,
		Observations: collection.Observations, Outcomes: collection.Outcomes, Logs: collection.Logs, Tools: collection.Tools,
	}
	outcome := "completed"
	if runErr != nil {
		outcome = "failed"
		item.Status = "failed"
		item.Error = runErr.Error()
	}
	persistCtx, cancelPersist := persistenceContext(ctx)
	defer cancelPersist()
	var err error
	item.RequestsUsed, err = e.readConsumedRequests(persistCtx, cycle.ProgramID, cycle.ID, actionID)
	if err != nil {
		return fmt.Errorf("read action %d request accounting: %w", sequence, err)
	}
	mergeActionResult(result, item)
	if runErr != nil {
		result.Status = "failed"
		result.Error = runErr.Error()
	}
	resultJSON, err := json.Marshal(storedActionResult{
		ProgramID: cycle.ProgramID, ActionRunID: cycle.ID, ActionID: actionID, ScopeHash: grant.ScopeHash,
		PolicyRevision: grant.PolicyRevision, Stage: grant.Stage, Tool: actionToolID(grant), CompletedAt: e.now(),
		ProfileVersion: collection.ProfileVersion, Observations: collection.Observations,
		Outcomes: collection.Outcomes, Logs: collection.Logs, Tools: collection.Tools, Error: item.Error,
		Notice: "Native one-request-per-target action result. No response body was collected; this record does not validate a vulnerability.",
	})
	if err != nil {
		return fmt.Errorf("encode action %d result: %w", sequence, err)
	}
	if err := e.Store.FinishAgentActionWithResult(persistCtx, cycle.ProgramID, cycle.ID, actionID, outcome, resultJSON, e.now()); err != nil {
		return fmt.Errorf("persist action %d result: %w", sequence, err)
	}
	if runErr != nil {
		return fmt.Errorf("native action %d failed: %w", sequence, runErr)
	}
	return nil
}

func mergeActionResult(result *Result, item ActionResult) {
	result.RequestsUsed += item.RequestsUsed
	result.Executed = result.Executed || item.RequestsUsed > 0
	result.Observations = append(result.Observations, item.Observations...)
	result.Outcomes = append(result.Outcomes, item.Outcomes...)
	result.Logs = append(result.Logs, item.Logs...)
	result.Tools = append(result.Tools, item.Tools...)
	result.ActionIDs = append(result.ActionIDs, item.ActionID)
	result.Actions = append(result.Actions, item)
}

type guardedRequestMeter struct {
	Base  recon.RequestMeter
	Guard func(context.Context) error
}

func (meter guardedRequestMeter) ConsumeRequest(ctx context.Context) error {
	if meter.Guard != nil {
		if err := meter.Guard(ctx); err != nil {
			return err
		}
	}
	return meter.Base.ConsumeRequest(ctx)
}
