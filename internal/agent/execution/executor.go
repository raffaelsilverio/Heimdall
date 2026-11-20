package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/clock"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

type Executor struct {
	Store    *store.Store
	Registry recon.AgentActionRegistry
	Policy   agent.ActionPolicy
	Clock    clock.Clock
}

type Result struct {
	ProgramID       string               `json:"program_id"`
	ActionRunID     string               `json:"action_run_id"`
	ActionIDs       []string             `json:"action_ids"`
	ScopeHash       string               `json:"scope_hash"`
	PolicyRevision  int64                `json:"policy_revision"`
	RequestsUsed    int                  `json:"requests_used"`
	ModelCalls      int                  `json:"model_calls,omitempty"`
	MemoryItemsSent int                  `json:"memory_items_sent,omitempty"`
	Status          string               `json:"status"`
	StopReason      string               `json:"stop_reason,omitempty"`
	Executed        bool                 `json:"executed"`
	Actions         []ActionResult       `json:"actions"`
	Observations    []recon.Observation  `json:"observations,omitempty"`
	Outcomes        []recon.AgentOutcome `json:"outcomes,omitempty"`
	Logs            []recon.LogEntry     `json:"logs,omitempty"`
	Tools           []recon.ToolResult   `json:"tools,omitempty"`
	Error           string               `json:"error,omitempty"`
}

type ActionResult struct {
	ActionID               string               `json:"action_id"`
	Sequence               int                  `json:"sequence"`
	Stage                  string               `json:"stage"`
	Tool                   string               `json:"tool,omitempty"`
	ActionClass            agent.ActionClass    `json:"action_class"`
	RequestBudget          int                  `json:"request_budget"`
	RequestsUsed           int                  `json:"requests_used"`
	RequestProfileRevision int64                `json:"request_profile_revision,omitempty"`
	Status                 string               `json:"status"`
	ProfileVersion         string               `json:"profile_version,omitempty"`
	Observations           []recon.Observation  `json:"observations,omitempty"`
	Outcomes               []recon.AgentOutcome `json:"outcomes,omitempty"`
	Logs                   []recon.LogEntry     `json:"logs,omitempty"`
	Tools                  []recon.ToolResult   `json:"tools,omitempty"`
	Error                  string               `json:"error,omitempty"`
}

type storedActionResult struct {
	ProgramID              string               `json:"program_id"`
	ActionRunID            string               `json:"action_run_id"`
	ActionID               string               `json:"action_id"`
	ScopeHash              string               `json:"scope_hash"`
	PolicyRevision         int64                `json:"policy_revision"`
	RequestProfileRevision int64                `json:"request_profile_revision,omitempty"`
	Stage                  string               `json:"stage"`
	Tool                   string               `json:"tool"`
	CompletedAt            time.Time            `json:"completed_at"`
	ProfileVersion         string               `json:"profile_version,omitempty"`
	Observations           []recon.Observation  `json:"observations,omitempty"`
	Outcomes               []recon.AgentOutcome `json:"outcomes,omitempty"`
	Logs                   []recon.LogEntry     `json:"logs,omitempty"`
	Tools                  []recon.ToolResult   `json:"tools,omitempty"`
	Error                  string               `json:"error,omitempty"`
	Notice                 string               `json:"notice"`
}

// ExecuteOne performs one explicitly supplied proposal through the reviewed
// native adapter named by the proposal (the HTTP probe when the tool is
// omitted). No model call or subprocess is involved.
func (e Executor) ExecuteOne(ctx context.Context, programID, actionRunID string, proposal agent.ActionProposal, now time.Time) (Result, error) {
	return e.ExecutePlan(ctx, programID, actionRunID, []agent.ActionProposal{proposal}, now)
}

// ExecutePlan executes a prevalidated, ordered list of reviewed native actions
// sequentially under one durable budget. Each action is dispatched to the
// registry entry named by its tool. It is supervised: the caller supplies the
// complete plan, and a failed action stops the remaining sequence.
func (e Executor) ExecutePlan(ctx context.Context, programID, actionRunID string, proposals []agent.ActionProposal, now time.Time) (Result, error) {
	if e.Store == nil {
		return Result{}, errors.New("agent action executor requires a store")
	}
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return Result{}, errors.New("one explicit program id is required")
	}
	if _, err := uuid.Parse(strings.TrimSpace(actionRunID)); err != nil {
		return Result{}, errors.New("action run id must be a UUID and is required for replay protection")
	}
	if len(proposals) == 0 || len(proposals) > 20 {
		return Result{}, errors.New("native executor requires a plan containing between 1 and 20 actions")
	}
	if e.Policy == nil {
		e.Policy = agent.ScopeActionPolicy{}
	}
	if len(e.Registry.Adapters) == 0 {
		e.Registry = recon.NewDefaultAgentActionRegistry()
	}
	now = normalizeNow(now, e.Clock)
	_, policyContext, err := e.loadPolicyContext(ctx, programID)
	if err != nil {
		return Result{}, err
	}
	plan, err := (agent.PolicyAwarePlanner{Policy: e.Policy}).Validate(ctx, policyContext, proposals, now)
	if err != nil {
		return Result{}, err
	}
	if !plan.PolicyChecksPassed || len(plan.Decisions) != len(proposals) {
		if len(plan.Decisions) > 0 {
			for _, decision := range plan.Decisions {
				if !decision.PolicyPassed {
					return Result{}, fmt.Errorf("agent action plan rejected by policy: %s", decision.Reason)
				}
			}
		}
		if !plan.PolicyChecksPassed || len(plan.Decisions) != len(proposals) {
			return Result{}, errors.New("agent action plan was not accepted by policy")
		}
	}
	for _, decision := range plan.Decisions {
		grant := decision.AuthorizedCandidate
		if grant == nil {
			return Result{}, errors.New("agent action plan contains no authorized candidate")
		}
		if _, err := e.validateActionGrant(*grant); err != nil {
			return Result{}, err
		}
	}

	cycle, err := e.Store.CreateAgentActionRun(ctx, actionRunID, programID, now)
	if err != nil {
		return Result{}, err
	}
	if cycle.Status != "active" {
		return Result{}, fmt.Errorf("action run %s is %s and cannot execute", cycle.ID, cycle.Status)
	}
	if cycle.ActionsReserved != 0 || cycle.RequestsReserved != 0 || cycle.RequestsConsumed != 0 || cycle.PlannerCalls != 0 {
		return Result{}, errors.New("action run already contains reservations or planner calls and cannot be replayed or resumed")
	}
	result := Result{
		ProgramID: programID, ActionRunID: cycle.ID, ScopeHash: cycle.ScopeHash,
		PolicyRevision: cycle.PolicyRevision, Status: "completed", Actions: make([]ActionResult, 0, len(proposals)),
	}
	for index, proposal := range proposals {
		currentProgram, currentContext, err := e.loadPolicyContext(ctx, programID)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		currentRun, err := e.Store.GetAgentActionRun(ctx, programID, cycle.ID)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if currentRun.ActionsReserved != index {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("action run reservation sequence is inconsistent"))
		}
		currentContext.ActionsUsed = currentRun.ActionsReserved
		currentContext.RequestsUsed = currentRun.RequestsReserved
		grant, err := e.Policy.Authorize(ctx, currentContext, proposal, now)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if _, err := e.validateActionGrant(grant); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if err := e.executeAction(ctx, currentProgram, cycle, index+1, proposal, grant, &result, nil); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
	}
	if err := e.Store.CloseAgentActionRun(ctx, programID, cycle.ID, "completed", now); err != nil {
		return result, fmt.Errorf("close completed action run: %w", err)
	}
	return result, nil
}

func (e Executor) loadPolicyContext(ctx context.Context, programID string) (assessment.Program, agent.ActionPolicyContext, error) {
	program, err := e.Store.GetProgram(ctx, programID)
	if err != nil {
		return assessment.Program{}, agent.ActionPolicyContext{}, err
	}
	policy, err := e.Store.GetProgramAgentPolicy(ctx, programID)
	if err != nil {
		return assessment.Program{}, agent.ActionPolicyContext{}, err
	}
	pendingReview, err := e.Store.HasPendingProgramSourceReview(ctx, programID)
	if err != nil {
		return assessment.Program{}, agent.ActionPolicyContext{}, err
	}
	schedules, err := e.Store.ListStageSchedules(ctx, programID)
	if err != nil {
		return assessment.Program{}, agent.ActionPolicyContext{}, err
	}
	enabledSchedules := make(map[string]recon.StageLimits)
	for _, schedule := range schedules {
		if schedule.Enabled {
			enabledSchedules[schedule.Stage] = schedule.Limits
		}
	}
	return program, agent.ActionPolicyContext{
		Program: program, SourceReviewPending: pendingReview, EnabledSchedules: enabledSchedules, Policy: policy,
	}, nil
}

func truncatePlanText(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maximum {
		return value
	}
	const suffix = "…"
	maximum -= len(suffix)
	for maximum > 0 && !utf8.RuneStart(value[maximum]) {
		maximum--
	}
	return value[:maximum] + suffix
}

func containsAllowedStage(stages []string, stage string) bool {
	for _, candidate := range stages {
		if strings.EqualFold(strings.TrimSpace(candidate), stage) {
			return true
		}
	}
	return false
}

func containsAllowedClass(classes []agent.ActionClass, class agent.ActionClass) bool {
	for _, candidate := range classes {
		if candidate == class {
			return true
		}
	}
	return false
}

func (e Executor) closeFailedPlan(ctx context.Context, result Result, programID, runID string, cause error) (Result, error) {
	now := e.now()
	result.Status = "failed"
	result.Error = cause.Error()
	persistCtx, cancel := persistenceContext(ctx)
	defer cancel()
	if err := e.Store.CloseAgentActionRun(persistCtx, programID, runID, "failed", now); err != nil {
		return result, errors.Join(cause, fmt.Errorf("close failed action run: %w", err))
	}
	return result, cause
}

func (e Executor) hasNativeHTTPProbe() bool {
	for _, spec := range e.Registry.Specs() {
		if spec.ID == recon.AgentHTTPProbeID && spec.Stage == recon.StageWeb {
			return true
		}
	}
	return false
}

func (e Executor) validateActionGrant(grant agent.AuthorizedAction) (recon.AgentToolSpec, error) {
	return ValidateGrant(e.Registry, grant)
}

func (e Executor) readConsumedRequests(ctx context.Context, programID, runID, actionID string) (int, error) {
	reservations, err := e.Store.ListAgentActionReservations(ctx, programID, runID)
	if err != nil {
		return 0, err
	}
	for _, reservation := range reservations {
		if reservation.ID == actionID {
			return reservation.RequestsConsumed, nil
		}
	}
	return 0, fmt.Errorf("action reservation %q not found", actionID)
}

func persistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}
