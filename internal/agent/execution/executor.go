package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/scheduler"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
)

type Executor struct {
	Store    *store.Store
	Registry recon.AgentActionRegistry
	Policy   agent.ActionPolicy
}

const (
	maxNativeHTTPActionTargets  = 8
	maxNativeHTTPActionURLBytes = 2048
)

type Result struct {
	ProgramID       string              `json:"program_id"`
	ActionRunID     string              `json:"action_run_id"`
	ActionIDs       []string            `json:"action_ids"`
	ScopeHash       string              `json:"scope_hash"`
	PolicyRevision  int64               `json:"policy_revision"`
	RequestsUsed    int                 `json:"requests_used"`
	ModelCalls      int                 `json:"model_calls,omitempty"`
	MemoryItemsSent int                 `json:"memory_items_sent,omitempty"`
	Status          string              `json:"status"`
	StopReason      string              `json:"stop_reason,omitempty"`
	Executed        bool                `json:"executed"`
	Actions         []ActionResult      `json:"actions"`
	Observations    []recon.Observation `json:"observations,omitempty"`
	Tools           []recon.ToolResult  `json:"tools,omitempty"`
	Error           string              `json:"error,omitempty"`
}

type ActionResult struct {
	ActionID      string              `json:"action_id"`
	Sequence      int                 `json:"sequence"`
	Stage         string              `json:"stage"`
	ActionClass   agent.ActionClass   `json:"action_class"`
	RequestBudget int                 `json:"request_budget"`
	RequestsUsed  int                 `json:"requests_used"`
	Status        string              `json:"status"`
	Observations  []recon.Observation `json:"observations,omitempty"`
	Tools         []recon.ToolResult  `json:"tools,omitempty"`
	Error         string              `json:"error,omitempty"`
}

type storedActionResult struct {
	ProgramID      string              `json:"program_id"`
	ActionRunID    string              `json:"action_run_id"`
	ActionID       string              `json:"action_id"`
	ScopeHash      string              `json:"scope_hash"`
	PolicyRevision int64               `json:"policy_revision"`
	Stage          string              `json:"stage"`
	CompletedAt    time.Time           `json:"completed_at"`
	Observations   []recon.Observation `json:"observations,omitempty"`
	Tools          []recon.ToolResult  `json:"tools,omitempty"`
	Error          string              `json:"error,omitempty"`
	Notice         string              `json:"notice"`
}

// ExecuteOne performs one explicitly supplied proposal through the single
// registered native HTTP adapter. No model call or subprocess is involved.
func (e Executor) ExecuteOne(ctx context.Context, programID, actionRunID string, proposal agent.ActionProposal, now time.Time) (Result, error) {
	return e.ExecutePlan(ctx, programID, actionRunID, []agent.ActionProposal{proposal}, now)
}

// ExecutePlan executes a prevalidated, ordered list of native HTTP actions
// sequentially under one durable budget. It is supervised: the caller supplies
// the complete plan, and a failed action stops the remaining sequence.
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
	if !e.hasNativeHTTPProbe() {
		return Result{}, errors.New("agent executor requires the compiled native HTTP probe adapter")
	}
	now = now.UTC()
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
		if grant == nil || grant.Stage != recon.StageWeb {
			return Result{}, fmt.Errorf("the initial executor supports only the native %q stage", recon.StageWeb)
		}
		if grant.RequestBudget < len(grant.Targets) {
			return Result{}, errors.New("request budget must cover one native HEAD request per authorized target")
		}
		if len(grant.Targets) > maxNativeHTTPActionTargets {
			return Result{}, fmt.Errorf("native HTTP executor is limited to %d targets per action", maxNativeHTTPActionTargets)
		}
		for _, target := range grant.Targets {
			if len(target) > maxNativeHTTPActionURLBytes {
				return Result{}, fmt.Errorf("native HTTP target exceeds %d bytes", maxNativeHTTPActionURLBytes)
			}
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
		grant, err := e.Policy.Authorize(ctx, currentContext, proposal, time.Now().UTC())
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if grant.Stage != recon.StageWeb || grant.RequestBudget < len(grant.Targets) {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("native action grant no longer satisfies the one-request-per-target contract"))
		}
		if err := e.executeAction(ctx, currentProgram, cycle, index+1, proposal, grant, &result, nil); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
	}
	if err := e.Store.CloseAgentActionRun(ctx, programID, cycle.ID, "completed", time.Now().UTC()); err != nil {
		return result, fmt.Errorf("close completed action run: %w", err)
	}
	return result, nil
}

// RunAdaptive asks the model for one next action at a time and executes only
// the registered native HTTP probe. Both planner context egress and active
// requests are caller-confirmed in the CLI; the loop is bounded by policy and
// maxSteps and is not attached to the daemon.
func (e Executor) RunAdaptive(ctx context.Context, programID, actionRunID string, model providers.Provider, modelName string, includeMemory bool, maxSteps int, now time.Time) (Result, error) {
	return e.runAdaptive(ctx, programID, actionRunID, model, modelName, includeMemory, maxSteps, 0, nil, nil, nil, now)
}

func (e Executor) RunAdaptiveWithAutomationConsent(ctx context.Context, programID, actionRunID string, model providers.Provider, modelName string, maxSteps, requestBudget int, seedResults []agent.PlanActionObservation, consent store.ProgramAgentAutomation, now time.Time) (Result, error) {
	return e.RunAdaptiveWithAutomationGuard(ctx, programID, actionRunID, model, modelName, maxSteps, requestBudget, seedResults, consent, nil, now)
}

func (e Executor) RunAdaptiveWithAutomationGuard(ctx context.Context, programID, actionRunID string, model providers.Provider, modelName string, maxSteps, requestBudget int, seedResults []agent.PlanActionObservation, consent store.ProgramAgentAutomation, guard func(context.Context) error, now time.Time) (Result, error) {
	return e.runAdaptive(ctx, programID, actionRunID, model, modelName, consent.IncludeMemory, maxSteps, requestBudget, seedResults, &consent, guard, now)
}

func (e Executor) runAdaptive(ctx context.Context, programID, actionRunID string, model providers.Provider, modelName string, includeMemory bool, maxSteps, automationRequestBudget int, seedResults []agent.PlanActionObservation, automationConsent *store.ProgramAgentAutomation, guard func(context.Context) error, now time.Time) (Result, error) {
	if e.Store == nil || model == nil {
		return Result{}, errors.New("adaptive execution requires a store and a configured model")
	}
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return Result{}, errors.New("one explicit program id is required")
	}
	if _, err := uuid.Parse(strings.TrimSpace(actionRunID)); err != nil {
		return Result{}, errors.New("action run id must be a UUID and is required for replay protection")
	}
	if maxSteps < 1 || maxSteps > 20 {
		return Result{}, errors.New("adaptive execution step limit must be between 1 and 20")
	}
	if e.Policy == nil {
		e.Policy = agent.ScopeActionPolicy{}
	}
	if len(e.Registry.Adapters) == 0 {
		e.Registry = recon.NewDefaultAgentActionRegistry()
	}
	if !e.hasNativeHTTPProbe() {
		return Result{}, errors.New("adaptive executor requires the compiled native HTTP probe adapter")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if automationConsent != nil {
		if automationRequestBudget < 1 || automationRequestBudget > automationConsent.MaxRequestsPerDay {
			return Result{}, errors.New("automated cycle request budget does not fit the persisted daily consent cap")
		}
		if err := e.validateAutomationConsent(ctx, programID, model.Name(), modelName, includeMemory, *automationConsent, now); err != nil {
			return Result{}, err
		}
	}
	_, initialContext, err := e.loadPolicyContext(ctx, programID)
	if err != nil {
		return Result{}, err
	}
	if !containsAllowedStage(initialContext.Policy.AllowedStages, recon.StageWeb) ||
		!containsAllowedClass(initialContext.Policy.AllowedClasses, agent.ActionSafeActive) {
		return Result{}, errors.New("adaptive native executor requires an explicit web/safe_active policy")
	}
	if _, enabled := initialContext.EnabledSchedules[recon.StageWeb]; !enabled {
		return Result{}, errors.New("adaptive native executor requires an enabled web schedule")
	}
	var cycle store.AgentActionRun
	if automationConsent == nil {
		cycle, err = e.Store.CreateAgentActionRun(ctx, actionRunID, programID, now)
	} else {
		cycle, err = e.Store.CreateAgentActionRunForAutomation(ctx, actionRunID, programID, automationConsent.Revision, automationRequestBudget, now)
	}
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
		PolicyRevision: cycle.PolicyRevision, Status: "completed", Actions: make([]ActionResult, 0),
	}
	seenTargets := make(map[string]struct{})
	history := append([]agent.PlanActionObservation(nil), seedResults...)
	for step := 0; step < maxSteps; step++ {
		if err := ctx.Err(); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		currentProgram, currentContext, err := e.loadPolicyContext(ctx, programID)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		currentRun, err := e.Store.GetAgentActionRun(ctx, programID, cycle.ID)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if currentRun.PolicyRevision != currentContext.Policy.Revision || currentRun.ScopeHash != currentProgram.ScopeHash ||
			!containsAllowedStage(currentContext.Policy.AllowedStages, recon.StageWeb) ||
			!containsAllowedClass(currentContext.Policy.AllowedClasses, agent.ActionSafeActive) {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive action run policy or scope changed"))
		}
		if currentRun.Status != "active" {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, fmt.Errorf("action run is %s", currentRun.Status))
		}
		if currentProgram.Status != assessment.ProgramActive || !currentProgram.ExpiresAt.After(time.Now().UTC()) || currentContext.SourceReviewPending {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive planner context is paused, expired, or under source review"))
		}
		fingerprint, fingerprintErr := assessment.ScopeFingerprint(currentProgram.Scope)
		if fingerprintErr != nil || fingerprint != currentProgram.ScopeHash {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive planner scope is invalid or stale"))
		}
		if currentRun.ActionsReserved >= currentRun.MaxActions || currentRun.RequestsReserved >= currentRun.MaxRequests {
			result.StopReason = "budget_exhausted"
			break
		}
		if automationConsent != nil {
			if err := e.validateAutomationConsent(ctx, programID, model.Name(), modelName, includeMemory, *automationConsent, time.Now().UTC()); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		currentContext.ActionsUsed = currentRun.ActionsReserved
		currentContext.RequestsUsed = currentRun.RequestsReserved
		if automationConsent != nil {
			if currentContext.Policy.MaxRequestsPerRun > cycle.MaxRequests {
				currentContext.Policy.MaxRequestsPerRun = cycle.MaxRequests
			}
			if currentContext.Policy.MaxRequestsPerAction > currentContext.Policy.MaxRequestsPerRun {
				currentContext.Policy.MaxRequestsPerAction = currentContext.Policy.MaxRequestsPerRun
			}
		}
		currentContext.MaxProposals = 1
		currentContext.RecentResults = append([]agent.PlanActionObservation(nil), history...)
		currentContext.Policy.AllowedStages = []string{recon.StageWeb}
		currentContext.Policy.AllowedClasses = []agent.ActionClass{agent.ActionSafeActive}
		limits, scheduleEnabled := currentContext.EnabledSchedules[recon.StageWeb]
		if !scheduleEnabled || limits.Validate() != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive native web schedule is disabled or invalid"))
		}
		currentContext.EnabledSchedules = map[string]recon.StageLimits{recon.StageWeb: limits}
		memory := []agent.PlanMemoryItem(nil)
		var memoryIDs []string
		if includeMemory {
			memory, memoryIDs, err = e.loadCurrentMemory(ctx, programID, time.Now().UTC())
			if err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if guard != nil {
			if err := guard(ctx); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if err := e.Store.RecordAgentActionPlannerCall(ctx, programID, cycle.ID, model.Name(), modelName, memoryIDs, time.Now().UTC()); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		result.ModelCalls++
		result.MemoryItemsSent += len(memory)
		if guard != nil {
			if err := guard(ctx); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		generationContext := currentContext
		if generationContext.Policy.MaxTargetsPerAction > maxNativeHTTPActionTargets {
			generationContext.Policy.MaxTargetsPerAction = maxNativeHTTPActionTargets
		}
		proposals, err := agent.GenerateActionProposals(ctx, model, modelName, generationContext, memory, time.Now().UTC())
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if automationConsent != nil {
			if err := e.validateAutomationConsent(ctx, programID, model.Name(), modelName, includeMemory, *automationConsent, time.Now().UTC()); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if guard != nil {
			if err := guard(ctx); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if len(proposals) == 0 {
			result.StopReason = "planner_stopped"
			break
		}
		if len(proposals) != 1 {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive planner must return zero or one action per step"))
		}
		proposal := proposals[0]
		grant, err := e.Policy.Authorize(ctx, currentContext, proposal, time.Now().UTC())
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, fmt.Errorf("adaptive action rejected by policy: %w", err))
		}
		if grant.RequestBudget < len(grant.Targets) || len(grant.Targets) > maxNativeHTTPActionTargets {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive native HTTP grant exceeds its one-request-per-target limit"))
		}
		for _, target := range grant.Targets {
			if len(target) > maxNativeHTTPActionURLBytes {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive native HTTP target exceeds the executor URL limit"))
			}
		}
		duplicate := false
		for _, target := range grant.Targets {
			key := strings.ToLower(target)
			if _, exists := seenTargets[key]; exists {
				duplicate = true
				break
			}
		}
		if duplicate {
			result.StopReason = "no_new_targets"
			break
		}
		if err := e.executeAction(ctx, currentProgram, cycle, currentRun.ActionsReserved+1, proposal, grant, &result, guard); err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		for _, target := range grant.Targets {
			seenTargets[strings.ToLower(target)] = struct{}{}
		}
		for _, observation := range result.Actions[len(result.Actions)-1].Observations {
			if observation.Category != recon.CategoryHTTPProbe {
				continue
			}
			history = append(history, agent.PlanActionObservation{
				Stage: recon.StageWeb, Target: observation.StableKey, Outcome: observation.Value,
			})
		}
		if len(history) > 8 {
			history = append([]agent.PlanActionObservation(nil), history[len(history)-8:]...)
		}
	}
	if result.StopReason == "" {
		result.StopReason = "max_steps_reached"
	}
	if err := e.Store.CloseAgentActionRun(ctx, programID, cycle.ID, "completed", time.Now().UTC()); err != nil {
		return result, fmt.Errorf("close adaptive action run: %w", err)
	}
	return result, nil
}

func (e Executor) validateAutomationConsent(ctx context.Context, programID, provider, model string, includeMemory bool, expected store.ProgramAgentAutomation, now time.Time) error {
	current, err := e.Store.GetProgramAgentAutomation(ctx, programID)
	if err != nil {
		return err
	}
	if !current.Enabled || current.Revision != expected.Revision || !current.AllowModelContextEgress ||
		!current.AllowActiveRequests || current.PlannerProvider != provider || current.PlannerModel != model ||
		current.IncludeMemory != includeMemory || current.ContextEgressExpiresAt == nil ||
		!current.ContextEgressExpiresAt.After(now.UTC()) {
		return errors.New("persistent adaptive-cycle consent is disabled, expired, or changed")
	}
	return nil
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

func (e Executor) loadCurrentMemory(ctx context.Context, programID string, now time.Time) ([]agent.PlanMemoryItem, []string, error) {
	memories, err := e.Store.ListProgramMemories(ctx, programID, 100, now)
	if err != nil {
		return nil, nil, fmt.Errorf("load same-program adaptive memory: %w", err)
	}
	items := make([]agent.PlanMemoryItem, 0, 8)
	ids := make([]string, 0, 8)
	totalBytes := 0
	for _, memory := range memories {
		if len(items) >= 8 {
			break
		}
		if memory.ProgramID != programID || memory.Status != "active" || memory.ScopeStale || memory.SourceStale || memory.SourceReviewPending {
			continue
		}
		item := agent.PlanMemoryItem{
			Kind:       strings.TrimSpace(memory.Kind),
			Title:      truncatePlanText(strings.TrimSpace(memory.Title), 200),
			Content:    truncatePlanText(strings.TrimSpace(memory.Content), 1500),
			SourceKind: strings.TrimSpace(memory.SourceKind), Confidence: memory.Confidence,
		}
		itemBytes := len(item.Kind) + len(item.Title) + len(item.Content) + len(item.SourceKind)
		if item.Kind == "" || item.Title == "" || item.Content == "" {
			continue
		}
		if totalBytes+itemBytes > 8<<10 {
			break
		}
		items = append(items, item)
		ids = append(ids, memory.ID)
		totalBytes += itemBytes
	}
	return items, ids, nil
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

func (e Executor) executeAction(ctx context.Context, program assessment.Program, cycle store.AgentActionRun, sequence int, proposal agent.ActionProposal, grant agent.AuthorizedAction, result *Result, guard func(context.Context) error) error {
	if guard != nil {
		if err := guard(ctx); err != nil {
			return err
		}
	}
	actionID := uuid.NewString()
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("encode authorized action grant: %w", err)
	}
	_, _, err = e.Store.ReserveAgentAction(ctx, store.ReserveAgentActionParams{
		ID: actionID, ActionRunID: cycle.ID, ProgramID: cycle.ProgramID, Sequence: sequence,
		Stage: grant.Stage, ActionClass: grant.Class, ProposalJSON: grantJSON, ScopeHash: grant.ScopeHash,
		PolicyRevision: grant.PolicyRevision, RequestBudget: grant.RequestBudget, TargetCount: len(grant.Targets),
		Limits: grant.Limits, GrantValidUntil: grant.ValidUntil,
	}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("reserve authorized action %d: %w", sequence, err)
	}
	actionLease := time.Duration(grant.Limits.TimeoutSeconds) * time.Second
	if actionLease > 10*time.Minute {
		actionLease = 10 * time.Minute
	}
	_, err = e.Store.StartAgentAction(ctx, cycle.ProgramID, cycle.ID, actionID, actionLease, time.Now().UTC())
	if err != nil {
		_ = e.Store.CancelReservedAgentAction(ctx, cycle.ProgramID, cycle.ID, actionID, time.Now().UTC())
		return fmt.Errorf("revalidate action %d before execution: %w", sequence, err)
	}
	meter := scheduler.AgentActionRequestMeter{Ledger: e.Store, ProgramID: cycle.ProgramID, RunID: cycle.ID, ActionID: actionID}
	var requestMeter recon.RequestMeter = meter
	if guard != nil {
		requestMeter = guardedRequestMeter{Base: meter, Guard: guard}
	}
	collection, runErr := e.Registry.Execute(ctx, recon.AgentHTTPProbeID, recon.StageRequest{
		Program: program, Stage: grant.Stage, Targets: grant.Targets, Limits: grant.Limits,
		RequestMeter: requestMeter, RequestBudget: grant.RequestBudget,
	})
	item := ActionResult{
		ActionID: actionID, Sequence: sequence, Stage: grant.Stage, ActionClass: grant.Class,
		RequestBudget: grant.RequestBudget, Status: "completed", Observations: collection.Observations, Tools: collection.Tools,
	}
	outcome := "completed"
	if runErr != nil {
		outcome = "failed"
		item.Status = "failed"
		item.Error = runErr.Error()
	}
	persistCtx, cancelPersist := persistenceContext(ctx)
	defer cancelPersist()
	item.RequestsUsed, err = e.readConsumedRequests(persistCtx, cycle.ProgramID, cycle.ID, actionID)
	if err != nil {
		return fmt.Errorf("read action %d request accounting: %w", sequence, err)
	}
	result.RequestsUsed += item.RequestsUsed
	result.Executed = result.Executed || item.RequestsUsed > 0
	result.Observations = append(result.Observations, item.Observations...)
	result.Tools = append(result.Tools, item.Tools...)
	result.ActionIDs = append(result.ActionIDs, item.ActionID)
	result.Actions = append(result.Actions, item)
	if runErr != nil {
		result.Status = "failed"
		result.Error = runErr.Error()
	}
	resultJSON, err := json.Marshal(storedActionResult{
		ProgramID: cycle.ProgramID, ActionRunID: cycle.ID, ActionID: actionID, ScopeHash: grant.ScopeHash,
		PolicyRevision: grant.PolicyRevision, Stage: grant.Stage, CompletedAt: time.Now().UTC(),
		Observations: collection.Observations, Tools: collection.Tools, Error: item.Error,
		Notice: "Native one-request-per-target action result. No response body was collected; this record does not validate a vulnerability.",
	})
	if err != nil {
		return fmt.Errorf("encode action %d result: %w", sequence, err)
	}
	if err := e.Store.FinishAgentActionWithResult(persistCtx, cycle.ProgramID, cycle.ID, actionID, outcome, resultJSON, time.Now().UTC()); err != nil {
		return fmt.Errorf("persist action %d result: %w", sequence, err)
	}
	if runErr != nil {
		return fmt.Errorf("native HTTP action %d failed: %w", sequence, runErr)
	}
	return nil
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

func (e Executor) closeFailedPlan(ctx context.Context, result Result, programID, runID string, cause error) (Result, error) {
	result.Status = "failed"
	result.Error = cause.Error()
	persistCtx, cancel := persistenceContext(ctx)
	defer cancel()
	if err := e.Store.CloseAgentActionRun(persistCtx, programID, runID, "failed", time.Now().UTC()); err != nil {
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
