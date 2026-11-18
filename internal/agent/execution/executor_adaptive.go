package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
)

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
	now = normalizeNow(now, e.Clock)
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
		if currentProgram.Status != assessment.ProgramActive || !currentProgram.ExpiresAt.After(now) || currentContext.SourceReviewPending {
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
			if err := e.validateAutomationConsent(ctx, programID, model.Name(), modelName, includeMemory, *automationConsent, now); err != nil {
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
			memory, memoryIDs, err = e.loadCurrentMemory(ctx, programID, now)
			if err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if guard != nil {
			if err := guard(ctx); err != nil {
				return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
			}
		}
		if err := e.Store.RecordAgentActionPlannerCall(ctx, programID, cycle.ID, model.Name(), modelName, memoryIDs, now); err != nil {
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
		if generationContext.Policy.MaxTargetsPerAction > recon.AgentHTTPProbeMaxTargets {
			generationContext.Policy.MaxTargetsPerAction = recon.AgentHTTPProbeMaxTargets
		}
		proposals, err := agent.GenerateActionProposals(ctx, model, modelName, generationContext, memory, now)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, err)
		}
		if automationConsent != nil {
			if err := e.validateAutomationConsent(ctx, programID, model.Name(), modelName, includeMemory, *automationConsent, now); err != nil {
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
		grant, err := e.Policy.Authorize(ctx, currentContext, proposal, now)
		if err != nil {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, fmt.Errorf("adaptive action rejected by policy: %w", err))
		}
		if grant.RequestBudget < len(grant.Targets) || len(grant.Targets) > recon.AgentHTTPProbeMaxTargets {
			return e.closeFailedPlan(ctx, result, programID, cycle.ID, errors.New("adaptive native HTTP grant exceeds its one-request-per-target limit"))
		}
		for _, target := range grant.Targets {
			if len(target) > recon.AgentHTTPProbeMaxURLBytes {
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
	if err := e.Store.CloseAgentActionRun(ctx, programID, cycle.ID, "completed", now); err != nil {
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
