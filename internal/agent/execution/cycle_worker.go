package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/clock"
	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/raffaelsilverio/Heimdall/providers"
)

type AgentCycleWorker struct {
	Store         *store.Store
	Home          string
	BatchSize     int
	LeaseDuration time.Duration
	Logger        *slog.Logger
	NewProvider   func(string, string) (providers.Provider, error)
	Clock         clock.Clock
}

type persistedCycleJobResult struct {
	ActionRunID     string            `json:"action_run_id,omitempty"`
	Status          string            `json:"status"`
	StopReason      string            `json:"stop_reason,omitempty"`
	ModelCalls      int               `json:"model_calls"`
	MemoryItemsSent int               `json:"memory_items_sent"`
	RequestsUsed    int               `json:"requests_used"`
	Actions         []cycleActionMark `json:"actions,omitempty"`
}

type cycleActionMark struct {
	ActionID      string `json:"action_id"`
	Sequence      int    `json:"sequence"`
	Status        string `json:"status"`
	RequestBudget int    `json:"request_budget"`
	RequestsUsed  int    `json:"requests_used"`
	Error         string `json:"error,omitempty"`
}

func (w AgentCycleWorker) RunCycle(ctx context.Context, now time.Time) (int, error) {
	if w.Store == nil {
		return 0, errors.New("agent cycle worker requires a store")
	}
	leaseDuration := w.LeaseDuration
	if leaseDuration <= 0 || leaseDuration > 10*time.Minute {
		leaseDuration = 10 * time.Minute
	}
	batchSize := w.BatchSize
	if batchSize != 1 {
		batchSize = 1
	}
	leases, err := w.Store.ClaimAgentCycleJobs(ctx, now.UTC(), leaseDuration, batchSize)
	if err != nil {
		return 0, err
	}
	processed := 0
	var failures []error
	for _, lease := range leases {
		if ctx.Err() != nil {
			return processed, errors.Join(append(failures, ctx.Err())...)
		}
		if err := w.processLease(ctx, lease, leaseDuration); err != nil {
			failures = append(failures, fmt.Errorf("adaptive cycle task %s: %w", lease.TaskID, err))
			continue
		}
		processed++
	}
	return processed, errors.Join(failures...)
}

func (w AgentCycleWorker) processLease(ctx context.Context, lease store.AgentCycleLease, leaseDuration time.Duration) error {
	modelConfig, err := config.Load(config.Options{
		Home:     w.Home,
		Provider: lease.Automation.PlannerProvider,
		Model:    lease.Automation.PlannerModel,
	})
	if err != nil {
		return w.finishJob(ctx, lease, Result{}, "failed", err)
	}
	if modelConfig.Provider != lease.Automation.PlannerProvider || modelConfig.Model != lease.Automation.PlannerModel {
		return w.finishJob(ctx, lease, Result{}, "failed", errors.New("configured planner provider/model differs from the program consent snapshot"))
	}
	newProvider := w.NewProvider
	if newProvider == nil {
		newProvider = providers.New
	}
	model, err := newProvider(modelConfig.Provider, modelConfig.APIKey)
	if err != nil {
		return w.finishJob(ctx, lease, Result{}, "failed", err)
	}

	cycleContext, cancelCycle := context.WithCancel(ctx)
	stopRenewal := make(chan struct{})
	renewalDone := make(chan struct{})
	var renewalErr error
	go func() {
		defer close(renewalDone)
		ticker := time.NewTicker(leaseHeartbeatInterval(leaseDuration))
		defer ticker.Stop()
		for {
			select {
			case <-cycleContext.Done():
				return
			case <-stopRenewal:
				return
			case <-ticker.C:
				renewed, err := w.Store.RenewAgentCycleJobLease(cycleContext, lease, w.now(), leaseDuration)
				if err != nil || !renewed {
					if err != nil {
						renewalErr = err
					} else {
						renewalErr = errors.New("agent cycle job lease or persisted consent was revoked")
					}
					cancelCycle()
					return
				}
			}
		}
	}()

	guard := func(guardContext context.Context) error {
		renewed, err := w.Store.RenewAgentCycleJobLease(guardContext, lease, w.now(), leaseDuration)
		if err != nil {
			return err
		}
		if !renewed {
			return errors.New("agent cycle job lease or persisted consent is no longer valid")
		}
		return nil
	}
	seed := agent.PlanActionObservation{
		Stage: lease.Stage, Target: lease.Target,
		Outcome: boundedWorkerEventSummary(lease.ChangeType, lease.Category),
	}
	result, runErr := (Executor{Store: w.Store, Clock: w.Clock}).RunAdaptiveWithAutomationGuard(
		cycleContext, lease.ProgramID, lease.ActionRunID, model, modelConfig.Model,
		lease.Automation.MaxStepsPerCycle, lease.RequestBudget, []agent.PlanActionObservation{seed}, lease.Automation, guard, w.now(),
	)
	close(stopRenewal)
	cancelCycle()
	<-renewalDone
	if renewalErr != nil && runErr == nil {
		runErr = renewalErr
	}
	outcome := "completed"
	if runErr != nil {
		outcome = w.failedOutcome(ctx, lease, result.ActionRunID)
	}
	if err := w.finishJob(ctx, lease, result, outcome, runErr); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

func (w AgentCycleWorker) failedOutcome(ctx context.Context, lease store.AgentCycleLease, actionRunID string) string {
	if actionRunID == "" {
		return "failed"
	}
	run, err := w.Store.GetAgentActionRun(ctx, lease.ProgramID, actionRunID)
	if err != nil || run.Status == "needs_review" {
		return "needs_review"
	}
	if run.Status == "active" {
		return "needs_review"
	}
	return "failed"
}

func (w AgentCycleWorker) finishJob(ctx context.Context, lease store.AgentCycleLease, result Result, outcome string, cause error) error {
	if result.Status == "" {
		result.Status = outcome
	}
	persisted := persistedCycleJobResult{
		ActionRunID: result.ActionRunID, Status: result.Status, StopReason: result.StopReason,
		ModelCalls: result.ModelCalls, MemoryItemsSent: result.MemoryItemsSent, RequestsUsed: result.RequestsUsed,
		Actions: make([]cycleActionMark, 0, len(result.Actions)),
	}
	for _, action := range result.Actions {
		persisted.Actions = append(persisted.Actions, cycleActionMark{
			ActionID: action.ActionID, Sequence: action.Sequence, Status: action.Status,
			RequestBudget: action.RequestBudget, RequestsUsed: action.RequestsUsed, Error: action.Error,
		})
	}
	encoded, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("encode adaptive cycle job result: %w", err)
	}
	persistContext, cancel := persistenceContext(ctx)
	defer cancel()
	return w.Store.CompleteAgentCycleJob(persistContext, lease, outcome, encoded, cause, w.now())
}

func boundedWorkerEventSummary(changeType, category string) string {
	value := strings.TrimSpace("Material recon event: " + changeType + " " + category)
	if len(value) > 256 {
		value = value[:256]
	}
	return strings.ToValidUTF8(value, "�")
}

func leaseHeartbeatInterval(lease time.Duration) time.Duration {
	interval := lease / 3
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}
