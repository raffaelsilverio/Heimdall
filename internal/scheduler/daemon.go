package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/clock"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

type Repository interface {
	ClaimDueSchedules(ctx context.Context, now time.Time, leaseDuration time.Duration) ([]store.DueJob, error)
	ValidateRunAuthorization(ctx context.Context, runID string, now time.Time) error
	InScopeHostSeeds(ctx context.Context, programID, scopeHash string) ([]string, error)
	InScopeEndpointSeeds(ctx context.Context, programID, scopeHash string) ([]string, error)
	CompleteRun(ctx context.Context, runID string, collection recon.Collection, complete bool, runErr error, now time.Time) ([]store.ChangeEvent, error)
}

type AgentEventTriageRunner interface {
	RunCycle(ctx context.Context, now time.Time) (int, error)
}

type AdaptiveAgentCycleRunner interface {
	RunCycle(ctx context.Context, now time.Time) (int, error)
}

type Daemon struct {
	Store         Repository
	Runner        recon.StageRunner
	AgentTriage   AgentEventTriageRunner
	AgentCycles   AdaptiveAgentCycleRunner
	PollInterval  time.Duration
	LeaseDuration time.Duration
	Logger        *slog.Logger
	Clock         clock.Clock
}

func (d Daemon) now() time.Time {
	return clock.Or(d.Clock).Now()
}

func (d Daemon) Run(ctx context.Context) error {
	if d.Store == nil || d.Runner == nil {
		return errors.New("daemon requires a store and stage runner")
	}
	interval := d.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	logger := d.logger()
	logger.Info("Heimdall daemon started", "poll_interval", interval)
	for {
		processed, err := d.RunCycle(ctx, d.now())
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("scheduler cycle failed", "error", err)
		}
		if processed > 0 && ctx.Err() == nil {
			continue
		}
		select {
		case <-ctx.Done():
			logger.Info("Heimdall daemon stopped")
			return nil
		case <-time.After(interval):
		}
	}
}

func (d Daemon) RunCycle(ctx context.Context, now time.Time) (int, error) {
	if d.Store == nil || d.Runner == nil {
		return 0, errors.New("daemon requires a store and stage runner")
	}
	leaseDuration := d.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Hour
	}
	processed := 0
	var failures []error
	if d.AgentTriage != nil {
		triaged, err := d.AgentTriage.RunCycle(ctx, now.UTC())
		processed += triaged
		if err != nil {
			failures = append(failures, fmt.Errorf("triage material recon events: %w", err))
		}
	}
	if d.AgentCycles != nil {
		cycles, err := d.AgentCycles.RunCycle(ctx, now.UTC())
		processed += cycles
		if err != nil {
			failures = append(failures, fmt.Errorf("run consented adaptive agent cycles: %w", err))
		}
	}
	jobs, err := d.Store.ClaimDueSchedules(ctx, now, leaseDuration)
	if err != nil {
		return processed, errors.Join(append(failures, err)...)
	}
	logger := d.logger()
	for _, job := range jobs {
		logger.Info("running scheduled recon", "program", job.Program.Name, "stage", job.Stage, "run_id", job.RunID)
		collection := recon.Collection{}
		runContext, cancelRun := context.WithDeadline(ctx, job.Program.ExpiresAt)
		runErr := d.Store.ValidateRunAuthorization(runContext, job.RunID, d.now())
		if runErr == nil {
			targets := []string(nil)
			switch job.Stage {
			case recon.StageWeb, recon.StageNmap:
				targets, runErr = d.Store.InScopeHostSeeds(runContext, job.Program.ID, job.Program.ScopeHash)
			case recon.StageCrawl, recon.StageFFUF, recon.StageNuclei:
				targets, runErr = d.Store.InScopeEndpointSeeds(runContext, job.Program.ID, job.Program.ScopeHash)
			}
			if runErr == nil {
				collection, runErr = d.runStageWithPolicy(runContext, job, recon.StageRequest{
					Program: job.Program,
					Stage:   job.Stage,
					Targets: targets,
					Limits:  job.Limits,
				})
			}
		}
		cancelRun()

		persistContext := ctx
		cancel := func() {}
		if ctx.Err() != nil {
			persistContext, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		}
		events, persistErr := d.Store.CompleteRun(persistContext, job.RunID, collection, runErr == nil, runErr, d.now())
		cancel()
		if persistErr != nil {
			failures = append(failures, fmt.Errorf("persist run %s: %w", job.RunID, persistErr))
			continue
		}
		logger.Info("recon run finished", "program", job.Program.Name, "run_id", job.RunID,
			"tools", len(collection.Tools), "observations", len(collection.Observations), "artifacts", len(collection.Artifacts),
			"changes", len(events), "complete", runErr == nil)
		if runErr != nil {
			logger.Error("recon stage failed", "program", job.Program.Name, "stage", job.Stage, "error", runErr)
			failures = append(failures, fmt.Errorf("program %s stage %s: %w", job.Program.Name, job.Stage, runErr))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return processed + len(jobs), errors.Join(failures...)
}

func (d Daemon) runStageWithPolicy(ctx context.Context, job store.DueJob, request recon.StageRequest) (recon.Collection, error) {
	stageContext, cancelStage := context.WithCancel(ctx)
	defer cancelStage()
	if err := d.Store.ValidateRunAuthorization(stageContext, job.RunID, d.now()); err != nil {
		return recon.Collection{}, err
	}
	stopMonitor := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stageContext.Done():
				return
			case <-stopMonitor:
				return
			case <-ticker.C:
				if err := d.Store.ValidateRunAuthorization(stageContext, job.RunID, d.now()); err != nil {
					cancelStage()
					return
				}
			}
		}
	}()
	collection, err := d.Runner.Run(stageContext, request)
	close(stopMonitor)
	<-monitorDone
	if stageContext.Err() != nil && err == nil {
		err = stageContext.Err()
	}
	checkContext, cancelCheck := context.WithTimeout(context.WithoutCancel(stageContext), 5*time.Second)
	defer cancelCheck()
	if policyErr := d.Store.ValidateRunAuthorization(checkContext, job.RunID, d.now()); policyErr != nil && err == nil {
		err = policyErr
	}
	return collection, err
}

func (d Daemon) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}
