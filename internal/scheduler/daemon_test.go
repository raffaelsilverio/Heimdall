package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/schedule"
	"github.com/raffaelsilverio/Heimdall/internal/store"
)

type sequenceCollector struct {
	results []recon.Collection
	calls   int
}

func (c *sequenceCollector) Run(context.Context, recon.StageRequest) (recon.Collection, error) {
	result := c.results[c.calls]
	c.calls++
	return result, nil
}

type blockingStageRunner struct {
	started chan struct{}
}

func (r blockingStageRunner) Run(ctx context.Context, _ recon.StageRequest) (recon.Collection, error) {
	close(r.started)
	<-ctx.Done()
	return recon.Collection{}, ctx.Err()
}

func TestRunCycleStoresBaselineAndMaterialChange(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	start := time.Now().UTC().Truncate(time.Minute)
	program, err := database.CreateProgram(ctx, store.CreateProgramParams{
		Name:                   "Scheduler test",
		AuthorizationReference: "internal:test",
		ExpiresAt:              start.Add(48 * time.Hour),
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Type: assessment.ScopeWildcardDomain, Value: "example.com",
		}}},
		Timezone: "UTC",
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "* * * * *", "UTC", true, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, start); err != nil {
		t.Fatal(err)
	}
	collector := &sequenceCollector{results: []recon.Collection{
		{Observations: []recon.Observation{{Category: recon.CategoryHostname, StableKey: "www.example.com", Value: "www.example.com", Source: "test", ToolVersion: "v1"}}},
		{Observations: []recon.Observation{
			{Category: recon.CategoryHostname, StableKey: "www.example.com", Value: "www.example.com", Source: "test", ToolVersion: "v1"},
			{Category: recon.CategoryHostname, StableKey: "new.example.com", Value: "new.example.com", Source: "test", ToolVersion: "v1"},
		}},
	}}
	daemon := Daemon{Store: database, Runner: collector, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if count, err := daemon.RunCycle(ctx, start); err != nil || count != 1 {
		t.Fatalf("first RunCycle: count=%d err=%v", count, err)
	}
	events, err := database.ListChangeEvents(ctx, program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("baseline run created change events: %+v", events)
	}
	if count, err := daemon.RunCycle(ctx, start.Add(time.Minute)); err != nil || count != 1 {
		t.Fatalf("second RunCycle: count=%d err=%v", count, err)
	}
	events, err = database.ListChangeEvents(ctx, program.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ChangeType != "added" || events[0].StableKey != "new.example.com" || !events[0].Material {
		t.Fatalf("unexpected material change: %+v", events)
	}
}

func TestDailyScheduleDefaultCanBeOverridden(t *testing.T) {
	if schedule.DefaultOSINTCron != "0 3 * * *" {
		t.Fatalf("default OSINT cron = %q, want daily at 03:00", schedule.DefaultOSINTCron)
	}
}

func TestPausingProgramCancelsAnInProgressWebStage(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	start := time.Now().UTC().Truncate(time.Minute)
	program, err := database.CreateProgram(ctx, store.CreateProgramParams{
		Name:                   "Pause web stage",
		AuthorizationReference: "internal:pause-web",
		ExpiresAt:              start.Add(24 * time.Hour),
		Scope:                  assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeURL, Value: "https://example.com"}}},
		Timezone:               "UTC",
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageOSINT, "0 3 * * *", "UTC", false, start); err != nil {
		t.Fatal(err)
	}
	if err := database.SetStageSchedule(ctx, program.ID, recon.StageWeb, "* * * * *", "UTC", true, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, start); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	daemon := Daemon{Store: database, Runner: blockingStageRunner{started: started}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	finished := make(chan error, 1)
	go func() {
		_, err := daemon.RunCycle(ctx, start)
		finished <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("web runner did not start")
	}
	if err := database.PauseProgram(ctx, program.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("paused run error = %v, want cancellation", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("paused web stage did not stop")
	}
	status, err := database.LatestRunStatus(ctx, program.ID, recon.StageWeb)
	if err != nil {
		t.Fatal(err)
	}
	if status != "interrupted" {
		t.Fatalf("paused run status = %q, want interrupted", status)
	}
}
