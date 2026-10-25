package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func TestProgramSourceReviewPausesAndRequiresExplicitApproval(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, now)
	if _, err := database.db.ExecContext(ctx, `UPDATE programs SET source_platform = 'hackerone', source_url = ? WHERE id = ?`,
		"https://hackerone.com/acme", program.ID); err != nil {
		t.Fatal(err)
	}

	candidate := assessment.Scope{Entries: []assessment.ScopeEntry{{
		Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "new.example.test",
	}}}
	snapshot, changed, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":1}`), &candidate, nil, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || snapshot.Status != "pending" {
		t.Fatalf("first source sync status=%s changed=%t", snapshot.Status, changed)
	}
	stored, err := database.GetProgram(ctx, program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != assessment.ProgramPaused {
		t.Fatalf("program status after source revision = %s, want paused", stored.Status)
	}
	if err := database.ActivateProgram(ctx, program.ID, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "pending source review") {
		t.Fatalf("activation with pending review returned %v", err)
	}

	// Repeating a fetch of the same pending revision is idempotent.
	repeated, changed, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{ "revision": 1 }`), &candidate, nil, nil, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || repeated.ID != snapshot.ID {
		t.Fatalf("repeated pending sync did not reuse the pending revision: id=%s changed=%t", repeated.ID, changed)
	}
	var sourceRows int
	if err := database.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM program_source_snapshots WHERE program_id = ?`, program.ID).Scan(&sourceRows); err != nil {
		t.Fatal(err)
	}
	if sourceRows != 1 {
		t.Fatalf("repeated pending sync left %d snapshots, want 1", sourceRows)
	}

	approved, scopeChanged, err := database.ApproveProgramSourceSnapshotWithPorts(ctx, program.ID, true, []uint16{443, 8443}, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" || !approved.ScopeApplied || approved.AppliedScopeHash == "" || !scopeChanged {
		t.Fatalf("unexpected approved snapshot: %+v scopeChanged=%t", approved, scopeChanged)
	}
	stored, err = database.GetProgram(ctx, program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ScopeHash != approved.AppliedScopeHash || stored.Status != assessment.ProgramPaused {
		t.Fatalf("approval did not apply candidate while keeping program paused: hash=%s status=%s", stored.ScopeHash, stored.Status)
	}
	if approved.AppliedScope == nil || len(approved.AppliedScope.Entries) != 1 || len(approved.AppliedScope.Entries[0].Ports) != 2 {
		t.Fatalf("explicit approved ports were not retained: %+v", approved.AppliedScope)
	}
	var revision int
	if err := database.db.QueryRowContext(ctx, `SELECT scope_revision FROM programs WHERE id = ?`, program.ID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("scope revision = %d, want 2", revision)
	}
	if err := database.ActivateProgram(ctx, program.ID, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("activation after review failed: %v", err)
	}
	stored, err = database.GetProgram(ctx, program.ID)
	if err != nil || stored.Status != assessment.ProgramActive {
		t.Fatalf("approved program did not reactivate explicitly: %+v err=%v", stored, err)
	}

	unchanged, changed, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":1}`), &candidate, nil, nil, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if changed || unchanged.Status != "unchanged" {
		t.Fatalf("same approved source status=%s changed=%t", unchanged.Status, changed)
	}
	stored, err = database.GetProgram(ctx, program.ID)
	if err != nil || stored.Status != assessment.ProgramActive {
		t.Fatalf("unchanged source sync paused the program: %+v err=%v", stored, err)
	}
}

func TestProgramSourceCanBeAcknowledgedWithoutReplacingLocalScope(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, now)
	if _, err := database.db.ExecContext(ctx, `UPDATE programs SET source_platform = 'hackerone', source_url = ? WHERE id = ?`,
		"https://hackerone.com/acme", program.ID); err != nil {
		t.Fatal(err)
	}
	before, err := database.GetProgram(ctx, program.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]string{"revision": "unsupported-mobile-assets"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := database.RecordProgramSourceSnapshot(ctx, program.ID, data, nil,
		[]string{"mobile assets retained in snapshot"}, []string{"unsupported asset type: ANDROID"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CandidateScope != nil || len(snapshot.Blockers) == 0 {
		t.Fatalf("unsupported candidate should not be applicable: %+v", snapshot)
	}
	if _, _, err := database.ApproveProgramSourceSnapshot(ctx, program.ID, true, now.Add(2*time.Minute)); err == nil {
		t.Fatal("applying an unsupported partial candidate unexpectedly succeeded")
	}

	approved, scopeChanged, err := database.ApproveProgramSourceSnapshot(ctx, program.ID, false, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" || approved.ScopeApplied || scopeChanged {
		t.Fatalf("unexpected keep-current approval: %+v scopeChanged=%t", approved, scopeChanged)
	}
	after, err := database.GetProgram(ctx, program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ScopeHash != before.ScopeHash || after.Status != assessment.ProgramPaused {
		t.Fatalf("keep-current approval modified the local scope or resumed program: hash=%s status=%s", after.ScopeHash, after.Status)
	}
	if err := database.ActivateProgram(ctx, program.ID, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("could not explicitly activate after acknowledging source: %v", err)
	}
	if schedules, err := database.ListStageSchedules(ctx, program.ID); err != nil {
		t.Fatal(err)
	} else if len(schedules) != 1 || !schedules[0].Enabled || schedules[0].Stage != recon.StageOSINT {
		t.Fatalf("unexpected schedule state after review: %+v", schedules)
	}
}

func TestChangedHackerOneSourcePausesActiveProgram(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, now)
	if _, err := database.db.ExecContext(ctx, `UPDATE programs SET source_platform = 'hackerone' WHERE id = ?`, program.ID); err != nil {
		t.Fatal(err)
	}
	current := assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "example.test"}}}
	if _, _, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":1}`), &current, nil, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.ApproveProgramSourceSnapshot(ctx, program.ID, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(ctx, program.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	updated := assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "new.example.test"}}}
	result, changed, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":2}`), &updated, nil, nil, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || result.Status != "pending" {
		t.Fatalf("changed source result = %+v changed=%t", result, changed)
	}
	stored, err := database.GetProgram(ctx, program.ID)
	if err != nil || stored.Status != assessment.ProgramPaused {
		t.Fatalf("changed source did not pause active program: status=%s err=%v", stored.Status, err)
	}
}
