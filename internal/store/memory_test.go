package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func createMemoryTestProgram(t *testing.T, database *Store, name string, now time.Time) assessment.Program {
	t.Helper()
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name:                   name,
		AuthorizationReference: "internal:memory-test",
		ExpiresAt:              now.Add(24 * time.Hour),
		Timezone:               "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeDomain, Value: "memory.example.test",
		}}},
	}, now)
	if err != nil {
		t.Fatalf("CreateProgram(%q): %v", name, err)
	}
	return program
}

func TestProgramMemorySearchAndGetAreIsolated(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Memory Program A", now)
	programB := createMemoryTestProgram(t, database, "Memory Program B", now)

	memoryA, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programA.ID, Kind: "fact", Title: "Private alpha authentication",
		Content: "Program A uses a private alpha login flow.", SourceKind: "operator", Confidence: 0.9,
		ScopeHash: programA.ScopeHash,
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programB.ID, Kind: "fact", Title: "Public beta authentication",
		Content: "Program B uses a public beta login flow.", SourceKind: "operator", Confidence: 0.8,
		ScopeHash: programB.ScopeHash,
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	resultsA, err := database.SearchProgramMemories(ctx, programA.ID, "private alpha", 10, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(resultsA) != 1 || resultsA[0].ID != memoryA.ID {
		t.Fatalf("program A search returned unexpected records: %+v", resultsA)
	}
	resultsB, err := database.SearchProgramMemories(ctx, programB.ID, "private alpha", 10, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(resultsB) != 0 {
		t.Fatalf("program B search leaked program A memory: %+v", resultsB)
	}
	if _, err := database.GetProgramMemory(ctx, programB.ID, memoryA.ID); err == nil {
		t.Fatal("GetProgramMemory returned another program's memory")
	}
	if _, err := database.ListProgramMemories(ctx, "", 10, now); err == nil {
		t.Fatal("memory listing without a program id unexpectedly succeeded")
	}

	updated, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programA.ID, Kind: "fact", Title: "Private alpha authentication, corrected",
		Content:    "The private alpha login flow was checked again and uses a second factor.",
		SourceKind: "operator", Confidence: 1, ScopeHash: programA.ScopeHash, SupersedesID: memoryA.ID,
	}, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	old, err := database.GetProgramMemory(ctx, programA.ID, memoryA.ID)
	if err != nil || old.Status != "superseded" {
		t.Fatalf("old memory was not retained as superseded: status=%s err=%v", old.Status, err)
	}
	if _, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programB.ID, Kind: "fact", Title: "Cross-program supersession",
		Content: "This must not link to program A.", SourceKind: "operator", Confidence: 1, SupersedesID: updated.ID,
	}, now.Add(5*time.Minute)); err == nil {
		t.Fatal("cross-program supersession unexpectedly succeeded")
	}
	if err := database.ArchiveProgramMemory(ctx, programA.ID, updated.ID, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	resultsA, err = database.SearchProgramMemories(ctx, programA.ID, "private alpha", 10, now.Add(7*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(resultsA) != 0 {
		t.Fatalf("archived/superseded memory remained searchable: %+v", resultsA)
	}
}

func TestProgramMemoryValidatesProvenanceAndMarksOldScope(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.May, 1, 0, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Run Memory Program A", now)
	programB := createMemoryTestProgram(t, database, "Run Memory Program B", now)

	var authorizationID string
	if err := database.db.QueryRowContext(ctx, `SELECT id FROM authorizations WHERE program_id = ? AND replaced_at IS NULL`, programA.ID).Scan(&authorizationID); err != nil {
		t.Fatal(err)
	}
	const runID = "memory-provenance-run-a"
	if _, err := database.db.ExecContext(ctx, `INSERT INTO runs(
		id, program_id, authorization_id, stage, trigger, scope_hash, profile_version, normalizer_version, status, started_at)
		VALUES (?, ?, ?, 'osint', 'manual', ?, 'test-v1', 'test-v1', 'complete', ?)`,
		runID, programA.ID, authorizationID, programA.ScopeHash, now.Unix()); err != nil {
		t.Fatal(err)
	}

	memory, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programA.ID, Kind: "negative_result", Title: "No login redirect observed",
		Content:    "The scoped login URL did not redirect during this run.",
		SourceKind: "run", SourceID: runID, Confidence: 0.7,
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if memory.ScopeHash != programA.ScopeHash {
		t.Fatalf("memory scope hash = %q, want source run hash %q", memory.ScopeHash, programA.ScopeHash)
	}
	verifiedAt := now.Add(time.Minute)
	verified, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programA.ID, Kind: "finding_verified", Title: "Reproduced access-control finding",
		Content:    "The test run reproduced the issue with attached evidence.",
		SourceKind: "run", SourceID: runID, Confidence: 0.95, VerifiedAt: &verifiedAt,
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verified finding backed by a complete same-program run was rejected: %v", err)
	}
	if verified.Status != "active" || verified.VerifiedAt == nil {
		t.Fatalf("verified finding metadata was not retained: %+v", verified)
	}
	if _, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programB.ID, Kind: "negative_result", Title: "Cross-program run reference",
		Content: "This reference must be rejected.", SourceKind: "run", SourceID: runID, Confidence: 0.5,
	}, now.Add(2*time.Minute)); err == nil {
		t.Fatal("memory accepted a run from another program")
	}
	if _, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: programA.ID, Kind: "finding_verified", Title: "Unsubstantiated verified finding",
		Content: "This must cite a run or artifact and a verification time.", SourceKind: "operator", Confidence: 1,
	}, now.Add(2*time.Minute)); err == nil {
		t.Fatal("verified finding was accepted without evidence provenance")
	}

	newScopeHash := strings.Repeat("a", 64)
	if _, err := database.db.ExecContext(ctx, `UPDATE programs SET scope_hash = ? WHERE id = ?`, newScopeHash, programA.ID); err != nil {
		t.Fatal(err)
	}
	memories, err := database.ListProgramMemories(ctx, programA.ID, 10, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(memories) != 2 || !memories[0].ScopeStale || !memories[1].ScopeStale {
		t.Fatalf("memory from prior scope was not marked stale: %+v", memories)
	}
}

func TestProgramMemoryExpiryAndSourceSnapshotFreshness(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	program, err := database.CreateProgram(ctx, CreateProgramParams{
		Name: "HackerOne memory program", SourcePlatform: "hackerone", SourceURL: "https://hackerone.com/acme",
		AuthorizationReference: "https://hackerone.com/acme", ExpiresAt: now.Add(24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{Type: assessment.ScopeDomain, Value: "acme.example.test"}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	firstSource, _, err := database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":1}`), &program.Scope, nil, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	approved, _, err := database.ApproveProgramSourceSnapshot(ctx, program.ID, true, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approved.SourceHash != firstSource.SourceHash {
		t.Fatal("approved source hash changed unexpectedly")
	}
	_, _, err = database.RecordProgramSourceSnapshot(ctx, program.ID, []byte(`{"revision":2}`), &program.Scope, nil, nil, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	expires := now.Add(4 * time.Minute)
	memory, err := database.AddProgramMemory(ctx, AddProgramMemoryParams{
		ProgramID: program.ID, Kind: "fact", Title: "Program policy note",
		Content:    "This observation came from the first source revision.",
		SourceKind: "source_snapshot", SourceID: firstSource.ID, Confidence: 1, ExpiresAt: &expires,
	}, now.Add(3*time.Minute+30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if memory.SourceHash != firstSource.SourceHash {
		t.Fatalf("snapshot provenance hash = %q, want %q", memory.SourceHash, firstSource.SourceHash)
	}
	results, err := database.SearchProgramMemories(ctx, program.ID, "first source revision", 10, now.Add(3*time.Minute+45*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].SourceStale || !results[0].SourceReviewPending {
		t.Fatalf("memory did not flag its pending source context: %+v", results)
	}
	results, err = database.SearchProgramMemories(ctx, program.ID, "first source revision", 10, expires.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expired memory remained searchable: %+v", results)
	}
}
