package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentTriageQueueMigrationPreservesLegacyStateAndSeparatesPlannerTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-agent-tasks.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, migrationName := range []string{
		"001_initial.sql", "002_tool_provenance_and_artifacts.sql", "003_stage_limits.sql",
		"004_sessions.sql", "005_program_sources.sql", "006_program_source_snapshots.sql",
		"007_program_memory.sql", "008_agent_event_triage.sql",
	} {
		migration, err := migrationFiles.ReadFile("migrations/" + migrationName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := legacy.Exec(string(migration)); err != nil {
			t.Fatalf("apply legacy migration %s: %v", migrationName, err)
		}
		if _, err := legacy.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, migrationName, 1); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Unix()
	if _, err := legacy.Exec(`INSERT INTO programs(id, name, status, scope_json, scope_hash, scope_revision, created_at, updated_at, source_platform)
		VALUES ('program-a', 'Program A', 'paused', ?, 'scope-a', 1, ?, ?, 'manual')`,
		`{"entries":[{"effect":"include","type":"domain","value":"example.test"}]}`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO authorizations(id, program_id, reference, expires_at, expires_at_ns, created_at)
		VALUES ('auth-a', 'program-a', 'internal:test', ?, ?, ?)`, now+86400, (now+86400)*1_000_000_000, now); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO runs(id, program_id, authorization_id, stage, trigger, scope_hash, profile_version,
		normalizer_version, status, started_at)
		VALUES ('run-a', 'program-a', 'auth-a', 'osint', 'manual', 'scope-a', 'profile-v1', 'normalizer-v1', 'complete', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO change_events(id, program_id, run_id, stage, scope_hash, category, stable_key,
		change_type, material, created_at)
		VALUES ('event-a', 'program-a', 'run-a', 'osint', 'scope-a', 'hostname', 'new.example.test', 'added', 1, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO sessions(id, program_id, kind, title, status, scope_hash, trigger_event_id, created_at, updated_at)
		VALUES ('session-a', 'program-a', 'agent_event', 'Recon change', 'open', 'scope-a', 'event-a', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	const oldResult = `{"brief":"preserved"}`
	if _, err := legacy.Exec(`INSERT INTO agent_tasks(id, event_id, status, created_at, session_id, attempts,
		triage_status, triage_attempts, triage_lease_until, triaged_at, triage_error, result_json)
		VALUES ('task-a', 'event-a', 'pending', ?, 'session-a', 0,
		'complete', 2, NULL, ?, NULL, ?)`, now, now+5, oldResult); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var triageStatus, resultJSON string
	var triageAttempts int
	var triagedAt int64
	if err := database.db.QueryRowContext(context.Background(), `SELECT status, attempts, triaged_at, result_json
		FROM agent_event_triage_jobs WHERE task_id = 'task-a'`).Scan(&triageStatus, &triageAttempts, &triagedAt, &resultJSON); err != nil {
		t.Fatal(err)
	}
	if triageStatus != "complete" || triageAttempts != 2 || triagedAt != now+5 || resultJSON != oldResult {
		t.Fatalf("legacy triage state was not migrated: status=%s attempts=%d triaged_at=%d result=%s", triageStatus, triageAttempts, triagedAt, resultJSON)
	}
	var legacyTriageColumns int
	if err := database.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('agent_tasks')
		WHERE name IN ('triage_status', 'triage_attempts', 'triage_lease_until', 'triaged_at', 'triage_error')`).Scan(&legacyTriageColumns); err != nil {
		t.Fatal(err)
	}
	if legacyTriageColumns != 0 {
		t.Fatalf("planner task table still has %d deterministic triage columns", legacyTriageColumns)
	}
	var plannerStatus string
	if err := database.db.QueryRowContext(context.Background(), `SELECT status FROM agent_tasks WHERE id = 'task-a'`).Scan(&plannerStatus); err != nil {
		t.Fatal(err)
	}
	if plannerStatus != "pending" {
		t.Fatalf("main planner task status = %s, want pending", plannerStatus)
	}
}
