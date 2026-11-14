package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestCreateActivateAndListProgram(t *testing.T) {
	database := openTestStore(t)
	now := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	program := createActiveProgram(t, database, now)
	if program.Status != assessment.ProgramDraft {
		t.Fatalf("new program status = %q, want draft", program.Status)
	}
	stored, err := database.GetProgram(context.Background(), program.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != assessment.ProgramActive {
		t.Fatalf("stored program status = %q, want active", stored.Status)
	}
	if stored.AuthorizationReference != "https://example.test/program" {
		t.Errorf("authorization reference was not stored: %q", stored.AuthorizationReference)
	}
	programs, err := database.ListPrograms(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || programs[0].ID != program.ID {
		t.Fatalf("unexpected listed programs: %+v", programs)
	}
}

func TestUpgradeFromInitialSchemaPreservesAuthorizationExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	initialMigration, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(string(initialMigration)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES ('001_initial.sql', 1)`); err != nil {
		t.Fatal(err)
	}
	const expirySeconds int64 = 2_000_000_000
	if _, err := database.Exec(`INSERT INTO programs(id, name, status, scope_json, scope_hash, scope_revision, created_at, updated_at)
		VALUES ('legacy-program', 'Legacy', 'draft', ?, 'legacy-hash', 1, 1, 1)`, `{"entries":[{"effect":"include","type":"domain","value":"example.com"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO authorizations(id, program_id, reference, expires_at, created_at)
		VALUES ('legacy-auth', 'legacy-program', 'internal:legacy', ?, 1)`, expirySeconds); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	program, err := upgraded.GetProgram(context.Background(), "legacy-program")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(expirySeconds, 0).UTC()
	if !program.ExpiresAt.Equal(want) {
		t.Fatalf("upgraded expiry = %s, want %s", program.ExpiresAt, want)
	}
	for _, table := range []string{"tool_runs", "artifacts"} {
		var count int
		if err := upgraded.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("migration did not create %s", table)
		}
	}
}

func TestInteractiveSessionPersistsMessagesAndCanBeClosed(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	program := createActiveProgram(t, database, now)
	session, err := database.CreateSession(context.Background(), program.ID, "Triage notes", now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Kind != "interactive" || session.Status != "open" {
		t.Fatalf("unexpected session state: %+v", session)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "user", "Check the observed hostname", "", "", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "assistant", "I will review the evidence.", "openai", "test-model", nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	messages, err := database.ListSessionMessages(context.Background(), session.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Sequence != 1 || messages[1].Provider != "openai" || messages[1].Model != "test-model" {
		t.Fatalf("unexpected persisted messages: %+v", messages)
	}
	if err := database.CloseSession(context.Background(), session.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendSessionMessage(context.Background(), session.ID, "user", "after close", "", "", nil, now.Add(3*time.Second)); err == nil {
		t.Fatal("closed session accepted a new message")
	}
}
