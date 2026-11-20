package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestProgramDataAccessDefaultsAndRevision(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Data Access A", now)
	programB := createMemoryTestProgram(t, database, "Data Access B", now)

	defaultPolicy, err := database.GetProgramDataAccess(ctx, programA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if defaultPolicy.Mode != assessment.DataAccessTestAccountsOnly || defaultPolicy.Revision != 1 ||
		!defaultPolicy.AllowOwnedTestAccounts || !defaultPolicy.AllowExplicitlyAuthorizedAccounts ||
		defaultPolicy.AllowOtherUsersData {
		t.Fatalf("new program data access policy is unexpected: %+v", defaultPolicy)
	}

	tightened := assessment.DefaultDataAccessPolicy()
	tightened.AllowOwnedTestAccounts = false
	saved, err := database.SetProgramDataAccess(ctx, programA.ID, tightened, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || saved.AllowOwnedTestAccounts {
		t.Fatalf("tightened policy is unexpected: %+v", saved)
	}
	unchanged, err := database.SetProgramDataAccess(ctx, programA.ID, tightened, now.Add(2*time.Minute))
	if err != nil || unchanged.Revision != 2 {
		t.Fatalf("identical policy should not create a revision: policy=%+v err=%v", unchanged, err)
	}
	other, err := database.GetProgramDataAccess(ctx, programB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if other.Revision != 1 || !other.AllowOwnedTestAccounts {
		t.Fatalf("program A policy leaked into B: %+v", other)
	}
	if _, err := database.SetProgramDataAccess(ctx, programA.ID, assessment.DataAccessPolicy{
		AllowOtherUsersData: true,
	}, now.Add(3*time.Minute)); err == nil || !strings.Contains(err.Error(), "other users") {
		t.Fatalf("widening policy error = %v", err)
	}
}

func TestProgramTestAccountLifecycle(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 20, 1, 0, 0, 0, time.UTC)
	programA := createMemoryTestProgram(t, database, "Accounts A", now)
	programB := createMemoryTestProgram(t, database, "Accounts B", now)

	account, err := database.AddProgramTestAccount(ctx, programA.ID, assessment.TestAccount{
		ID: "test-user-1", Identity: "test-user-1@example.test", Role: assessment.TestAccountRoleUser,
		CredentialRef: "env:HEIMDALL_ACCOUNT_TEST_USER_1",
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if account.Status != assessment.TestAccountStatusAuthorized || account.Source != assessment.TestAccountSourceOwned ||
		!account.CreatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("registered account is unexpected: %+v", account)
	}
	accounts, err := database.ListProgramTestAccounts(ctx, programA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].ID != "test-user-1" || accounts[0].CredentialRef != "env:HEIMDALL_ACCOUNT_TEST_USER_1" {
		t.Fatalf("listed accounts are unexpected: %+v", accounts)
	}
	if _, err := database.AddProgramTestAccount(ctx, programA.ID, assessment.TestAccount{
		ID: "test-user-1", Identity: "duplicate@example.test", Role: assessment.TestAccountRoleUser,
	}, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate account error = %v", err)
	}
	if _, err := database.AddProgramTestAccount(ctx, programA.ID, assessment.TestAccount{
		ID: "unsafe", Identity: "unsafe@example.test", Role: assessment.TestAccountRoleUser,
		CredentialRef: "Bearer secret-token",
	}, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "raw credentials are never stored") {
		t.Fatalf("raw credential error = %v", err)
	}
	if _, err := database.AddProgramTestAccount(ctx, "missing-program", assessment.TestAccount{
		ID: "test-user-1", Identity: "test-user-1@example.test", Role: assessment.TestAccountRoleUser,
	}, now); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing program error = %v", err)
	}
	otherAccounts, err := database.ListProgramTestAccounts(ctx, programB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherAccounts) != 0 {
		t.Fatalf("program A accounts leaked into B: %+v", otherAccounts)
	}

	policy, err := database.GetProgramDataAccess(ctx, programA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.AuthorizeTestAccount(account); err != nil {
		t.Fatalf("authorized account was rejected: %v", err)
	}
	revoked, err := database.RevokeProgramTestAccount(ctx, programA.ID, "test-user-1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != assessment.TestAccountStatusRevoked {
		t.Fatalf("revoked account is unexpected: %+v", revoked)
	}
	if err := policy.AuthorizeTestAccount(revoked); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked account was authorized: %v", err)
	}
	again, err := database.RevokeProgramTestAccount(ctx, programA.ID, "test-user-1", now.Add(4*time.Minute))
	if err != nil || again.Status != assessment.TestAccountStatusRevoked || !again.UpdatedAt.Equal(revoked.UpdatedAt) {
		t.Fatalf("revocation was not idempotent: account=%+v err=%v", again, err)
	}
	if _, err := database.RevokeProgramTestAccount(ctx, programA.ID, "missing", now); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing account error = %v", err)
	}
}
