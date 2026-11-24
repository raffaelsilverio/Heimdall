package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
)

func createApprovalProgram(t *testing.T, database *Store, now time.Time) assessment.Program {
	t.Helper()
	program, err := database.CreateProgram(context.Background(), CreateProgramParams{
		Name: "Approval Program", AuthorizationReference: "internal:approval-test",
		ExpiresAt: now.Add(24 * time.Hour), Timezone: "UTC",
		Scope: assessment.Scope{Entries: []assessment.ScopeEntry{{
			Effect: assessment.ScopeInclude, Type: assessment.ScopeURL, Value: "https://app.example.test/",
		}}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ActivateProgram(context.Background(), program.ID, now); err != nil {
		t.Fatal(err)
	}
	return program
}

func createApprovalPolicy(t *testing.T, database *Store, programID string, now time.Time, approvalClasses []contract.ActionClass) contract.ProgramAgentPolicy {
	t.Helper()
	policy, err := database.SetProgramAgentPolicy(context.Background(), programID, contract.ProgramAgentPolicy{
		AllowedStages:           []string{recon.StageWeb},
		AllowedClasses:          []contract.ActionClass{contract.ActionSafeActive},
		ApprovalRequiredClasses: approvalClasses,
		MaxActionsPerRun:        2, MaxRequestsPerRun: 10, MaxRequestsPerAction: 2, MaxTargetsPerAction: 2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func approvalSubject(t *testing.T, program assessment.Program, revision int64, target string) contract.ApprovalSubject {
	t.Helper()
	subject, err := contract.NewApprovalSubject(program.ID, program.ScopeHash, revision, recon.StageWeb,
		recon.AgentHTTPProbeID, contract.ActionSafeActive, []string{target}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return subject
}

func TestAgentApprovalRequestLifecycle(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 20, 1, 0, 0, 0, time.UTC)
	program := createApprovalProgram(t, database, now)
	policy := createApprovalPolicy(t, database, program.ID, now.Add(time.Second), []contract.ActionClass{contract.ActionSafeActive})
	subject := approvalSubject(t, program, policy.Revision, "https://app.example.test/login")

	approval, err := database.CreateAgentApprovalRequest(ctx, program.ID, subject, "operator", now.Add(time.Hour), now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approval.Status != contract.ApprovalPending || approval.Fingerprint == "" || approval.Subject.ProgramID != program.ID {
		t.Fatalf("created approval is unexpected: %+v", approval)
	}
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, subject, "operator", now.Add(time.Hour), now.Add(3*time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate request error = %v", err)
	}
	usable, err := database.ListUsableAgentApprovals(ctx, program.ID, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(usable) != 0 {
		t.Fatalf("pending approval was reported as usable: %+v", usable)
	}
	listed, err := database.ListAgentApprovals(ctx, program.ID, 10)
	if err != nil || len(listed) != 1 || listed[0].ID != approval.ID {
		t.Fatalf("listed approvals = %+v, err=%v", listed, err)
	}

	approved, err := database.DecideAgentApproval(ctx, program.ID, approval.ID, true, "reviewer", "reviewed scope and budget", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != contract.ApprovalApproved || approved.ReviewedBy != "reviewer" || approved.DecidedAt == nil {
		t.Fatalf("approved record is unexpected: %+v", approved)
	}
	if _, err := database.DecideAgentApproval(ctx, program.ID, approval.ID, false, "reviewer", "late", now.Add(6*time.Minute)); err == nil {
		t.Fatal("approval was decided twice")
	}
	usable, err = database.ListUsableAgentApprovals(ctx, program.ID, now.Add(7*time.Minute))
	if err != nil || len(usable) != 1 || usable[0].ID != approval.ID {
		t.Fatalf("usable approvals = %+v, err=%v", usable, err)
	}
	expired, err := database.ListUsableAgentApprovals(ctx, program.ID, now.Add(2*time.Hour))
	if err != nil || len(expired) != 0 {
		t.Fatalf("expired approval remained usable: %+v, err=%v", expired, err)
	}
	if _, err := database.GetAgentApproval(ctx, "other-program", approval.ID); err == nil {
		t.Fatal("approval was readable by another program")
	}
}

func TestAgentApprovalRejectsStaleOrUnsafeRequests(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.November, 20, 2, 0, 0, 0, time.UTC)
	program := createApprovalProgram(t, database, now)
	policy := createApprovalPolicy(t, database, program.ID, now.Add(time.Second), []contract.ActionClass{contract.ActionSafeActive})
	subject := approvalSubject(t, program, policy.Revision, "https://app.example.test/login")

	outOfScope := subject
	outOfScope.Targets = []string{"https://outside.example.test/"}
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, outOfScope, "operator", now.Add(time.Hour), now.Add(time.Minute)); err == nil {
		t.Fatal("out-of-scope approval request was accepted")
	}
	if _, err := database.CreateAgentApprovalRequest(ctx, "other-program", subject, "operator", now.Add(time.Hour), now.Add(time.Minute)); err == nil {
		t.Fatal("approval request for another program was accepted")
	}
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, subject, "", now.Add(time.Hour), now.Add(time.Minute)); err == nil {
		t.Fatal("approval request without a requester was accepted")
	}
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, subject, "operator", now, now.Add(time.Minute)); err == nil {
		t.Fatal("approval request with an expired window was accepted")
	}
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, subject, "operator", now.Add(48*time.Hour), now.Add(time.Minute)); err == nil {
		t.Fatal("approval expiry beyond the program authorization was accepted")
	}

	noApprovalPolicy := createApprovalPolicy(t, database, program.ID, now.Add(2*time.Minute), nil)
	noApprovalSubject := approvalSubject(t, program, noApprovalPolicy.Revision, "https://app.example.test/login")
	if _, err := database.CreateAgentApprovalRequest(ctx, program.ID, noApprovalSubject, "operator", now.Add(time.Hour), now.Add(3*time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "does not require approval") {
		t.Fatalf("class without approval requirement error = %v", err)
	}

	approvalPolicy := createApprovalPolicy(t, database, program.ID, now.Add(4*time.Minute), []contract.ActionClass{contract.ActionSafeActive})
	approval, err := database.CreateAgentApprovalRequest(ctx, program.ID, approvalSubject(t, program, approvalPolicy.Revision, "https://app.example.test/login"),
		"operator", now.Add(time.Hour), now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// A policy change invalidates an undecided approval.
	createApprovalPolicy(t, database, program.ID, now.Add(6*time.Minute), nil)
	if _, err := database.DecideAgentApproval(ctx, program.ID, approval.ID, true, "reviewer", "stale", now.Add(7*time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale approval decision error = %v", err)
	}

	deniedPolicy := createApprovalPolicy(t, database, program.ID, now.Add(8*time.Minute), []contract.ActionClass{contract.ActionSafeActive})
	deniedRequest, err := database.CreateAgentApprovalRequest(ctx, program.ID, approvalSubject(t, program, deniedPolicy.Revision, "https://app.example.test/login"),
		"operator", now.Add(time.Hour), now.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	denied, err := database.DecideAgentApproval(ctx, program.ID, deniedRequest.ID, false, "reviewer", "insufficient justification", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != contract.ApprovalDenied {
		t.Fatalf("denied approval status = %q", denied.Status)
	}
	usable, err := database.ListUsableAgentApprovals(ctx, program.ID, now.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range usable {
		if item.ID == deniedRequest.ID {
			t.Fatalf("denied approval remained usable: %+v", item)
		}
	}
}
