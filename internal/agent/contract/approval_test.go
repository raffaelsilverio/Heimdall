package contract

import (
	"strings"
	"testing"
	"time"
)

func TestApprovalSubjectCanonicalizesAndFingerprints(t *testing.T) {
	subject, err := NewApprovalSubject(" program-a ", "scope-hash", 3, " WEB ",
		" NATIVE_HTTP_PROBE ", ActionSafeActive,
		[]string{"https://app.example.test/b", "https://app.example.test/a", "https://app.example.test/a"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if subject.ProgramID != "program-a" || subject.Stage != "web" || subject.Tool != "native_http_probe" ||
		subject.Class != ActionSafeActive || subject.Impact != ImpactActive || subject.RequestBudget != 2 {
		t.Fatalf("subject was not canonicalized: %+v", subject)
	}
	if len(subject.Targets) != 2 || subject.Targets[0] != "https://app.example.test/a" ||
		subject.Targets[1] != "https://app.example.test/b" {
		t.Fatalf("targets were not sorted and deduplicated: %v", subject.Targets)
	}
	fingerprint := subject.Fingerprint()
	if len(fingerprint) != 64 || strings.ContainsAny(fingerprint, "ABCDEF") {
		t.Fatalf("fingerprint is not lowercase SHA-256 hex: %q", fingerprint)
	}
	reordered, err := NewApprovalSubject(subject.ProgramID, subject.ScopeHash, subject.PolicyRevision,
		subject.Stage, subject.Tool, subject.Class, []string{subject.Targets[1], subject.Targets[0]}, subject.RequestBudget)
	if err != nil {
		t.Fatal(err)
	}
	if reordered.Fingerprint() != fingerprint {
		t.Fatal("fingerprint depends on target ordering")
	}
	subject.RequestBudget = 3
	if subject.Fingerprint() == fingerprint {
		t.Fatal("fingerprint did not change with the request budget")
	}
}

func TestApprovalSubjectRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name    string
		subject func() (ApprovalSubject, error)
		want    string
	}{
		{"missing program", func() (ApprovalSubject, error) {
			return NewApprovalSubject("", "scope", 1, "web", "native_http_probe", ActionSafeActive, []string{"https://a.test"}, 1)
		}, "program and scope"},
		{"missing revision", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 0, "web", "native_http_probe", ActionSafeActive, []string{"https://a.test"}, 1)
		}, "policy revision"},
		{"class mismatch", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 1, "web", "native_http_probe", ActionSensitive, []string{"https://a.test"}, 1)
		}, "do not match"},
		{"unsafe tool", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 1, "web", "native-http", ActionSafeActive, []string{"https://a.test"}, 1)
		}, "lowercase letters"},
		{"missing target", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 1, "web", "native_http_probe", ActionSafeActive, nil, 1)
		}, "between 1"},
		{"empty target", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 1, "web", "native_http_probe", ActionSafeActive, []string{" "}, 1)
		}, "empty or oversized"},
		{"zero budget", func() (ApprovalSubject, error) {
			return NewApprovalSubject("program", "scope", 1, "web", "native_http_probe", ActionSafeActive, []string{"https://a.test"}, 0)
		}, "request budget"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.subject(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestActionApprovalValidationAndEffectiveStatus(t *testing.T) {
	now := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	subject, err := NewApprovalSubject("program", "scope", 1, "web", "native_http_probe",
		ActionSafeActive, []string{"https://app.example.test/"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	approval := ActionApproval{
		ID: "approval-1", Subject: subject, Fingerprint: subject.Fingerprint(), Status: ApprovalPending,
		RequestedBy: "operator", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := approval.Validate(); err != nil {
		t.Fatalf("pending approval is invalid: %v", err)
	}
	if status := approval.EffectiveStatus(now.Add(2 * time.Hour)); status != ApprovalExpired {
		t.Fatalf("expired pending approval status = %q", status)
	}
	decidedAt := now.Add(time.Minute)
	approval.Status = ApprovalApproved
	approval.ReviewedBy = "reviewer"
	approval.DecidedAt = &decidedAt
	if err := approval.Validate(); err != nil {
		t.Fatalf("approved approval is invalid: %v", err)
	}
	if !approval.MatchesGrant("program", "scope", 1, "web", "native_http_probe", ActionSafeActive,
		[]string{"https://app.example.test/"}, 1) {
		t.Fatal("approval did not match its exact grant")
	}
	if approval.MatchesGrant("program", "scope", 1, "web", "native_tls_probe", ActionSafeActive,
		[]string{"https://app.example.test/"}, 1) {
		t.Fatal("approval matched a different tool")
	}
	approval.Fingerprint = strings.Repeat("e", 64)
	if err := approval.Validate(); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("tampered fingerprint error = %v", err)
	}
}
