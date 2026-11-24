package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Decision is the explicit result of the policy engine. Every action must map
// to exactly one decision; the executor runs only ALLOW.
type Decision string

const (
	DecisionAllow           Decision = "ALLOW"
	DecisionDeny            Decision = "DENY"
	DecisionRequireApproval Decision = "REQUIRE_APPROVAL"
)

// ActionImpact classifies the operational impact of an action class. The
// mapping is deliberately conservative: sensitive actions are always high
// impact regardless of the tool that implements them.
type ActionImpact string

const (
	ImpactPassive ActionImpact = "passive"
	ImpactLow     ActionImpact = "low"
	ImpactActive  ActionImpact = "active"
	ImpactHigh    ActionImpact = "high"
)

// ActionImpactForClass is the only mapping from a reviewed action class to an
// impact level. Unknown classes have no impact and are rejected.
func ActionImpactForClass(class ActionClass) (ActionImpact, bool) {
	switch class {
	case ActionPassive:
		return ImpactPassive, true
	case ActionSafeActive:
		return ImpactActive, true
	case ActionSensitive:
		return ImpactHigh, true
	default:
		return "", false
	}
}

// ApprovalStatus is the durable state of one scoped approval.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalConsumed ApprovalStatus = "consumed"
	ApprovalExpired  ApprovalStatus = "expired"
)

const (
	// MaxApprovalTargets bounds the target list bound to one approval.
	MaxApprovalTargets = 50_000
	// MaxApprovalActorBytes bounds the requester and reviewer identifiers.
	MaxApprovalActorBytes = 96
	// MaxApprovalNoteBytes bounds the optional reviewer note.
	MaxApprovalNoteBytes = 512
)

// ApprovalSubject is the immutable description of the one operation an
// approval authorizes. It never contains a credential, header value, or
// response body.
type ApprovalSubject struct {
	ProgramID      string       `json:"program_id"`
	ScopeHash      string       `json:"scope_hash"`
	PolicyRevision int64        `json:"policy_revision"`
	Stage          string       `json:"stage"`
	Tool           string       `json:"tool"`
	Class          ActionClass  `json:"class"`
	Impact         ActionImpact `json:"impact"`
	Targets        []string     `json:"targets"`
	RequestBudget  int          `json:"request_budget"`
}

// NewApprovalSubject canonicalizes an operation into the exact form used by
// the policy engine and the approval store.
func NewApprovalSubject(programID, scopeHash string, policyRevision int64, stage, tool string, class ActionClass, targets []string, requestBudget int) (ApprovalSubject, error) {
	subject, err := normalizeApprovalBase(programID, scopeHash, policyRevision, stage, class, requestBudget)
	if err != nil {
		return ApprovalSubject{}, err
	}
	subject.Tool, err = normalizeApprovalTool(tool)
	if err != nil {
		return ApprovalSubject{}, err
	}
	subject.Targets, err = canonicalApprovalTargets(targets)
	if err != nil {
		return ApprovalSubject{}, err
	}
	return subject, nil
}

func normalizeApprovalBase(programID, scopeHash string, policyRevision int64, stage string, class ActionClass, requestBudget int) (ApprovalSubject, error) {
	programID = strings.TrimSpace(programID)
	scopeHash = strings.TrimSpace(scopeHash)
	stage = strings.ToLower(strings.TrimSpace(stage))
	if programID == "" || scopeHash == "" {
		return ApprovalSubject{}, errors.New("approval subject requires a program and scope hash")
	}
	if policyRevision <= 0 {
		return ApprovalSubject{}, errors.New("approval subject requires a positive policy revision")
	}
	registeredClass, ok := ActionClassForStage(stage)
	if !ok || registeredClass != class {
		return ApprovalSubject{}, fmt.Errorf("approval subject stage %q and class %q do not match the registry", stage, class)
	}
	impact, ok := ActionImpactForClass(class)
	if !ok {
		return ApprovalSubject{}, fmt.Errorf("approval subject class %q has no impact level", class)
	}
	if requestBudget < 1 {
		return ApprovalSubject{}, errors.New("approval subject requires a positive request budget")
	}
	return ApprovalSubject{
		ProgramID: programID, ScopeHash: scopeHash, PolicyRevision: policyRevision,
		Stage: stage, Class: class, Impact: impact, RequestBudget: requestBudget,
	}, nil
}

func normalizeApprovalTool(raw string) (string, error) {
	tool := strings.ToLower(strings.TrimSpace(raw))
	if tool == "" || len(tool) > 64 {
		return "", errors.New("approval subject requires a tool id of at most 64 bytes")
	}
	for _, character := range tool {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return "", fmt.Errorf("approval subject tool id %q must use lowercase letters, digits, or underscores", tool)
	}
	return tool, nil
}

func canonicalApprovalTargets(targets []string) ([]string, error) {
	if len(targets) == 0 || len(targets) > MaxApprovalTargets {
		return nil, fmt.Errorf("approval subject requires between 1 and %d targets", MaxApprovalTargets)
	}
	set := make(map[string]struct{}, len(targets))
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" || len(target) > 2048 {
			return nil, errors.New("approval subject contains an empty or oversized target")
		}
		set[target] = struct{}{}
	}
	canonicalTargets := make([]string, 0, len(set))
	for target := range set {
		canonicalTargets = append(canonicalTargets, target)
	}
	sort.Strings(canonicalTargets)
	return canonicalTargets, nil
}

// Fingerprint returns the stable SHA-256 binding of the subject. Two approvals
// can match an action only when every field here is identical.
func (subject ApprovalSubject) Fingerprint() string {
	encoded, err := json.Marshal(subject)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// ActionApproval is one reviewed, scoped authorization. It is single-use:
// the executor consumes it atomically before the request is sent.
type ActionApproval struct {
	ID          string          `json:"id"`
	Subject     ApprovalSubject `json:"subject"`
	Fingerprint string          `json:"fingerprint"`
	Status      ApprovalStatus  `json:"status"`
	RequestedBy string          `json:"requested_by"`
	ReviewedBy  string          `json:"reviewed_by,omitempty"`
	ReviewNote  string          `json:"review_note,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	ConsumedAt  *time.Time      `json:"consumed_at,omitempty"`
}

// EffectiveStatus reports expiry without mutating the stored record. The
// executor treats pending, denied, consumed, and expired approvals as unusable.
func (approval ActionApproval) EffectiveStatus(now time.Time) ApprovalStatus {
	if (approval.Status == ApprovalApproved || approval.Status == ApprovalPending) && !approval.ExpiresAt.After(now.UTC()) {
		return ApprovalExpired
	}
	return approval.Status
}

// Validate checks a stored approval against its canonical subject.
func (approval ActionApproval) Validate() error {
	if strings.TrimSpace(approval.ID) == "" {
		return errors.New("approval id is required")
	}
	canonical, err := NewApprovalSubject(approval.Subject.ProgramID, approval.Subject.ScopeHash,
		approval.Subject.PolicyRevision, approval.Subject.Stage, approval.Subject.Tool, approval.Subject.Class,
		approval.Subject.Targets, approval.Subject.RequestBudget)
	if err != nil {
		return fmt.Errorf("approval subject is invalid: %w", err)
	}
	if canonical.Impact != approval.Subject.Impact || !sameApprovalTargets(canonical.Targets, approval.Subject.Targets) {
		return errors.New("approval subject is not canonical")
	}
	if approval.Fingerprint != canonical.Fingerprint() {
		return errors.New("approval fingerprint does not match its subject")
	}
	if err := approval.validateState(); err != nil {
		return err
	}
	if err := approval.validateActors(); err != nil {
		return err
	}
	if approval.CreatedAt.IsZero() || approval.ExpiresAt.IsZero() || !approval.ExpiresAt.After(approval.CreatedAt) {
		return errors.New("approval validity window is invalid")
	}
	return nil
}

func (approval ActionApproval) validateState() error {
	switch approval.Status {
	case ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalConsumed:
	default:
		return fmt.Errorf("approval status %q is invalid", approval.Status)
	}
	if approval.Status == ApprovalApproved && (approval.ReviewedBy == "" || approval.DecidedAt == nil) {
		return errors.New("approved action requires a reviewer and decision time")
	}
	if approval.Status == ApprovalDenied && (approval.ReviewedBy == "" || approval.DecidedAt == nil) {
		return errors.New("denied action requires a reviewer and decision time")
	}
	return nil
}

func (approval ActionApproval) validateActors() error {
	if err := validateApprovalActor(approval.RequestedBy, "requester"); err != nil {
		return err
	}
	if approval.ReviewedBy != "" {
		if err := validateApprovalActor(approval.ReviewedBy, "reviewer"); err != nil {
			return err
		}
	}
	if len(approval.ReviewNote) > MaxApprovalNoteBytes {
		return fmt.Errorf("approval review note must not exceed %d bytes", MaxApprovalNoteBytes)
	}
	return nil
}

// MatchesGrant reports whether this approval authorizes exactly the supplied
// grant. It is the executor-side cross-check against a tampered approval row.
func (approval ActionApproval) MatchesGrant(programID, scopeHash string, policyRevision int64, stage, tool string, class ActionClass, targets []string, requestBudget int) bool {
	subject, err := NewApprovalSubject(programID, scopeHash, policyRevision, stage, tool, class, targets, requestBudget)
	if err != nil {
		return false
	}
	return approval.Fingerprint == subject.Fingerprint() && approval.Subject.Fingerprint() == subject.Fingerprint()
}

// ValidateApprovalActor exposes the actor validation used by the store and CLI.
func ValidateApprovalActor(actor, role string) error {
	return validateApprovalActor(actor, role)
}

func validateApprovalActor(actor, role string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" || len(actor) > MaxApprovalActorBytes {
		return fmt.Errorf("approval %s must be between 1 and %d bytes", role, MaxApprovalActorBytes)
	}
	for _, character := range actor {
		if character < 0x20 || character > 0x7e {
			return fmt.Errorf("approval %s must use printable ASCII", role)
		}
	}
	return nil
}

func sameApprovalTargets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
