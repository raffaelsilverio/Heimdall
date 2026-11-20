package assessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxProgramTestAccounts bounds the number of registered test accounts per
	// program. The limit keeps policy evaluation and CLI output deterministic.
	MaxProgramTestAccounts = 32
	// MaxTestAccountIDBytes bounds the stable account identifier.
	MaxTestAccountIDBytes = 64
	// MaxTestAccountIdentityBytes bounds the account identity shown to the
	// operator, such as the test mailbox or application username.
	MaxTestAccountIdentityBytes = 128
	// MaxTestAccountCredentialRefBytes bounds the credential reference. Only a
	// reference is stored; the secret itself never enters the database.
	MaxTestAccountCredentialRefBytes = 160
	// TestAccountCredentialEnvPrefix marks a credential resolved from the
	// process environment when a session is created.
	TestAccountCredentialEnvPrefix = "env:"
)

// DataAccessMode names the only supported user-data policy. Heimdall operates
// exclusively on data owned by registered test accounts.
type DataAccessMode string

const DataAccessTestAccountsOnly DataAccessMode = "test_accounts_only"

// TestAccountRole describes the permissions of an authorized test account.
type TestAccountRole string

const (
	TestAccountRoleUser          TestAccountRole = "user"
	TestAccountRoleAdministrator TestAccountRole = "administrator"
	TestAccountRoleOther         TestAccountRole = "other"
)

// TestAccountStatus controls whether an account may be used for a session.
type TestAccountStatus string

const (
	TestAccountStatusAuthorized TestAccountStatus = "authorized"
	TestAccountStatusRevoked    TestAccountStatus = "revoked"
)

// TestAccountSource records why the account is authorized.
type TestAccountSource string

const (
	TestAccountSourceOwned                TestAccountSource = "owned"
	TestAccountSourceExplicitlyAuthorized TestAccountSource = "explicitly_authorized"
)

// DataAccessPolicy is the per-program rule for user data. The default admits
// only registered test accounts and never authorizes other users' data.
type DataAccessPolicy struct {
	Mode                              DataAccessMode `json:"mode"`
	AllowOwnedTestAccounts            bool           `json:"allow_owned_test_accounts"`
	AllowExplicitlyAuthorizedAccounts bool           `json:"allow_explicitly_authorized_accounts"`
	AllowOtherUsersData               bool           `json:"allow_other_users_data"`
	Revision                          int64          `json:"revision,omitempty"`
}

// TestAccount is the reviewed metadata for one authorized test account. It
// intentionally stores only a credential reference such as
// "env:HEIMDALL_ACCOUNT_ALPHA", never a token, cookie, or password.
type TestAccount struct {
	ID            string            `json:"id"`
	Identity      string            `json:"identity"`
	Role          TestAccountRole   `json:"role"`
	Status        TestAccountStatus `json:"status"`
	Source        TestAccountSource `json:"source"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// DefaultDataAccessPolicy returns the restrictive built-in policy.
func DefaultDataAccessPolicy() DataAccessPolicy {
	return DataAccessPolicy{
		Mode:                              DataAccessTestAccountsOnly,
		AllowOwnedTestAccounts:            true,
		AllowExplicitlyAuthorizedAccounts: true,
	}
}

// NormalizeDataAccessPolicy canonicalizes the policy and rejects attempts to
// widen access to other users' data.
func NormalizeDataAccessPolicy(policy DataAccessPolicy) (DataAccessPolicy, error) {
	mode := DataAccessMode(strings.TrimSpace(string(policy.Mode)))
	if mode == "" {
		mode = DataAccessTestAccountsOnly
	}
	if mode != DataAccessTestAccountsOnly {
		return DataAccessPolicy{}, fmt.Errorf("data access mode %q is not supported; only %q is allowed", mode, DataAccessTestAccountsOnly)
	}
	if policy.AllowOtherUsersData {
		return DataAccessPolicy{}, errors.New("data access policy cannot authorize data belonging to other users")
	}
	if policy.Revision < 0 {
		return DataAccessPolicy{}, errors.New("data access revision must not be negative")
	}
	policy.Mode = mode
	return policy, nil
}

// RevisionOrDefault presents an unset default row as revision 1.
func (policy DataAccessPolicy) RevisionOrDefault() int64 {
	if policy.Revision <= 0 {
		return 1
	}
	return policy.Revision
}

// Equal compares two policies ignoring their revision.
func (policy DataAccessPolicy) Equal(other DataAccessPolicy) bool {
	policy.Revision = 0
	other.Revision = 0
	return policy == other
}

// AuthorizeTestAccount is the single decision point for user-data access. A
// registered account is usable only when it is authorized, its source is
// enabled by the program policy, and the policy still forbids other users'
// data. Future session and browser layers must call this before touching an
// authenticated resource.
func (policy DataAccessPolicy) AuthorizeTestAccount(account TestAccount) error {
	normalizedPolicy, err := NormalizeDataAccessPolicy(policy)
	if err != nil {
		return fmt.Errorf("data access policy is invalid: %w", err)
	}
	account, err = NormalizeTestAccount(account)
	if err != nil {
		return fmt.Errorf("test account is invalid: %w", err)
	}
	if normalizedPolicy.Mode != DataAccessTestAccountsOnly {
		return fmt.Errorf("data access mode %q is not authorized", normalizedPolicy.Mode)
	}
	if account.Status != TestAccountStatusAuthorized {
		return fmt.Errorf("test account %q is %s", account.ID, account.Status)
	}
	switch account.Source {
	case TestAccountSourceOwned:
		if !normalizedPolicy.AllowOwnedTestAccounts {
			return fmt.Errorf("test account %q is owned but owned test accounts are disabled", account.ID)
		}
	case TestAccountSourceExplicitlyAuthorized:
		if !normalizedPolicy.AllowExplicitlyAuthorizedAccounts {
			return fmt.Errorf("test account %q is explicitly authorized but that source is disabled", account.ID)
		}
	default:
		return fmt.Errorf("test account %q has an unsupported source", account.ID)
	}
	return nil
}

// NormalizeTestAccount validates an account record and fills safe defaults for
// status and source when an operator creates a new account.
func NormalizeTestAccount(account TestAccount) (TestAccount, error) {
	account.ID = strings.ToLower(strings.TrimSpace(account.ID))
	if err := validateTestAccountID(account.ID); err != nil {
		return TestAccount{}, err
	}
	identity, err := normalizeTestAccountIdentity(account.Identity)
	if err != nil {
		return TestAccount{}, err
	}
	account.Identity = identity
	role, err := normalizeTestAccountRole(account.Role)
	if err != nil {
		return TestAccount{}, err
	}
	account.Role = role
	status, err := normalizeTestAccountStatus(account.Status)
	if err != nil {
		return TestAccount{}, err
	}
	account.Status = status
	source, err := normalizeTestAccountSource(account.Source)
	if err != nil {
		return TestAccount{}, err
	}
	account.Source = source
	credentialRef, err := normalizeTestAccountCredentialRef(account.CredentialRef)
	if err != nil {
		return TestAccount{}, err
	}
	account.CredentialRef = credentialRef
	return account, nil
}

func normalizeTestAccountIdentity(raw string) (string, error) {
	identity := strings.TrimSpace(raw)
	if identity == "" || len(identity) > MaxTestAccountIdentityBytes {
		return "", fmt.Errorf("test account identity must be between 1 and %d bytes", MaxTestAccountIdentityBytes)
	}
	for _, character := range identity {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("test account identity must use printable ASCII without control characters")
		}
	}
	return identity, nil
}

func normalizeTestAccountRole(raw TestAccountRole) (TestAccountRole, error) {
	role := TestAccountRole(strings.ToLower(strings.TrimSpace(string(raw))))
	switch role {
	case TestAccountRoleUser, TestAccountRoleAdministrator, TestAccountRoleOther:
		return role, nil
	default:
		return "", fmt.Errorf("test account role %q must be user, administrator, or other", role)
	}
}

func normalizeTestAccountStatus(raw TestAccountStatus) (TestAccountStatus, error) {
	status := TestAccountStatus(strings.ToLower(strings.TrimSpace(string(raw))))
	if status == "" {
		status = TestAccountStatusAuthorized
	}
	if status != TestAccountStatusAuthorized && status != TestAccountStatusRevoked {
		return "", fmt.Errorf("test account status %q must be authorized or revoked", status)
	}
	return status, nil
}

func normalizeTestAccountSource(raw TestAccountSource) (TestAccountSource, error) {
	source := TestAccountSource(strings.ToLower(strings.TrimSpace(string(raw))))
	if source == "" {
		source = TestAccountSourceOwned
	}
	if source != TestAccountSourceOwned && source != TestAccountSourceExplicitlyAuthorized {
		return "", fmt.Errorf("test account source %q must be owned or explicitly_authorized", source)
	}
	return source, nil
}

func normalizeTestAccountCredentialRef(raw string) (string, error) {
	credentialRef := strings.TrimSpace(raw)
	if credentialRef == "" {
		return "", nil
	}
	if err := validateCredentialReference(credentialRef); err != nil {
		return "", err
	}
	return credentialRef, nil
}

func validateTestAccountID(id string) error {
	if id == "" || len(id) > MaxTestAccountIDBytes {
		return fmt.Errorf("test account id must be between 1 and %d bytes", MaxTestAccountIDBytes)
	}
	for index, character := range id {
		valid := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '_'))
		if !valid {
			return fmt.Errorf("test account id %q must use lowercase letters, digits, '-' or '_', starting with a letter or digit", id)
		}
	}
	return nil
}

func validateCredentialReference(reference string) error {
	if len(reference) > MaxTestAccountCredentialRefBytes {
		return fmt.Errorf("test account credential reference must not exceed %d bytes", MaxTestAccountCredentialRefBytes)
	}
	if !strings.HasPrefix(reference, TestAccountCredentialEnvPrefix) {
		return fmt.Errorf("test account credential reference must use the %sNAME form; raw credentials are never stored", TestAccountCredentialEnvPrefix)
	}
	name := strings.TrimPrefix(reference, TestAccountCredentialEnvPrefix)
	if name == "" || name[0] < 'A' || name[0] > 'Z' {
		return errors.New("test account credential environment variable must start with an uppercase letter")
	}
	for _, character := range name {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return errors.New("test account credential environment variable must use uppercase letters, digits, or '_'")
	}
	return nil
}
