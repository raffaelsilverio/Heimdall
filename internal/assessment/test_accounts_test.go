package assessment

import (
	"strings"
	"testing"
)

func TestNormalizeDataAccessPolicyDefaultsAndRejectsWidening(t *testing.T) {
	policy, err := NormalizeDataAccessPolicy(DefaultDataAccessPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != DataAccessTestAccountsOnly || !policy.AllowOwnedTestAccounts ||
		!policy.AllowExplicitlyAuthorizedAccounts || policy.AllowOtherUsersData {
		t.Fatalf("default data access policy is unexpected: %+v", policy)
	}
	if policy.RevisionOrDefault() != 1 {
		t.Fatalf("unset revision should default to 1: %+v", policy)
	}
	tests := []struct {
		name   string
		policy DataAccessPolicy
		want   string
	}{
		{name: "other users", policy: DataAccessPolicy{AllowOtherUsersData: true}, want: "other users"},
		{name: "unknown mode", policy: DataAccessPolicy{Mode: "all_data"}, want: "not supported"},
		{name: "negative revision", policy: DataAccessPolicy{Revision: -1}, want: "must not be negative"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeDataAccessPolicy(test.policy); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NormalizeDataAccessPolicy error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestNormalizeTestAccountCanonicalizesMetadata(t *testing.T) {
	account, err := NormalizeTestAccount(TestAccount{
		ID: " Test-User_1 ", Identity: " test-user@example.test ",
		Role: "USER", CredentialRef: " env:HEIMDALL_ACCOUNT_TEST_USER ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.ID != "test-user_1" || account.Identity != "test-user@example.test" ||
		account.Role != TestAccountRoleUser || account.Status != TestAccountStatusAuthorized ||
		account.Source != TestAccountSourceOwned || account.CredentialRef != "env:HEIMDALL_ACCOUNT_TEST_USER" {
		t.Fatalf("test account was not normalized: %+v", account)
	}
	explicit, err := NormalizeTestAccount(TestAccount{
		ID: "researcher", Identity: "researcher@example.test",
		Role: "administrator", Source: "EXPLICITLY_AUTHORIZED",
	})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Source != TestAccountSourceExplicitlyAuthorized || explicit.Role != TestAccountRoleAdministrator {
		t.Fatalf("explicit account was not normalized: %+v", explicit)
	}
}

func TestNormalizeTestAccountRejectsUnsafeMetadata(t *testing.T) {
	tests := []struct {
		name    string
		account TestAccount
		want    string
	}{
		{name: "missing id", account: TestAccount{Identity: "user@example.test", Role: "user"}, want: "id must be"},
		{name: "id with space", account: TestAccount{ID: "test user", Identity: "user@example.test", Role: "user"}, want: "lowercase"},
		{name: "id starting with separator", account: TestAccount{ID: "-test", Identity: "user@example.test", Role: "user"}, want: "lowercase"},
		{name: "missing identity", account: TestAccount{ID: "test", Role: "user"}, want: "identity must be"},
		{name: "newline identity", account: TestAccount{ID: "test", Identity: "user\nadmin", Role: "user"}, want: "printable ASCII"},
		{name: "invalid role", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "root"}, want: "role"},
		{name: "invalid status", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "user", Status: "pending"}, want: "status"},
		{name: "invalid source", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "user", Source: "borrowed"}, want: "source"},
		{name: "raw credential", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "user", CredentialRef: "Bearer secret"}, want: "raw credentials are never stored"},
		{name: "invalid env name", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "user", CredentialRef: "env:token-value"}, want: "uppercase"},
		{name: "empty env name", account: TestAccount{ID: "test", Identity: "user@example.test", Role: "user", CredentialRef: "env:"}, want: "start with an uppercase"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeTestAccount(test.account); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NormalizeTestAccount error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAuthorizeTestAccountEnforcesTheDataAccessPolicy(t *testing.T) {
	owned := TestAccount{
		ID: "owned", Identity: "owned@example.test", Role: TestAccountRoleUser,
		Status: TestAccountStatusAuthorized, Source: TestAccountSourceOwned,
	}
	explicit := TestAccount{
		ID: "explicit", Identity: "explicit@example.test", Role: TestAccountRoleUser,
		Status: TestAccountStatusAuthorized, Source: TestAccountSourceExplicitlyAuthorized,
	}
	if err := DefaultDataAccessPolicy().AuthorizeTestAccount(owned); err != nil {
		t.Fatalf("default policy rejected an owned test account: %v", err)
	}
	if err := DefaultDataAccessPolicy().AuthorizeTestAccount(explicit); err != nil {
		t.Fatalf("default policy rejected an explicitly authorized test account: %v", err)
	}
	disabledOwned := DefaultDataAccessPolicy()
	disabledOwned.AllowOwnedTestAccounts = false
	if err := disabledOwned.AuthorizeTestAccount(owned); err == nil || !strings.Contains(err.Error(), "owned test accounts are disabled") {
		t.Fatalf("disabled owned source error = %v", err)
	}
	if err := disabledOwned.AuthorizeTestAccount(explicit); err != nil {
		t.Fatalf("disabled owned source blocked an explicit account: %v", err)
	}
	disabledExplicit := DefaultDataAccessPolicy()
	disabledExplicit.AllowExplicitlyAuthorizedAccounts = false
	if err := disabledExplicit.AuthorizeTestAccount(explicit); err == nil || !strings.Contains(err.Error(), "source is disabled") {
		t.Fatalf("disabled explicit source error = %v", err)
	}
	revoked := owned
	revoked.Status = TestAccountStatusRevoked
	if err := DefaultDataAccessPolicy().AuthorizeTestAccount(revoked); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked account error = %v", err)
	}
	unsafe := DefaultDataAccessPolicy()
	unsafe.AllowOtherUsersData = true
	if err := unsafe.AuthorizeTestAccount(owned); err == nil || !strings.Contains(err.Error(), "cannot authorize") {
		t.Fatalf("unsafe policy error = %v", err)
	}
}
