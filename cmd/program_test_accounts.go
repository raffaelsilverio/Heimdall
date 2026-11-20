package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newProgramAccountsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "accounts",
		Short: "Manage the authorized test accounts of one program",
		Long:  "Accounts store metadata and an optional environment reference only. Credential values are never read, printed, or persisted.",
	}
	command.AddCommand(newProgramAccountsListCommand(), newProgramAccountsAddCommand(), newProgramAccountsRevokeCommand())
	return command
}

func newProgramAccountsListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list <program-id>",
		Short: "List registered test accounts and whether the data policy allows them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				policy, err := database.GetProgramDataAccess(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				accounts, err := database.ListProgramTestAccounts(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return writeProgramTestAccounts(cmd.OutOrStdout(), policy, accounts)
			})
		},
	}
}

func newProgramAccountsAddCommand() *cobra.Command {
	var accountID, identity, role, source, credentialEnv string
	command := &cobra.Command{
		Use:   "add <program-id>",
		Short: "Register one authorized test account",
		Long:  "This saves metadata only; it starts no session and reads no credential. Use --credential-env NAME to reference an environment variable resolved later by the session layer.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			credentialRef := ""
			if strings.TrimSpace(credentialEnv) != "" {
				credentialRef = assessment.TestAccountCredentialEnvPrefix + strings.TrimSpace(credentialEnv)
			}
			account := assessment.TestAccount{
				ID: accountID, Identity: identity, Role: assessment.TestAccountRole(role),
				Source: assessment.TestAccountSource(source), CredentialRef: credentialRef,
			}
			return withProgramStore(cmd, func(database *store.Store) error {
				saved, err := database.AddProgramTestAccount(cmd.Context(), args[0], account, time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Registered test account %s (%s, %s) for program %s. No credential value was read or stored.\n",
					saved.ID, saved.Role, saved.Source, args[0])
				return err
			})
		},
	}
	command.Flags().StringVar(&accountID, "id", "", "Stable account id (lowercase letters, digits, '-' or '_')")
	command.Flags().StringVar(&identity, "identity", "", "Account identity in the application, such as a test mailbox")
	command.Flags().StringVar(&role, "role", string(assessment.TestAccountRoleUser), "Account role: user, administrator, or other")
	command.Flags().StringVar(&source, "source", string(assessment.TestAccountSourceOwned), "Authorization source: owned or explicitly_authorized")
	command.Flags().StringVar(&credentialEnv, "credential-env", "", "Environment variable that will hold the credential (name only)")
	_ = command.MarkFlagRequired("id")
	_ = command.MarkFlagRequired("identity")
	return command
}

func newProgramAccountsRevokeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <program-id> <account-id>",
		Short: "Revoke one test account without deleting its audit record",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				account, err := database.RevokeProgramTestAccount(cmd.Context(), args[0], args[1], time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Test account %s is now %s for program %s.\n", account.ID, account.Status, args[0])
				return err
			})
		},
	}
}

func newProgramDataAccessCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "data-access",
		Short: "Show or tighten the user-data policy of one program",
		Long:  "Only test-account data may be accessed. Data belonging to other users is never authorized by this policy.",
	}
	command.AddCommand(newProgramDataAccessShowCommand(), newProgramDataAccessSetCommand())
	return command
}

func newProgramDataAccessShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show the user-data policy for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				policy, err := database.GetProgramDataAccess(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return writeProgramDataAccess(cmd.OutOrStdout(), policy)
			})
		},
	}
}

func newProgramDataAccessSetCommand() *cobra.Command {
	var allowOwned, allowExplicitlyAuthorized bool
	command := &cobra.Command{
		Use:   "set <program-id>",
		Short: "Tighten the user-data policy for one program",
		Long:  "This saves policy only. Use --allow-owned=false or --allow-explicitly-authorized=false to disable a source; other users' data cannot be enabled.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy := assessment.DefaultDataAccessPolicy()
			policy.AllowOwnedTestAccounts = allowOwned
			policy.AllowExplicitlyAuthorizedAccounts = allowExplicitlyAuthorized
			return withProgramStore(cmd, func(database *store.Store) error {
				saved, err := database.SetProgramDataAccess(cmd.Context(), args[0], policy, time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved data access policy revision %d for program %s. No data was accessed.\n",
					saved.Revision, args[0])
				return err
			})
		},
	}
	command.Flags().BoolVar(&allowOwned, "allow-owned", true, "Allow accounts explicitly marked as owned by the operator")
	command.Flags().BoolVar(&allowExplicitlyAuthorized, "allow-explicitly-authorized", true, "Allow accounts with explicit authorization")
	return command
}

func writeProgramDataAccessSummary(ctx context.Context, output io.Writer, database *store.Store, programID string) error {
	dataAccess, err := database.GetProgramDataAccess(ctx, programID)
	if err != nil {
		return err
	}
	accounts, err := database.ListProgramTestAccounts(ctx, programID)
	if err != nil {
		return err
	}
	usable := 0
	for _, account := range accounts {
		if dataAccess.AuthorizeTestAccount(account) == nil {
			usable++
		}
	}
	_, err = fmt.Fprintf(output, "Data access: %s, test accounts %d (usable %d), other users' data denied, revision %d\n",
		dataAccess.Mode, len(accounts), usable, dataAccess.RevisionOrDefault())
	return err
}

func writeProgramDataAccess(output interface{ Write([]byte) (int, error) }, policy assessment.DataAccessPolicy) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "SETTING\tVALUE"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "REVISION\t%d\nMODE\t%s\nOWNED TEST ACCOUNTS\t%t\nEXPLICITLY AUTHORIZED ACCOUNTS\t%t\nOTHER USERS' DATA\tdenied\n",
		policy.RevisionOrDefault(), policy.Mode, policy.AllowOwnedTestAccounts, policy.AllowExplicitlyAuthorizedAccounts); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "Only registered test-account data is authorized. This policy is configuration only; no session is opened.")
	return err
}

func writeProgramTestAccounts(output interface{ Write([]byte) (int, error) }, policy assessment.DataAccessPolicy, accounts []assessment.TestAccount) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tIDENTITY\tROLE\tSOURCE\tSTATUS\tCREDENTIAL REF\tUSABLE"); err != nil {
		return err
	}
	for _, account := range accounts {
		usable := "yes"
		if err := policy.AuthorizeTestAccount(account); err != nil {
			usable = "no"
		}
		credentialRef := account.CredentialRef
		if credentialRef == "" {
			credentialRef = "(none)"
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", account.ID, account.Identity,
			account.Role, account.Source, account.Status, credentialRef, usable); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "Data access mode: %s; other users' data: denied; accounts: %d\n", policy.Mode, len(accounts))
	return err
}
