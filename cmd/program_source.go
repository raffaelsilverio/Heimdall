package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/platform/hackerone"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

type hackerOneSnapshotClient interface {
	FetchSnapshot(context.Context, string) (hackerone.Snapshot, error)
}

type hackerOneSnapshotClientFactory func() (hackerOneSnapshotClient, error)

func newProgramSourceCommand() *cobra.Command {
	command := &cobra.Command{Use: "source", Short: "Sync and review a program's platform source"}
	command.AddCommand(
		newProgramSourceSyncCommand(),
		newProgramSourceShowCommand(),
		newProgramSourceApproveCommand(),
	)
	return command
}

func newProgramSourceSyncCommand() *cobra.Command {
	return newProgramSourceSyncCommandWithFactory(func() (hackerOneSnapshotClient, error) {
		return hackerone.NewClientFromEnv()
	})
}

func newProgramSourceSyncCommandWithFactory(factory hackerOneSnapshotClientFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "sync <program-id>",
		Short: "Fetch a HackerOne program and create a source review",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()

			program, err := database.GetProgram(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if program.SourcePlatform != "hackerone" || program.SourceURL == "" {
				return errors.New("program must have --platform hackerone and a --program-url before source sync")
			}
			client, err := factory()
			if err != nil {
				return err
			}
			fetchContext, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			remote, err := client.FetchSnapshot(fetchContext, program.SourceURL)
			if err != nil {
				return err
			}
			sourceJSON, err := remote.SourceJSON()
			if err != nil {
				return err
			}
			snapshot, changed, err := database.RecordProgramSourceSnapshot(
				cmd.Context(), program.ID, sourceJSON, remote.Scope, remote.Warnings, remote.Blockers, time.Now().UTC(),
			)
			if err != nil {
				return err
			}
			current, err := database.GetProgram(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			changeText := "matches the last approved source"
			if changed {
				changeText = "is new or differs from the last approved source"
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "HackerOne source snapshot %s\nStatus: %s\nSHA-256: %s\nSource %s. Program status: %s.\n",
				snapshot.ID, snapshot.Status, snapshot.SourceHash, changeText, current.Status); err != nil {
				return err
			}
			if snapshot.Status == "pending" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Review with: heimdall program source show %s\n", program.ID)
				if len(snapshot.Blockers) == 0 {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Apply only after review: heimdall program source approve %s --confirm-scope [--port <authorized-port>]\n", program.ID)
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "The candidate has unmapped scope; after review, retain local scope with: heimdall program source approve %s --keep-current-scope\n", program.ID)
				}
			}
			return nil
		},
	}
}

func newProgramSourceShowCommand() *cobra.Command {
	var showJSON bool
	command := &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show the latest stored HackerOne source snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			snapshot, err := database.GetLatestProgramSourceSnapshot(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if showJSON {
				var formatted bytes.Buffer
				if err := json.Indent(&formatted, snapshot.SourceJSON, "", "  "); err != nil {
					return fmt.Errorf("format stored source snapshot: %w", err)
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), formatted.String())
				return err
			}
			return writeProgramSourceSnapshot(cmd.OutOrStdout(), snapshot)
		},
	}
	command.Flags().BoolVar(&showJSON, "json", false, "Print the complete stored platform source JSON")
	return command
}

func writeProgramSourceSnapshot(output io.Writer, snapshot store.ProgramSourceSnapshot) error {
	var data hackerone.SourceData
	if err := json.Unmarshal(snapshot.SourceJSON, &data); err != nil {
		return fmt.Errorf("decode stored HackerOne source: %w", err)
	}
	if _, err := fmt.Fprintf(output, "Snapshot: %s\nProgram: %s (%s)\nStatus: %s\nFetched: %s\nSource SHA-256: %s\n",
		snapshot.ID, safeSourceText(data.Program.Name), safeSourceText(data.Program.Handle), snapshot.Status,
		snapshot.FetchedAt.Format(time.RFC3339), snapshot.SourceHash); err != nil {
		return err
	}
	if snapshot.CandidateScopeHash != "" {
		if _, err := fmt.Fprintf(output, "Candidate scope SHA-256: %s\n", snapshot.CandidateScopeHash); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(output, "Candidate scope: unavailable"); err != nil {
		return err
	}
	if snapshot.AppliedScopeHash != "" {
		if _, err := fmt.Fprintf(output, "Applied scope SHA-256: %s\n", snapshot.AppliedScopeHash); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(output, "Program state: %s\nSubmission state: %s\nOpen scope: %s\nStructured assets: %d\nReport-category exclusions: %d\n",
		safeSourceText(data.Program.State), safeSourceText(data.Program.SubmissionState), boolText(data.Program.OpenScope),
		len(data.StructuredScopes), len(data.ScopeExclusions)); err != nil {
		return err
	}
	if snapshot.ReviewedAt != nil {
		if _, err := fmt.Fprintf(output, "Reviewed: %s\nScope applied: %t\n", snapshot.ReviewedAt.Format(time.RFC3339), snapshot.ScopeApplied); err != nil {
			return err
		}
	}
	if len(snapshot.Blockers) > 0 {
		if _, err := fmt.Fprintln(output, "Scope mapping blockers:"); err != nil {
			return err
		}
		for _, blocker := range snapshot.Blockers {
			if _, err := fmt.Fprintf(output, "  - %s\n", safeSourceText(blocker)); err != nil {
				return err
			}
		}
	}
	if len(snapshot.Warnings) > 0 {
		if _, err := fmt.Fprintln(output, "Notes:"); err != nil {
			return err
		}
		for _, warning := range snapshot.Warnings {
			if _, err := fmt.Fprintf(output, "  - %s\n", safeSourceText(warning)); err != nil {
				return err
			}
		}
	}

	if data.Program.Policy != "" {
		policy := safeSourceText(data.Program.Policy)
		const maxPolicyChars = 12_000
		if utf8.RuneCountInString(policy) > maxPolicyChars {
			policy = string([]rune(policy)[:maxPolicyChars]) + "\n[truncated; use --json to print the full stored source]"
		}
		if _, err := fmt.Fprintf(output, "\nProgram policy:\n%s\n", policy); err != nil {
			return err
		}
	}
	if len(data.ScopeExclusions) > 0 {
		if _, err := fmt.Fprintln(output, "Report-category exclusions (not excluded assets):"); err != nil {
			return err
		}
		const maxExclusionRows = 1000
		for index, exclusion := range data.ScopeExclusions {
			if index >= maxExclusionRows {
				break
			}
			if _, err := fmt.Fprintf(output, "  - %s: %s\n", safeSourceText(exclusion.Category), safeSourceText(exclusion.Details)); err != nil {
				return err
			}
		}
		if len(data.ScopeExclusions) > maxExclusionRows {
			if _, err := fmt.Fprintf(output, "  [showing first %d exclusions; use --json for the complete stored source]\n", maxExclusionRows); err != nil {
				return err
			}
		}
	}
	const maxScopeRows = 1000
	if err := writeProgramSourceScope(output, "\nCANDIDATE EFFECT\tTYPE\tVALUE\tPORTS", snapshot.CandidateScope,
		fmt.Sprintf("[showing first %d candidate entries; use --json for the complete stored source]", maxScopeRows)); err != nil {
		return err
	}
	if err := writeProgramSourceScope(output, "\nAPPROVED EFFECT\tTYPE\tVALUE\tPORTS", snapshot.AppliedScope,
		fmt.Sprintf("[showing first %d approved entries; `heimdall program show %s` prints the complete current scope]", maxScopeRows, snapshot.ProgramID)); err != nil {
		return err
	}
	return nil
}

func writeProgramSourceScope(output io.Writer, heading string, scope *assessment.Scope, overflowMessage string) error {
	if scope == nil {
		return nil
	}
	const maxScopeRows = 1000
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, heading); err != nil {
		return err
	}
	for index, entry := range scope.Entries {
		if index >= maxScopeRows {
			break
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%v\n", entry.Effect, entry.Type, safeSourceText(entry.Value), entry.Ports); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if len(scope.Entries) > maxScopeRows {
		if _, err := fmt.Fprintln(output, overflowMessage); err != nil {
			return err
		}
	}
	return nil
}

func newProgramSourceApproveCommand() *cobra.Command {
	var confirmScope, keepCurrentScope bool
	var portValues []string
	command := &cobra.Command{
		Use:   "approve <program-id>",
		Short: "Resolve a pending source review after explicit confirmation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if confirmScope == keepCurrentScope {
				return errors.New("choose exactly one of --confirm-scope or --keep-current-scope")
			}
			ports, err := parsePorts(portValues)
			if err != nil {
				return fmt.Errorf("parse --port: %w", err)
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			snapshot, scopeChanged, err := database.ApproveProgramSourceSnapshotWithPorts(
				cmd.Context(), args[0], confirmScope, ports, time.Now().UTC(),
			)
			if err != nil {
				return err
			}
			program, err := database.GetProgram(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Approved source snapshot %s. Candidate scope applied: %t; scope revision changed: %t; authorized ports added to broad assets: %v. Program remains %s; activate separately after review.\n",
				snapshot.ID, snapshot.ScopeApplied, scopeChanged, ports, program.Status)
			return err
		},
	}
	command.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Apply the reviewed HackerOne scope candidate to the local program")
	command.Flags().BoolVar(&keepCurrentScope, "keep-current-scope", false, "Acknowledge the source while retaining the existing local scope")
	command.Flags().StringSliceVar(&portValues, "port", nil, "Explicitly authorize a port for imported domain/IP/CIDR assets (repeatable; not read from HackerOne)")
	return command
}

func boolText(value *bool) string {
	if value == nil {
		return "unknown"
	}
	return fmt.Sprint(*value)
}

func safeSourceText(value string) string {
	value = strings.ToValidUTF8(value, "�")
	var result strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || !unicode.IsControl(character) {
			result.WriteRune(character)
		}
	}
	return result.String()
}
