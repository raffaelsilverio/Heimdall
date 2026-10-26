package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newMemoryCommand() *cobra.Command {
	command := &cobra.Command{Use: "memory", Short: "Manage strictly program-scoped agent memory"}
	command.AddCommand(newMemoryAddCommand(), newMemoryListCommand(), newMemorySearchCommand(), newMemoryShowCommand(), newMemoryArchiveCommand(), newMemoryRestoreCommand())
	return command
}

func newMemoryAddCommand() *cobra.Command {
	var kind, title, content, sourceKind, sourceID, scopeHash, sourceHash, expiresAtValue, supersedesID string
	var confidence float64
	var verified, contentStdin bool
	command := &cobra.Command{
		Use:   "add <program-id>",
		Short: "Record a memory item for exactly one program",
		Long:  "Memory is always scoped to one program. Source references are checked to belong to that same program. Use --content-stdin to avoid putting sensitive notes in shell history.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, expiresAt, verifiedAt, err := prepareMemoryInput(cmd, content, contentStdin, expiresAtValue, verified)
			if err != nil {
				return err
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			memory, err := database.AddProgramMemory(cmd.Context(), store.AddProgramMemoryParams{
				ProgramID: args[0], Kind: kind, Title: title, Content: content,
				SourceKind: sourceKind, SourceID: sourceID, ScopeHash: scopeHash, SourceHash: sourceHash,
				Confidence: confidence, VerifiedAt: verifiedAt, ExpiresAt: expiresAt, SupersedesID: supersedesID,
			}, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Stored %s memory %s for program %s.\n", memory.Kind, memory.ID, memory.ProgramID)
			return err
		},
	}
	command.Flags().StringVar(&kind, "kind", "", "Memory kind (fact, hypothesis, negative_result, decision, finding_candidate, finding_verified, procedure, handoff)")
	command.Flags().StringVar(&title, "title", "", "Short memory title")
	command.Flags().StringVar(&content, "content", "", "Memory content")
	command.Flags().BoolVar(&contentStdin, "content-stdin", false, "Read memory content from stdin instead of a command-line argument")
	command.Flags().StringVar(&sourceKind, "source-kind", "operator", "Provenance kind (operator, run, event, session, source_snapshot, artifact)")
	command.Flags().StringVar(&sourceID, "source-id", "", "Provenance record ID; non-operator sources must belong to this program")
	command.Flags().StringVar(&scopeHash, "scope-hash", "", "Scope revision associated with this memory; derived from cited run/event/session when possible")
	command.Flags().StringVar(&sourceHash, "source-hash", "", "Source revision hash associated with this memory")
	command.Flags().Float64Var(&confidence, "confidence", 1, "Confidence from 0.0 to 1.0")
	command.Flags().BoolVar(&verified, "verified", false, "Record that an operator verified this memory at creation time")
	command.Flags().StringVar(&expiresAtValue, "expires-at", "", "Optional expiry in RFC3339 format")
	command.Flags().StringVar(&supersedesID, "supersedes", "", "Active memory ID of the same kind in this program to supersede")
	_ = command.MarkFlagRequired("kind")
	_ = command.MarkFlagRequired("title")
	return command
}

func prepareMemoryInput(cmd *cobra.Command, content string, contentStdin bool, expiresAtValue string, verified bool) (string, *time.Time, *time.Time, error) {
	if !contentStdin && strings.TrimSpace(content) == "" {
		return "", nil, nil, fmt.Errorf("memory content is required; provide --content or --content-stdin")
	}
	if contentStdin {
		if content != "" {
			return "", nil, nil, fmt.Errorf("use either --content or --content-stdin, not both")
		}
		body, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), (64<<10)+1))
		if err != nil {
			return "", nil, nil, fmt.Errorf("read memory content from stdin: %w", err)
		}
		content = string(body)
	}
	var expiresAt *time.Time
	if strings.TrimSpace(expiresAtValue) != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAtValue)
		if err != nil {
			return "", nil, nil, fmt.Errorf("parse --expires-at as RFC3339: %w", err)
		}
		expiresAt = &parsed
	}
	var verifiedAt *time.Time
	if verified {
		now := time.Now().UTC()
		verifiedAt = &now
	}
	return content, expiresAt, verifiedAt, nil
}

func newMemoryListCommand() *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   "list <program-id>",
		Short: "List active, unexpired memory for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer func() {
				resultErr = errors.Join(resultErr, database.Close())
			}()
			memories, err := database.ListProgramMemories(cmd.Context(), args[0], limit, time.Now().UTC())
			if err != nil {
				return err
			}
			return writeProgramMemories(cmd.OutOrStdout(), memories)
		},
	}
	command.Flags().IntVar(&limit, "limit", 20, "Maximum memory records to list (1-100)")
	return command
}

func newMemorySearchCommand() *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   "search <program-id> <query>",
		Short: "Search local memory inside exactly one program",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			memories, err := database.SearchProgramMemories(cmd.Context(), args[0], args[1], limit, time.Now().UTC())
			if err != nil {
				return err
			}
			return writeProgramMemories(cmd.OutOrStdout(), memories)
		},
	}
	command.Flags().IntVar(&limit, "limit", 20, "Maximum search results (1-100)")
	return command
}

func newMemoryShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id> <memory-id>",
		Short: "Show one memory record, scoped to its program",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			memory, err := database.GetProgramMemory(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			return writeProgramMemory(cmd.OutOrStdout(), memory)
		},
	}
}

func newMemoryArchiveCommand() *cobra.Command {
	return newMemoryStateCommand(
		"archive", "Archive one memory record without deleting its provenance", "Archived",
		func(ctx context.Context, database *store.Store, programID, memoryID string, now time.Time) error {
			return database.ArchiveProgramMemory(ctx, programID, memoryID, now)
		},
	)
}

func newMemoryRestoreCommand() *cobra.Command {
	return newMemoryStateCommand(
		"restore", "Restore an archived, unexpired memory record", "Restored",
		func(ctx context.Context, database *store.Store, programID, memoryID string, now time.Time) error {
			return database.RestoreProgramMemory(ctx, programID, memoryID, now)
		},
	)
}

func newMemoryStateCommand(
	action, short, pastTense string,
	transition func(context.Context, *store.Store, string, string, time.Time) error,
) *cobra.Command {
	return &cobra.Command{
		Use:   action + " <program-id> <memory-id>",
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			if err := transition(cmd.Context(), database, args[0], args[1], time.Now().UTC()); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s memory %s in program %s.\n", pastTense, args[1], args[0])
			return err
		},
	}
}

func writeProgramMemories(output io.Writer, memories []store.ProgramMemory) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tKIND\tCONFIDENCE\tTITLE\tPROVENANCE\tFRESHNESS"); err != nil {
		return err
	}
	for _, memory := range memories {
		freshness := memoryFreshness(memory)
		provenance := memory.SourceKind
		if memory.SourceID != "" {
			provenance += ":" + memory.SourceID
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%.2f\t%s\t%s\t%s\n", memory.ID, memory.Kind,
			memory.Confidence, safeSourceText(memory.Title), safeSourceText(provenance), freshness); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writeProgramMemory(output io.Writer, memory store.ProgramMemory) error {
	if _, err := fmt.Fprintf(output, "ID: %s\nProgram: %s\nKind: %s\nStatus: %s\nTitle: %s\nConfidence: %.2f\nProvenance: %s %s\nScope hash: %s\nSource hash: %s\nObserved: %s\n",
		memory.ID, memory.ProgramID, memory.Kind, memory.Status, safeSourceText(memory.Title), memory.Confidence,
		memory.SourceKind, safeSourceText(memory.SourceID), memory.ScopeHash, memory.SourceHash, memory.ObservedAt.Format(time.RFC3339)); err != nil {
		return err
	}
	if memory.VerifiedAt != nil {
		if _, err := fmt.Fprintf(output, "Verified: %s\n", memory.VerifiedAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if memory.ExpiresAt != nil {
		if _, err := fmt.Fprintf(output, "Expires: %s\n", memory.ExpiresAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if memory.SupersedesID != "" {
		if _, err := fmt.Fprintf(output, "Supersedes: %s\n", memory.SupersedesID); err != nil {
			return err
		}
	}
	if freshness := memoryFreshness(memory); freshness != "current" {
		if _, err := fmt.Fprintf(output, "Freshness: %s\n", freshness); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "\n%s\n", safeSourceText(memory.Content))
	return err
}

func memoryFreshness(memory store.ProgramMemory) string {
	var flags []string
	if memory.ScopeStale {
		flags = append(flags, "old-scope")
	}
	if memory.SourceStale {
		flags = append(flags, "unapproved-or-old-source")
	}
	if memory.SourceReviewPending {
		flags = append(flags, "source-review-pending")
	}
	if len(flags) == 0 {
		return "current"
	}
	return strings.Join(flags, ",")
}
