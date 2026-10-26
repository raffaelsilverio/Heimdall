package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newAgentCycleJobsCommand() *cobra.Command {
	return newAgentProgramListCommand(
		"cycle-jobs <program-id>", "List consented adaptive cycle jobs for one program", "Maximum cycle jobs to list",
		func(ctx context.Context, database *store.Store, programID string, limit int) ([]store.AgentCycleJob, error) {
			return database.ListAgentCycleJobs(ctx, programID, limit)
		}, func(output io.Writer, jobs []store.AgentCycleJob) error {
			return writeJSON(output, jobs)
		},
	)
}

func newAgentCycleJobReviewCommand() *cobra.Command {
	var decision, reviewer, note string
	command := &cobra.Command{
		Use:   "cycle-review <program-id> <task-id>",
		Short: "Record an operator assessment for a cycle job that needs review",
		Long:  "Review is append-once, records operator/rationale, and never retries a cycle. If an action run exists, any uncertain actions must be reviewed first with agent action-review.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			decision = strings.ToLower(strings.TrimSpace(decision))
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			if err := database.ResolveAgentCycleJobReview(cmd.Context(), args[0], args[1], decision, reviewer, note, time.Now().UTC()); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Recorded cycle-job review %s for task %s; no cycle was replayed.\n", decision, args[1])
			return err
		},
	}
	command.Flags().StringVar(&decision, "decision", "", "Operator assessment: assessed_completed, assessed_failed, or assessed_no_action")
	command.Flags().StringVar(&reviewer, "reviewed-by", "", "Operator identity for the audit record")
	command.Flags().StringVar(&note, "note", "", "Required rationale/evidence for the operator assessment")
	_ = command.MarkFlagRequired("decision")
	_ = command.MarkFlagRequired("reviewed-by")
	_ = command.MarkFlagRequired("note")
	return command
}
