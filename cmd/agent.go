package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newAgentCommand() *cobra.Command {
	command := &cobra.Command{Use: "agent", Short: "Process supervised agent-event work"}
	command.AddCommand(newAgentTriageCommand(), newAgentTasksCommand(), newAgentRetryTriageCommand(), newAgentPlanCommand(), newAgentProposeCommand(), newAgentExecuteCommand(), newAgentCycleCommand(), newAgentCycleJobsCommand(), newAgentCycleJobReviewCommand(), newAgentActionRunsCommand(), newAgentActionRunShowCommand(), newAgentActionReviewCommand(), newAgentToolsCommand(), newAgentApprovalsCommand())
	return command
}

func newAgentRetryTriageCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "retry-triage <program-id> <task-id>",
		Short: "Retry a failed deterministic event triage task",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			if err := database.RetryAgentEventTriage(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Requeued triage for task %s in program %s.\n", args[1], args[0])
			return err
		},
	}
}

func writeAgentTaskStatuses(output io.Writer, tasks []store.AgentTaskStatus) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "TASK\tEVENT\tTASK STATUS\tTRIAGE\tTRIAGE/AGENT TRIES\tCREATED\tTRIAGED\tERROR"); err != nil {
		return err
	}
	for _, task := range tasks {
		triaged := "-"
		if task.TriagedAt != nil {
			triaged = task.TriagedAt.Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\t%s\n",
			task.ID, task.EventID, task.Status, task.TriageStatus, task.TriageAttempts, task.Attempts,
			task.CreatedAt.Format(time.RFC3339), triaged, safeSourceText(task.TriageError)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func newAgentTriageCommand() *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   "triage",
		Short: "Prepare deterministic handoffs for pending material recon events",
		Long:  "This command records a per-program memory and a structured session brief. It makes no LLM calls and executes no tools or scans.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			worker := agent.TriageWorker{Store: database, BatchSize: limit}
			processed, err := worker.RunCycle(cmd.Context(), time.Now().UTC())
			if err != nil {
				return err
			}
			if processed == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "No pending material recon events to triage.")
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Prepared %d deterministic event handoff(s); no scans or LLM calls were made.\n", processed)
			return err
		},
	}
	command.Flags().IntVar(&limit, "limit", 10, "Maximum pending event handoffs to prepare (1-50)")
	return command
}
