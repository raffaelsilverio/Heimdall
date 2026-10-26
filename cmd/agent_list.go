package cmd

import (
	"context"
	"io"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newAgentTasksCommand() *cobra.Command {
	return newAgentProgramListCommand(
		"tasks <program-id>", "List agent tasks for one program", "Maximum task records to list",
		func(ctx context.Context, database *store.Store, programID string, limit int) ([]store.AgentTaskStatus, error) {
			return database.ListAgentTaskStatuses(ctx, programID, limit)
		}, func(output io.Writer, tasks []store.AgentTaskStatus) error {
			return writeAgentTaskStatuses(output, tasks)
		},
	)
}

func newAgentProgramListCommand[T any](
	use, short, limitHelp string,
	list func(context.Context, *store.Store, string, int) ([]T, error),
	write func(io.Writer, []T) error,
) *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			items, err := list(cmd.Context(), database, args[0], limit)
			if err != nil {
				return err
			}
			return write(cmd.OutOrStdout(), items)
		},
	}
	command.Flags().IntVar(&limit, "limit", 20, limitHelp+" (1-100)")
	return command
}
