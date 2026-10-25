package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newChangesCommand() *cobra.Command {
	command := &cobra.Command{Use: "changes", Short: "Inspect recon changes"}
	listCommand := &cobra.Command{
		Use:   "list [program-id]",
		Short: "List persisted change events",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			limit, err := cmd.Flags().GetInt("limit")
			if err != nil {
				return err
			}
			programID := ""
			if len(args) == 1 {
				programID = args[0]
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			events, err := database.ListChangeEvents(cmd.Context(), programID, limit)
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "TIME\tPROGRAM\tCHANGE\tCATEGORY\tASSET\tMATERIAL"); err != nil {
				return err
			}
			for _, event := range events {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%t\n", event.CreatedAt.Format("2006-01-02 15:04:05Z"),
					event.ProgramID, event.ChangeType, event.Category, event.StableKey, event.Material); err != nil {
					return err
				}
			}
			return writer.Flush()
		},
	}
	listCommand.Flags().Int("limit", 100, "Maximum number of events")
	command.AddCommand(listCommand)
	return command
}
