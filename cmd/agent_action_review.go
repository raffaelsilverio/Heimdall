package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newAgentActionReviewCommand() *cobra.Command {
	var decision, reviewer, note string
	command := &cobra.Command{
		Use:   "action-review <program-id> <action-run-id> <action-id>",
		Short: "Record an operator assessment for an uncertain action without replaying it",
		Long:  "This records a review decision and note but leaves the action status uncertain. It never refunds budgets or retries the action. Once all uncertain actions in the run are reviewed, the run closes as failed.",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			decision = strings.ToLower(strings.TrimSpace(decision))
			if decision != "assessed_completed" && decision != "assessed_not_executed" {
				return fmt.Errorf("--decision must be assessed_completed or assessed_not_executed")
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer closeStoreOnReturn(database, &resultErr)
			if err := database.ResolveUncertainAgentAction(cmd.Context(), args[0], args[1], args[2], decision, reviewer, note, time.Now().UTC()); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Recorded review for action %s (%s). The action remains uncertain and was not replayed.\n", args[2], decision)
			return err
		},
	}
	command.Flags().StringVar(&decision, "decision", "", "Operator assessment: assessed_completed or assessed_not_executed")
	command.Flags().StringVar(&reviewer, "reviewed-by", "", "Operator identity for the audit record")
	command.Flags().StringVar(&note, "note", "", "Required rationale/evidence for the operator assessment")
	_ = command.MarkFlagRequired("decision")
	_ = command.MarkFlagRequired("reviewed-by")
	_ = command.MarkFlagRequired("note")
	return command
}
