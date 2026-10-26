package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newAgentActionRunsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "action-runs <program-id>",
		Short: "List durable agent action runs for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer closeStoreOnReturn(database, &resultErr)
			runs, err := database.ListAgentActionRuns(cmd.Context(), args[0], 100)
			if err != nil {
				return err
			}
			return writeJSON(cmd.OutOrStdout(), runs)
		},
	}
}

func newAgentActionRunShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "action-run <program-id> <run-id>",
		Short: "Show one action run and its reservations/results",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer closeStoreOnReturn(database, &resultErr)
			run, err := database.GetAgentActionRun(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			actions, err := database.ListAgentActionReservations(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			actionViews := make([]map[string]any, 0, len(actions))
			for _, action := range actions {
				view, err := actionLedgerReservationView(action)
				if err != nil {
					return err
				}
				actionViews = append(actionViews, view)
			}
			return writeJSON(cmd.OutOrStdout(), struct {
				Run     store.AgentActionRun `json:"run"`
				Actions []map[string]any     `json:"actions"`
			}{Run: run, Actions: actionViews})
		},
	}
}

func actionLedgerReservationView(action store.AgentActionReservation) (map[string]any, error) {
	encoded, err := json.Marshal(action)
	if err != nil {
		return nil, fmt.Errorf("encode action reservation view: %w", err)
	}
	var view map[string]any
	if err := json.Unmarshal(encoded, &view); err != nil {
		return nil, fmt.Errorf("decode action reservation view: %w", err)
	}
	var grant, result any
	if err := json.Unmarshal([]byte(action.ProposalJSON), &grant); err != nil {
		return nil, fmt.Errorf("decode stored action grant: %w", err)
	}
	if err := json.Unmarshal([]byte(action.ResultJSON), &result); err != nil {
		return nil, fmt.Errorf("decode stored action result: %w", err)
	}
	delete(view, "authorization_grant_json")
	delete(view, "result_json")
	view["authorization_grant"] = grant
	view["result"] = result
	return view, nil
}

func writeJSON(output interface{ Write([]byte) (int, error) }, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent action ledger output: %w", err)
	}
	_, err = fmt.Fprintln(output, string(encoded))
	return err
}
