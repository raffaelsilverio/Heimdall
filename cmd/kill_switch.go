package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newKillSwitchCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "kill-switch",
		Short: "Inspect or change the global execution kill switch",
		Long:  "The kill switch is a global, durable halt independent of any program or policy. While engaged, no agent action, approval consumption, scheduled recon run, or adaptive cycle may start or send a request.",
	}
	command.AddCommand(newKillSwitchStatusCommand(), newKillSwitchSetCommand(true), newKillSwitchSetCommand(false))
	return command
}

func newKillSwitchStatusCommand() *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "status",
		Short: "Show the current global kill-switch state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				state, err := database.GetKillSwitch(cmd.Context())
				if err != nil {
					return err
				}
				if jsonOutput {
					encoded, err := json.MarshalIndent(state, "", "  ")
					if err != nil {
						return fmt.Errorf("encode kill switch: %w", err)
					}
					_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
					return err
				}
				changedAt := "-"
				if !state.ChangedAt.IsZero() {
					changedAt = state.ChangedAt.Format(time.RFC3339)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Engaged: %t\nReason: %s\nChanged by: %s\nChanged at: %s\nRevision: %d\n",
					state.Engaged, safeSourceText(state.Reason), safeSourceText(state.ChangedBy), changedAt, state.Revision)
				return err
			})
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "Emit the kill-switch state as JSON")
	return command
}

func newKillSwitchSetCommand(engage bool) *cobra.Command {
	var actor, reason string
	use := "release"
	short := "Release the global kill switch"
	if engage {
		use = "engage"
		short = "Engage the global kill switch and stop all execution"
	}
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				state, err := database.SetKillSwitch(cmd.Context(), engage, actor, reason, time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Kill switch engaged: %t\nReason: %s\nChanged by: %s\nRevision: %d\n",
					state.Engaged, safeSourceText(state.Reason), safeSourceText(state.ChangedBy), state.Revision)
				return err
			})
		},
	}
	command.Flags().StringVar(&actor, "by", "", "Operator identifier recorded in the audit trail")
	command.Flags().StringVar(&reason, "reason", "", "Printable reason for the transition")
	_ = command.MarkFlagRequired("by")
	_ = command.MarkFlagRequired("reason")
	return command
}
