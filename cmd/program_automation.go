package cmd

import (
	"fmt"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newProgramAutomationCommand() *cobra.Command {
	command := &cobra.Command{Use: "automation", Short: "Configure explicit, expiring per-program agent-cycle consent"}
	command.AddCommand(newProgramAutomationShowCommand(), newProgramAutomationSetCommand(), newProgramAutomationDisableCommand())
	return command
}

func newProgramAutomationShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show a program's deny-by-default autonomous-cycle consent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			consent, err := database.GetProgramAgentAutomation(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return writeJSON(cmd.OutOrStdout(), consent)
		},
	}
}

func newProgramAutomationSetCommand() *cobra.Command {
	var providerName, modelName, expiresAtValue, reviewedBy, reason string
	var maxCycles, maxRequests, maxSteps int
	var allowModelContextEgress, allowActiveRequests, includeMemory bool
	command := &cobra.Command{
		Use:   "set <program-id>",
		Short: "Enable bounded daemon-cycle consent for one program",
		Long:  "Persist time-bounded consent for sending structured program context to one configured provider/model and for active requests. This does not launch or backfill a cycle; future eligible material events may enter the daemon queue.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !allowModelContextEgress || !allowActiveRequests {
				return fmt.Errorf("explicitly pass --allow-model-context-egress and --allow-active-requests to enable automation")
			}
			expiresAt, err := time.Parse(time.RFC3339, expiresAtValue)
			if err != nil {
				return fmt.Errorf("parse --context-egress-expires-at as RFC3339: %w", err)
			}
			cfg, err := config.LoadConfig(providerName, modelName)
			if err != nil {
				return fmt.Errorf("validate planner provider/model: %w", err)
			}
			if cfg.Model == "" {
				return fmt.Errorf("planner model is required; provide --model")
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			consent, err := database.SetProgramAgentAutomation(cmd.Context(), args[0], store.ProgramAgentAutomation{
				Enabled: true, PlannerProvider: cfg.Provider, PlannerModel: cfg.Model,
				ContextEgressExpiresAt: &expiresAt, AllowModelContextEgress: allowModelContextEgress,
				AllowActiveRequests: allowActiveRequests, IncludeMemory: includeMemory,
				MaxCyclesPerDay: maxCycles, MaxRequestsPerDay: maxRequests, MaxStepsPerCycle: maxSteps,
				ReviewedBy: reviewedBy, ReviewReason: reason,
			}, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved automation consent revision %d for program %s. No cycle was launched or backfilled.\n",
				consent.Revision, args[0])
			return err
		},
	}
	command.Flags().StringVar(&providerName, "provider", "", "Planner provider to which consent applies (openai or opencode)")
	command.Flags().StringVar(&modelName, "model", "", "Planner model to which consent applies")
	command.Flags().StringVar(&expiresAtValue, "context-egress-expires-at", "", "Consent expiry in RFC3339; at most 90 days and no later than program authorization")
	command.Flags().BoolVar(&allowModelContextEgress, "allow-model-context-egress", false, "Explicitly allow structured scope/policy/result context to leave this machine")
	command.Flags().BoolVar(&allowActiveRequests, "allow-active-requests", false, "Explicitly allow bounded native HTTP HEAD requests under current scope/policy")
	command.Flags().BoolVar(&includeMemory, "include-memory", false, "Also allow bounded fresh memory notes from this program in planner context")
	command.Flags().IntVar(&maxCycles, "max-cycles-per-day", 0, "Maximum automatically started cycles per UTC day (1-50)")
	command.Flags().IntVar(&maxRequests, "max-requests-per-day", 0, "Maximum native HTTP requests reserved per UTC day (1-10000)")
	command.Flags().IntVar(&maxSteps, "max-steps-per-cycle", 0, "Maximum adaptive steps per cycle (1-20 and within policy action budget)")
	command.Flags().StringVar(&reviewedBy, "reviewed-by", "", "Operator granting this persistent consent")
	command.Flags().StringVar(&reason, "reason", "", "Required audit rationale for the consent")
	for _, name := range []string{"provider", "model", "context-egress-expires-at", "allow-model-context-egress", "allow-active-requests", "max-cycles-per-day", "max-requests-per-day", "max-steps-per-cycle", "reviewed-by", "reason"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func newProgramAutomationDisableCommand() *cobra.Command {
	var reviewedBy, reason string
	command := &cobra.Command{
		Use:   "disable <program-id>",
		Short: "Revoke persisted adaptive-cycle consent for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			consent, err := database.DisableProgramAgentAutomation(cmd.Context(), args[0], reviewedBy, reason, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Disabled agent automation for program %s (revision %d).\n", args[0], consent.Revision)
			return err
		},
	}
	command.Flags().StringVar(&reviewedBy, "reviewed-by", "", "Operator revoking the consent")
	command.Flags().StringVar(&reason, "reason", "", "Required audit rationale for revocation")
	_ = command.MarkFlagRequired("reviewed-by")
	_ = command.MarkFlagRequired("reason")
	return command
}
