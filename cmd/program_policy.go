package cmd

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent/contract"
	"github.com/spf13/cobra"
)

func newProgramPolicyCommand() *cobra.Command {
	command := &cobra.Command{Use: "policy", Short: "Configure per-program agent action policy"}
	command.AddCommand(newProgramPolicyShowCommand(), newProgramPolicySetCommand(), newProgramPolicyResetCommand())
	return command
}

func newProgramPolicyShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show the deny-by-default agent policy for one program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer func() {
				resultErr = errors.Join(resultErr, database.Close())
			}()
			policy, err := database.GetProgramAgentPolicy(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return writeProgramAgentPolicy(cmd.OutOrStdout(), policy)
		},
	}
}

func newProgramPolicySetCommand() *cobra.Command {
	var stages, classes []string
	var maxActions, maxRequests, maxRequestsPerAction, maxTargets int
	command := &cobra.Command{
		Use:   "set <program-id>",
		Short: "Replace one program's explicit agent allowlist and budgets",
		Long:  "This saves policy only; it does not start an agent or execute tools. Use `program policy reset` to restore deny-all.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			if len(stages) == 0 || len(classes) == 0 {
				return fmt.Errorf("--allow-stage and --allow-class are required; use `program policy reset` for deny-all")
			}
			policy := contract.ProgramAgentPolicy{
				AllowedStages: stages, MaxActionsPerRun: maxActions, MaxRequestsPerRun: maxRequests,
				MaxRequestsPerAction: maxRequestsPerAction, MaxTargetsPerAction: maxTargets,
			}
			for _, class := range classes {
				policy.AllowedClasses = append(policy.AllowedClasses, contract.ActionClass(strings.ToLower(strings.TrimSpace(class))))
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer func() {
				resultErr = errors.Join(resultErr, database.Close())
			}()
			saved, err := database.SetProgramAgentPolicy(cmd.Context(), args[0], policy, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved agent policy revision %d for program %s. No agent actions were executed.\n",
				saved.Revision, args[0])
			return err
		},
	}
	command.Flags().StringSliceVar(&stages, "allow-stage", nil, "Allow an agent stage (repeatable: osint,dns,web,nmap,crawl,ffuf,nuclei)")
	command.Flags().StringSliceVar(&classes, "allow-class", nil, "Allow an action class (repeatable: passive,safe_active,sensitive)")
	command.Flags().IntVar(&maxActions, "max-actions-per-run", 0, "Maximum agent actions in one run")
	command.Flags().IntVar(&maxRequests, "max-requests-per-run", 0, "Maximum request units in one run")
	command.Flags().IntVar(&maxRequestsPerAction, "max-requests-per-action", 0, "Maximum request units in one action")
	command.Flags().IntVar(&maxTargets, "max-targets-per-action", 0, "Maximum targets in one action")
	return command
}

func newProgramPolicyResetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset <program-id>",
		Short: "Restore the program's deny-all agent policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer func() {
				resultErr = errors.Join(resultErr, database.Close())
			}()
			policy, err := database.SetProgramAgentPolicy(cmd.Context(), args[0], contract.ProgramAgentPolicy{}, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Agent policy reset to deny-all for program %s (revision %d).\n", args[0], policy.Revision)
			return err
		},
	}
}

func writeProgramAgentPolicy(output interface{ Write([]byte) (int, error) }, policy contract.ProgramAgentPolicy) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "SETTING\tVALUE"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "REVISION\t%d\nALLOWED STAGES\t%v\nALLOWED CLASSES\t%v\nMAX ACTIONS/RUN\t%d\nMAX REQUESTS/RUN\t%d\nMAX REQUESTS/ACTION\t%d\nMAX TARGETS/ACTION\t%d\n",
		policy.Revision, policy.AllowedStages, policy.AllowedClasses, policy.MaxActionsPerRun,
		policy.MaxRequestsPerRun, policy.MaxRequestsPerAction, policy.MaxTargetsPerAction); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "Policy is configuration only; the agent planner/executor is not enabled.")
	return err
}
