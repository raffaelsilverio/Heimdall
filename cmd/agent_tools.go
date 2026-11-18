package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/spf13/cobra"
)

type agentToolCatalogEntry struct {
	recon.AgentToolSpec
	Autonomous bool `json:"autonomous"`
}

func newAgentToolsCommand() *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "tools",
		Short: "List the compiled agent tool catalog, risk class, scope and accounting",
		Long:  "Lists only agent adapters compiled into this binary. It reads no database, calls no provider, and sends no network or shell request.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := agentToolCatalog()
			if asJSON {
				encoded, err := json.MarshalIndent(entries, "", "  ")
				if err != nil {
					return fmt.Errorf("encode agent tool catalog: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "TOOL\tVERSION\tSTAGE\tCLASS\tTARGET TYPES\tSCOPE\tMAX TARGETS\tMAX REQUESTS\tACCOUNTING\tAUTONOMOUS\tARGUMENTS"); err != nil {
				return err
			}
			for _, entry := range entries {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
					entry.ID, entry.Version, entry.Stage, entry.Class,
					strings.Join(entry.TargetTypes, ","), entry.ScopeRule,
					entry.MaxTargets, entry.MaxRequests, entry.Accounting,
					formatAgentToolAutonomy(entry.Autonomous), formatAgentToolArguments(entry.AgentToolSpec)); err != nil {
					return err
				}
			}
			return writer.Flush()
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "Print the full metadata and argument schemas as JSON")
	return command
}

func agentToolCatalog() []agentToolCatalogEntry {
	specs := recon.NewDefaultAgentActionRegistry().Specs()
	entries := make([]agentToolCatalogEntry, 0, len(specs))
	for _, spec := range specs {
		entries = append(entries, agentToolCatalogEntry{AgentToolSpec: spec, Autonomous: spec.AutonomousEligible()})
	}
	return entries
}

func formatAgentToolAutonomy(autonomous bool) string {
	if autonomous {
		return "yes"
	}
	return "no"
}

func formatAgentToolArguments(spec recon.AgentToolSpec) string {
	parts := make([]string, 0, len(spec.Arguments))
	for _, argument := range spec.Arguments {
		required := "optional"
		if argument.Required {
			required = "required"
		}
		part := fmt.Sprintf("%s:%s %s", argument.Name, argument.Type, required)
		if argument.MaxItems > 0 {
			part += fmt.Sprintf(" max_items=%d", argument.MaxItems)
		}
		if argument.MaxLength > 0 {
			part += fmt.Sprintf(" max_length=%d", argument.MaxLength)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}
