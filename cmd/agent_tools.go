package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/spf13/cobra"
)

func newAgentToolsCommand() *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "tools",
		Short: "List the compiled agent tool catalog and argument schemas",
		Long:  "Lists only agent adapters compiled into this binary. It reads no database, calls no provider, and sends no network or shell request.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			specs := recon.NewDefaultAgentActionRegistry().Specs()
			if asJSON {
				encoded, err := json.MarshalIndent(specs, "", "  ")
				if err != nil {
					return fmt.Errorf("encode agent tool catalog: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "TOOL\tSTAGE\tCLASS\tMAX TARGETS\tACCOUNTING\tARGUMENTS"); err != nil {
				return err
			}
			for _, spec := range specs {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%s\t%s\n",
					spec.ID, spec.Stage, spec.Class, spec.MaxTargets, spec.Accounting, formatAgentToolArguments(spec)); err != nil {
					return err
				}
			}
			return writer.Flush()
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "Print the full metadata and argument schemas as JSON")
	return command
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
