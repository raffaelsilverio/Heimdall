package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/spf13/cobra"
)

func newToolsCommand() *cobra.Command {
	command := &cobra.Command{Use: "tools", Short: "Inspect recon tool integrations"}
	command.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List registered recon adapters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			registry := recon.NewDefaultOSINTRegistry()
			specs := append(registry.Specs(), recon.DNSCollector{}.Specs()...)
			specs = append(specs, (recon.WebCollector{}).ToolSpecs()...)
			specs = append(specs, (recon.NmapCollector{}).ToolSpecs()...)
			specs = append(specs, (recon.KatanaCollector{}).ToolSpecs()...)
			specs = append(specs, (recon.FFUFCollector{}).ToolSpecs()...)
			specs = append(specs, (recon.NucleiCollector{}).ToolSpecs()...)
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "STAGE\tTOOL\tDEFAULT BINARY\tBINARY OVERRIDE"); err != nil {
				return err
			}
			for _, spec := range specs {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", spec.Stage, spec.ID, spec.Binary, spec.BinaryEnv); err != nil {
					return err
				}
			}
			return writer.Flush()
		},
	})
	command.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check installed binaries and versions without running recon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			registry := recon.NewDefaultOSINTRegistry()
			results := registry.Doctor(cmd.Context())
			for _, spec := range (recon.DNSCollector{}).Specs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			for _, spec := range (recon.WebCollector{}).ToolSpecs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			for _, spec := range (recon.NmapCollector{}).ToolSpecs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			for _, spec := range (recon.KatanaCollector{}).ToolSpecs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			for _, spec := range (recon.FFUFCollector{}).ToolSpecs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			for _, spec := range (recon.NucleiCollector{}).ToolSpecs() {
				results = append(results, recon.CheckTool(cmd.Context(), spec, nil, nil))
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "TOOL\tSTATUS\tBINARY\tVERSION"); err != nil {
				return err
			}
			problems := 0
			for _, result := range results {
				if result.Status == "missing" || result.Status == "failed" {
					problems++
				}
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", result.ID, result.Status, result.Binary, result.Version); err != nil {
					return err
				}
			}
			if err := writer.Flush(); err != nil {
				return err
			}
			if problems > 0 {
				return fmt.Errorf("%d registered tool(s) are missing or failed version checks", problems)
			}
			return nil
		},
	})
	return command
}
