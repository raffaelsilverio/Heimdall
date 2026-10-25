package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newArtifactsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "artifacts <run-id>",
		Short: "List sanitized local artifacts for a recon run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			artifacts, err := database.ListArtifacts(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "PATH\tMEDIA TYPE\tSIZE\tSHA256"); err != nil {
				return err
			}
			for _, artifact := range artifacts {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", artifact.RelativePath, artifact.MediaType, artifact.SizeBytes, artifact.SHA256); err != nil {
					return err
				}
			}
			return writer.Flush()
		},
	}
}
