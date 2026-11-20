package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newProgramRequestProfileCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "request-profile",
		Short: "Configure the mandatory HTTP User-Agent and headers for one program",
		Long:  "These rules are applied by the request middleware to outbound HTTP requests. Credential and framing headers are rejected; test-account credentials use a separate mechanism.",
	}
	command.AddCommand(
		newProgramRequestProfileShowCommand(),
		newProgramRequestProfileSetCommand(),
		newProgramRequestProfileResetCommand(),
	)
	return command
}

func newProgramRequestProfileShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show the request profile applied to outbound HTTP requests",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				profile, err := database.GetProgramRequestProfile(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return writeProgramRequestProfile(cmd.OutOrStdout(), profile)
			})
		},
	}
}

func newProgramRequestProfileSetCommand() *cobra.Command {
	var userAgent string
	var headers []string
	command := &cobra.Command{
		Use:   "set <program-id>",
		Short: "Replace the program's User-Agent and mandatory headers",
		Long:  "This saves configuration only; it starts no scan and sends no request. An empty --user-agent restores the built-in value. No --header clears the header list.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := assessment.RequestProfile{UserAgent: userAgent}
			for _, raw := range headers {
				name, value, found := strings.Cut(raw, "=")
				if !found || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
					return fmt.Errorf("--header %q must use a non-empty Name=Value form", raw)
				}
				profile.Headers = append(profile.Headers, assessment.RequestHeader{Name: name, Value: value})
			}
			return withProgramStore(cmd, func(database *store.Store) error {
				saved, err := database.SetProgramRequestProfile(cmd.Context(), args[0], profile, time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved request profile revision %d for program %s. No request was sent.\n",
					saved.Revision, args[0])
				return err
			})
		},
	}
	command.Flags().StringVar(&userAgent, "user-agent", "", "User-Agent applied to outbound HTTP requests (empty restores the built-in value)")
	command.Flags().StringArrayVar(&headers, "header", nil, "Mandatory header in Name=Value form (repeatable)")
	return command
}

func newProgramRequestProfileResetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset <program-id>",
		Short: "Restore the built-in User-Agent and clear mandatory headers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withProgramStore(cmd, func(database *store.Store) error {
				profile, err := database.SetProgramRequestProfile(cmd.Context(), args[0], assessment.RequestProfile{}, time.Now().UTC())
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Request profile reset to the built-in User-Agent for program %s (revision %d).\n", args[0], profile.Revision)
				return err
			})
		},
	}
}

func writeProgramRequestProfile(output interface{ Write([]byte) (int, error) }, profile assessment.RequestProfile) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "USER-AGENT\t%s\nREVISION\t%d\n", profile.UserAgent, profile.Revision); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if len(profile.Headers) == 0 {
		_, err := fmt.Fprintln(output, "HEADERS\t(none)")
		return err
	}
	writer = tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "HEADER\tVALUE"); err != nil {
		return err
	}
	for _, header := range profile.Headers {
		if _, err := fmt.Fprintf(writer, "%s\t%s\n", header.Name, header.Value); err != nil {
			return err
		}
	}
	return writer.Flush()
}
