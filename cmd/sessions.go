package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newSessionCommand() *cobra.Command {
	command := &cobra.Command{Use: "session", Short: "Create and resume persistent conversations"}
	command.AddCommand(newSessionCreateCommand(), newSessionListCommand(), newSessionShowCommand(), newSessionCloseCommand())
	return command
}

func newSessionCreateCommand() *cobra.Command {
	var title string
	command := &cobra.Command{
		Use:   "create <program-id>",
		Short: "Create an interactive session for a program",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			session, err := database.CreateSession(cmd.Context(), args[0], title, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created session %s (%s) for program %s\n", session.ID, session.Kind, session.ProgramID)
			return err
		},
	}
	command.Flags().StringVar(&title, "title", "", "Session title")
	return command
}

func newSessionListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list [program-id]",
		Short: "List interactive and agent-event sessions",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			programID := ""
			if len(args) > 0 {
				programID = args[0]
			}
			sessions, err := database.ListSessions(cmd.Context(), programID, 100)
			if err != nil {
				return err
			}
			return writeSessions(cmd.OutOrStdout(), sessions)
		},
	}
}

func writeSessions(output io.Writer, sessions []store.Session) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tPROGRAM\tKIND\tSTATUS\tTITLE\tUPDATED"); err != nil {
		return err
	}
	for _, session := range sessions {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n", session.ID, session.ProgramID, session.Kind,
			session.Status, session.Title, session.UpdatedAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func newSessionShowCommand() *cobra.Command {
	var limit int
	command := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show session metadata and recent messages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			session, err := database.GetSession(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "ID: %s\nProgram: %s\nKind: %s\nStatus: %s\nTitle: %s\nScope revision hash: %s\nTrigger event: %s\n",
				session.ID, session.ProgramID, session.Kind, session.Status, session.Title, session.ScopeHash, session.TriggerEventID); err != nil {
				return err
			}
			messages, err := database.ListSessionMessages(cmd.Context(), session.ID, limit)
			if err != nil {
				return err
			}
			for _, message := range messages {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "\n[%s] %s\n%s\n", message.CreatedAt.Format(time.RFC3339), message.Role, message.Content); err != nil {
					return err
				}
			}
			return nil
		},
	}
	command.Flags().IntVar(&limit, "limit", 100, "Maximum number of recent messages to show")
	return command
}

func newSessionCloseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "close <session-id>",
		Short: "Close an open interactive session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			if err := database.CloseSession(cmd.Context(), args[0], time.Now().UTC()); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Session %s closed.\n", args[0])
			return err
		},
	}
}
