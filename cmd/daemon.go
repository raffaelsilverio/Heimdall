package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/agent"
	"github.com/raffaelsilverio/Heimdall/internal/agent/execution"
	"github.com/raffaelsilverio/Heimdall/internal/clock"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/scheduler"
	"github.com/spf13/cobra"
)

func newDaemonCommand() *cobra.Command {
	var runOnce bool
	var pollInterval time.Duration
	command := &cobra.Command{
		Use:   "daemon",
		Short: "Run scheduled recon jobs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			home, err := cmd.Root().PersistentFlags().GetString("home")
			if err != nil {
				return fmt.Errorf("read Heimdall home: %w", err)
			}
			logger := slog.Default()
			daemon := scheduler.Daemon{
				Store:        database,
				Runner:       recon.NewDefaultStageSet(),
				AgentTriage:  agent.TriageWorker{Store: database},
				AgentCycles:  execution.AgentCycleWorker{Store: database, Home: home, Clock: clock.System{}},
				PollInterval: pollInterval,
				Logger:       logger,
				Clock:        clock.System{},
			}
			if runOnce {
				count, err := daemon.RunCycle(cmd.Context(), time.Now().UTC())
				if err != nil {
					return err
				}
				if count == 0 {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), "No due recon jobs, agent triage tasks, or consented adaptive cycles.")
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Processed %d work item(s) (scheduled recon, deterministic triage, and/or consented adaptive cycles).\n", count)
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return daemon.Run(ctx)
		},
	}
	command.Flags().BoolVar(&runOnce, "once", false, "Run one scheduler cycle and exit")
	command.Flags().DurationVar(&pollInterval, "poll-interval", 30*time.Second, "How often to check for due jobs")
	return command
}
