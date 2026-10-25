package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func Execute() error {
	return NewRootCommand().Execute()
}

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "heimdall",
		Short:         "AI harness for Offensive Security",
		Long:          "Heimdall is an extensible AI harness designed for Offensive Security.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("home", defaultHome(), "Heimdall data directory")
	root.AddCommand(newRunCommand(), newProgramCommand(), newScheduleCommand(), newDaemonCommand(), newAgentCommand(), newChangesCommand(), newArtifactsCommand(), newToolsCommand(), newSessionCommand(), newMemoryCommand())
	return root
}

func defaultHome() string {
	if configured := strings.TrimSpace(os.Getenv("HEIMDALL_HOME")); configured != "" {
		return configured
	}
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", ".heimdall")
	}
	return filepath.Join(configDirectory, "heimdall")
}

func openStore(cmd *cobra.Command) (*store.Store, error) {
	home, err := cmd.Root().PersistentFlags().GetString("home")
	if err != nil {
		return nil, fmt.Errorf("read Heimdall home: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return nil, fmt.Errorf("Heimdall home directory is empty")
	}
	return store.Open(cmd.Context(), filepath.Join(home, "heimdall.db"))
}
