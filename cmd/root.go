package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/raffaelsilverio/Heimdall/internal/config"
	"github.com/raffaelsilverio/Heimdall/internal/logging"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

type configContextKey struct{}

// Execute runs the CLI with a context cancelled by SIGINT or SIGTERM. Commands
// that support cancellation close their in-flight work before returning.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return NewRootCommand().ExecuteContext(ctx)
}

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:               "heimdall",
		Short:             "AI harness for Offensive Security",
		Long:              "Heimdall is an extensible AI harness designed for Offensive Security.",
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: configureRuntime,
	}
	root.PersistentFlags().String("home", config.Home(), "Heimdall data directory")
	root.PersistentFlags().String("config", "", "Config file (default: <home>/"+config.ConfigFileName+")")
	root.PersistentFlags().String("log-level", "", "Log level: debug, info, warn or error (default: info)")
	root.PersistentFlags().String("log-format", "", "Log format: text or json (default: text)")
	root.PersistentFlags().Duration("request-timeout", 0, "Provider request timeout (default: 60s)")
	root.PersistentFlags().Int("context-max-bytes", 0, "Maximum bytes of conversation context sent to a model (default: 262144)")
	root.AddCommand(newRunCommand(), newProgramCommand(), newScheduleCommand(), newDaemonCommand(), newAgentCommand(), newChangesCommand(), newArtifactsCommand(), newToolsCommand(), newSessionCommand(), newMemoryCommand(), newKillSwitchCommand())
	return root
}

func configureRuntime(cmd *cobra.Command, _ []string) error {
	flags := cmd.Root().PersistentFlags()
	home, err := flags.GetString("home")
	if err != nil {
		return fmt.Errorf("read Heimdall home: %w", err)
	}
	configFile, err := flags.GetString("config")
	if err != nil {
		return fmt.Errorf("read config path: %w", err)
	}
	logLevel, err := flags.GetString("log-level")
	if err != nil {
		return fmt.Errorf("read log level: %w", err)
	}
	logFormat, err := flags.GetString("log-format")
	if err != nil {
		return fmt.Errorf("read log format: %w", err)
	}
	requestTimeout, err := flags.GetDuration("request-timeout")
	if err != nil {
		return fmt.Errorf("read request timeout: %w", err)
	}
	contextMaxBytes, err := flags.GetInt("context-max-bytes")
	if err != nil {
		return fmt.Errorf("read context budget: %w", err)
	}
	cfg, err := config.Load(config.Options{
		Home:            home,
		ConfigFile:      configFile,
		LogLevel:        logLevel,
		LogFormat:       logFormat,
		RequestTimeout:  requestTimeout,
		ContextMaxBytes: contextMaxBytes,
	})
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	logger, err := logging.New(cmd.ErrOrStderr(), cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	slog.SetDefault(logger)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.SetContext(context.WithValue(ctx, configContextKey{}, cfg))
	return nil
}

// loadProviderConfig returns the runtime configuration with command-level
// provider and model overrides applied.
func loadProviderConfig(cmd *cobra.Command, provider, model string) (config.Config, error) {
	if base, ok := cmd.Context().Value(configContextKey{}).(config.Config); ok {
		return base.WithOverrides(provider, model)
	}
	flags := cmd.Root().PersistentFlags()
	home, err := flags.GetString("home")
	if err != nil {
		return config.Config{}, fmt.Errorf("read Heimdall home: %w", err)
	}
	configFile, err := flags.GetString("config")
	if err != nil {
		return config.Config{}, fmt.Errorf("read config path: %w", err)
	}
	requestTimeout, err := flags.GetDuration("request-timeout")
	if err != nil {
		return config.Config{}, fmt.Errorf("read request timeout: %w", err)
	}
	contextMaxBytes, err := flags.GetInt("context-max-bytes")
	if err != nil {
		return config.Config{}, fmt.Errorf("read context budget: %w", err)
	}
	return config.Load(config.Options{
		Home:            home,
		ConfigFile:      configFile,
		Provider:        provider,
		Model:           model,
		RequestTimeout:  requestTimeout,
		ContextMaxBytes: contextMaxBytes,
	})
}

func openStore(cmd *cobra.Command) (*store.Store, error) {
	home, err := cmd.Root().PersistentFlags().GetString("home")
	if err != nil {
		return nil, fmt.Errorf("read Heimdall home: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return nil, fmt.Errorf("home directory is empty")
	}
	return store.Open(cmd.Context(), filepath.Join(home, "heimdall.db"))
}

func closeStoreOnReturn(database *store.Store, resultErr *error) {
	*resultErr = errors.Join(*resultErr, database.Close())
}
