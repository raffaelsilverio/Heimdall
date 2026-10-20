
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "heimdall",
	Short:         "AI harness for Offensive Security",
	Long:          "Heimdall is an extensible AI harness designed for Offensive Security.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}
