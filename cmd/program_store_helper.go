package cmd

import (
	"errors"

	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

// withProgramStore opens the command's store and always closes it, joining
// close errors with the command result. It keeps read-only program commands
// free of repeated lifecycle boilerplate.
func withProgramStore(cmd *cobra.Command, action func(*store.Store) error) (resultErr error) {
	database, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, database.Close())
	}()
	return action(database)
}
