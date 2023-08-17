package main

import (
	"database/sql"
	"github.com/spf13/cobra"
)

func newRootCommand(db *sql.DB) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "certstore",
		Version: version,
		Short:   "CertStore - a X.509 certificate management tool",
	}
	cmd.AddCommand(
		newFetchCommand(db),
		newListCommand(db),
		newSaveCommand(db),
		newShowCommand(db),
		newStoreCommand(db),
	)
	return cmd
}
