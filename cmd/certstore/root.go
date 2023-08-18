package main

import (
	"github.com/spf13/cobra"
)

func newRootCommand(cs CertStore) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "certstore",
		Version: version,
		Short:   "CertStore - a X.509 certificate management tool",
	}
	cmd.AddCommand(
		newFetchCommand(cs),
		newListCommand(cs),
		newSaveCommand(cs),
		newShowCommand(cs),
		newStoreCommand(cs),
	)
	return cmd
}
