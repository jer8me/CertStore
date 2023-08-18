package main

import (
	"github.com/spf13/cobra"
	"os"
)

func newRootCommand(cs CertStore) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "certstore",
		Version:       version,
		Short:         "CertStore - a X.509 certificate management tool",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		newFetchCommand(cs),
		newListCommand(cs),
		newSaveCommand(cs),
		newShowCommand(cs, os.Stdout),
		newStoreCommand(cs),
	)
	return cmd
}
