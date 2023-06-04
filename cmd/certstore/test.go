package certstore

import (
	"github.com/jer8me/CertStore/pkg/test"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:     "test",
	Aliases: []string{"t"},
	Short:   "Test",
	Run: func(cmd *cobra.Command, args []string) {
		test.Test()
	},
}

func init() {
	cmd.AddCommand(testCmd)
}
