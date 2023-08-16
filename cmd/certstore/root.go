package certstore

import (
	"github.com/spf13/cobra"
	"os"
)

const version = "0.0.1"

var rootCmd = &cobra.Command{
	Use:     "CertStore",
	Version: version,
	Short:   "CertStore - a X.509 certificate management tool",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Exit with an error code
		os.Exit(1)
	}
}
