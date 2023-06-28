package certstore

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

const version = "0.0.1"

var viperCfg = viper.New()

var rootCmd = &cobra.Command{
	Use:     "CertStore",
	Version: version,
	Short:   "CertStore - a X.509 certificate management tool",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while executing CLI: %s", err)
		os.Exit(1)
	}
}
