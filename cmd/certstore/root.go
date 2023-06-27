package certstore

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const version = "0.0.1"

const (
	defaultUser = "root"
	defaultDB   = "certstore"
)

var (
	// Database connection parameters
	userName     string
	userPassword string
	dbName       string
)

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

func AddDBCommand(subcmd *cobra.Command) {
	subcmd.Flags().StringVar(&userName, "dbuser", defaultUser, "Database Username")
	subcmd.Flags().StringVar(&userPassword, "dbpass", "", "Database Password")
	subcmd.Flags().StringVar(&dbName, "dbname", defaultDB, "Database Name")
	subcmd.MarkFlagRequired("dbpass")
	rootCmd.AddCommand(subcmd)
}
