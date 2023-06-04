package certstore

import (
	"github.com/jer8me/CertStore/pkg/test"
	"github.com/spf13/cobra"
)

const (
	defaultUser = "root"
	defaultDB   = "test"
)

var (
	// Database connection parameters
	userName     string
	userPassword string
	dbName       string

	// Command
	testCmd = &cobra.Command{
		Use:     "test",
		Aliases: []string{"t"},
		Short:   "Test",
		Run: func(cmd *cobra.Command, args []string) {
			test.Test(userName, userPassword, dbName)
		},
	}
)

func init() {
	testCmd.Flags().StringVar(&userName, "dbuser", defaultUser, "Database Username")
	testCmd.Flags().StringVar(&userPassword, "dbpass", "", "Database Password")
	testCmd.Flags().StringVar(&dbName, "dbname", defaultDB, "Database Name")
	testCmd.MarkFlagRequired("dbpass")
	cmd.AddCommand(testCmd)
}
