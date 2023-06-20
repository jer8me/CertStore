package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certstore"
	"github.com/spf13/cobra"
)

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

var storeCmd = &cobra.Command{
	Use:     "store cert_path [...cert_path]",
	Aliases: []string{"s"},
	Args:    cobra.MinimumNArgs(1),
	Short:   "Store a certificate",
	Run: func(cmd *cobra.Command, args []string) {
		for _, certPath := range args {
			err := certstore.StoreCertificate(certPath, userName, userPassword, dbName)
			if err == nil {
				fmt.Printf("Certificate %s successfully stored\n", certPath)
			} else {
				fmt.Printf("Failed to store certificate %s: %v\n", certPath, err)
			}
		}
	},
}

func init() {
	storeCmd.Flags().StringVar(&userName, "dbuser", defaultUser, "Database Username")
	storeCmd.Flags().StringVar(&userPassword, "dbpass", "", "Database Password")
	storeCmd.Flags().StringVar(&dbName, "dbname", defaultDB, "Database Name")
	storeCmd.MarkFlagRequired("dbpass")
	cmd.AddCommand(storeCmd)
}
