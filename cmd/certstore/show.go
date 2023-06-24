package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certstore"
	"github.com/spf13/cobra"
)

var certificateId int64

var (
	// Command
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "Show a certificate",
		Run: func(cmd *cobra.Command, args []string) {
			err := certstore.ShowCertificate(certificateId, userName, userPassword, dbName)
			if err != nil {
				fmt.Printf("Failed to retrieve certificate: %v\n", err)
			}
		},
	}
)

func init() {
	showCmd.Flags().Int64Var(&certificateId, "id", 0, "Certificate Id")
	showCmd.MarkFlagRequired("id")
	showCmd.Flags().StringVar(&userName, "dbuser", defaultUser, "Database Username")
	showCmd.Flags().StringVar(&userPassword, "dbpass", "", "Database Password")
	showCmd.Flags().StringVar(&dbName, "dbname", defaultDB, "Database Name")
	showCmd.MarkFlagRequired("dbpass")
	cmd.AddCommand(showCmd)
}
