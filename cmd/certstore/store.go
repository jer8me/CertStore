package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certstore"
	"github.com/spf13/cobra"
)

var storeCmd = &cobra.Command{
	Use:   "store cert_path [...cert_path]",
	Args:  cobra.MinimumNArgs(1),
	Short: "Store a certificate",
	Run: func(cmd *cobra.Command, args []string) {
		for _, certPath := range args {
			certificateId, err := certstore.StoreCertificateMySql(certPath, userName, userPassword, dbName)
			if err == nil {
				fmt.Printf("Certificate %s successfully stored (certificate ID=%d)\n", certPath, certificateId)
			} else {
				fmt.Printf("Failed to store certificate %s: %v\n", certPath, err)
			}
		}
	},
}

func init() {
	AddDBCommand(storeCmd)
}
