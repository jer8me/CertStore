package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
)

var storeCmd = &cobra.Command{
	Use:   "store cert_path [...cert_path]",
	Args:  cobra.MinimumNArgs(1),
	Short: "Store a certificate",
	RunE:  storeCertificate,
}

func storeCertificate(cmd *cobra.Command, args []string) error {
	db, err := openMySqlDB()
	if err != nil {
		return err
	}
	defer db.Close()

	for _, certPath := range args {
		// Read certificate file
		x509cert, err := certificates.ParsePEMFile(certPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read certificate %s: %v\n", certPath, err)
			continue
		}
		// Store certificate in database
		certificateId, err := storage.StoreX509Certificate(db, x509cert)
		if err == nil {
			fmt.Printf("Certificate %s successfully stored (certificate ID=%d)\n", certPath, certificateId)
		} else {
			fmt.Fprintf(os.Stderr, "failed to store certificate %s: %v\n", certPath, err)
		}
	}
	return nil
}

func init() {
	addMySqlFlags(storeCmd)
	rootCmd.AddCommand(storeCmd)
}
