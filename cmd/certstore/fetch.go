package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
)

var (
	// Command
	fetchCmd = &cobra.Command{
		Use:   "fetch output_file",
		Args:  cobra.ExactArgs(1),
		Short: "Fetch a certificate and save it to a file",
		RunE:  fetchCertificate,
	}
)

func fetchCertificate(cmd *cobra.Command, args []string) error {
	db, err := openMySqlDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Fetch certificate
	x509Certificate, err := storage.GetX509Certificate(db, certificateId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve certificate from database: %v\n", err)
		os.Exit(1)
	}
	// Save certificate to file
	filename := args[0]
	err = certificates.WritePEMFile(filename, x509Certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write certificate file %s: %v\n", filename, err)
		os.Exit(1)
	}
	return nil
}

func init() {
	addMySqlFlags(fetchCmd)
	addIdFlag(fetchCmd, true)
	rootCmd.AddCommand(fetchCmd)
}
