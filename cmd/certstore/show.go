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
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "Show a certificate",
		RunE:  showCertificate,
	}
)

func showCertificate(cmd *cobra.Command, args []string) error {
	db, err := openMySqlDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Fetch certificate
	cert, err := storage.GetCertificate(db, certificateId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve certificate from database: %v\n", err)
		os.Exit(1)
	}
	certificates.PrintCertificate(os.Stdout, cert)

	return nil
}

func init() {
	addMySqlFlags(showCmd)
	addIdFlag(showCmd, true)
	rootCmd.AddCommand(showCmd)
}
