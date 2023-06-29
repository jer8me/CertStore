package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificates",
	RunE:  listCertificates,
}

func listCertificates(cmd *cobra.Command, args []string) error {
	db, err := openMySqlDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Fetch certificate
	certs, err := storage.GetCertificates(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve certificates from database: %v\n", err)
		os.Exit(1)
	}
	certificates.PrintCertificates(os.Stdout, certs)

	return nil
}

func init() {
	addMySqlFlags(listCmd)
	rootCmd.AddCommand(listCmd)
}
