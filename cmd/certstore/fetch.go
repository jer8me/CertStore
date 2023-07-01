package certstore

import (
	"fmt"
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
	cert, err := storage.GetCertificate(db, certificateId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve certificate from database: %v\n", err)
		os.Exit(1)
	}
	// Save certificate to file
	filename := args[0]
	fmt.Printf("Fetching certificate %s to file %s\n", cert.SerialNumber, filename)

	// TODO save certificate to file

	return nil
}

func init() {
	addMySqlFlags(fetchCmd)
	addIdFlag(fetchCmd, true)
	rootCmd.AddCommand(fetchCmd)
}
