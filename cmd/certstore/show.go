package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
	"strconv"
)

var (
	// Command
	showCmd = &cobra.Command{
		Use:     "show certificate_id",
		Args:    cobra.ExactArgs(1),
		Short:   "Show a certificate",
		PreRunE: checkShowFlags,
		RunE:    showCertificate,
	}
)

func checkShowFlags(_ *cobra.Command, args []string) error {
	var err error
	if certificateId, err = strconv.ParseInt(args[0], 10, 64); err != nil {
		return fmt.Errorf("invalid certificate ID")
	}
	return nil
}

func showCertificate(_ *cobra.Command, _ []string) error {
	db, err := openSQLite()
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		return err
	}

	// Fetch certificate
	cert, err := storage.GetCertificate(db, certificateId)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to retrieve certificate from database: %v\n", err)
		os.Exit(1)
	}
	certificates.PrintCertificate(os.Stdout, cert)

	return nil
}

func init() {
	rootCmd.AddCommand(showCmd)
}
