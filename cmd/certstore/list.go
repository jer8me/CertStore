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

var searchFilters storage.SearchFilter

func listCertificates(cmd *cobra.Command, args []string) error {
	db, err := openSQLite()
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		return err
	}

	// Fetch certificate
	certs, err := storage.GetCertificates(db, &searchFilters)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve certificates from database: %v\n", err)
		os.Exit(1)
	}
	certificates.PrintCertificates(os.Stdout, certs)

	return nil
}

func init() {
	// Add all filter flags
	listCmd.Flags().StringVar(&searchFilters.San, "san", "", "Certificate SAN")
	listCmd.Flags().StringVar(&searchFilters.Serial, "serial", "", "Certificate Serial Number")
	listCmd.Flags().StringVar(&searchFilters.Issuer, "issuer", "", "Certificate Issuer Fields")
	listCmd.Flags().StringVar(&searchFilters.IssuerCn, "issuer-cn", "", "Certificate Issuer Common Name")
	listCmd.Flags().StringVar(&searchFilters.IssuerCountry, "issuer-country", "", "Certificate Issuer Country")
	listCmd.Flags().StringVar(&searchFilters.IssuerLocality, "issuer-locality", "", "Certificate Issuer Locality")
	listCmd.Flags().StringVar(&searchFilters.IssuerState, "issuer-state", "", "Certificate Issuer State or Province")
	listCmd.Flags().StringVar(&searchFilters.IssuerStreet, "issuer-street", "", "Certificate Issuer Street Address")
	listCmd.Flags().StringVar(&searchFilters.IssuerOrg, "issuer-org", "", "Certificate Organization")
	listCmd.Flags().StringVar(&searchFilters.IssuerOrgUnit, "issuer-org-unit", "", "Certificate Organization Unit")
	listCmd.Flags().StringVar(&searchFilters.IssuerPostalCode, "issuer-postal-code", "", "Certificate Postal Code")
	listCmd.Flags().StringVar(&searchFilters.Subject, "subject", "", "Certificate Subject Fields")
	listCmd.Flags().StringVar(&searchFilters.SubjectCn, "subject-cn", "", "Certificate Subject Common Name")
	listCmd.Flags().StringVar(&searchFilters.SubjectCountry, "subject-country", "", "Certificate Subject Country")
	listCmd.Flags().StringVar(&searchFilters.SubjectLocality, "subject-locality", "", "Certificate Subject Locality")
	listCmd.Flags().StringVar(&searchFilters.SubjectState, "subject-state", "", "Certificate Subject State or Province")
	listCmd.Flags().StringVar(&searchFilters.SubjectStreet, "subject-street", "", "Certificate Subject Street Address")
	listCmd.Flags().StringVar(&searchFilters.SubjectOrg, "subject-org", "", "Certificate Subject Organization")
	listCmd.Flags().StringVar(&searchFilters.SubjectOrgUnit, "subject-org-unit", "", "Certificate Subject Organization Unit")
	listCmd.Flags().StringVar(&searchFilters.SubjectPostalCode, "subject-postal-code", "", "Certificate Subject Postal Code")

	rootCmd.AddCommand(listCmd)
}
