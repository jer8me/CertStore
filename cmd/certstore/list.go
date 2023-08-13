package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List certificates",
	PreRunE: checkListFlags,
	RunE:    listCertificates,
}

var searchFilters storage.SearchFilter

// Cobra does not parse dates directly
// Use a temporary string variable to store the command line argument
// The data will be parsed and adjusted in the PreRun function
var expireBefore string

func checkListFlags(_ *cobra.Command, _ []string) error {
	for _, algo := range searchFilters.PublicKeyAlgorithms {
		if !common.ValidPublicKeyAlgorithm(algo) {
			return fmt.Errorf("%s is not a valid public key algorithm", algo)
		}
	}
	if expireBefore != "" {
		date, err := time.ParseInLocation(time.DateOnly, expireBefore, time.UTC)
		if err != nil {
			return fmt.Errorf("invalid expiration date, must be yyyy-mm-dd")
		}
		// Add one day to the value to get our upper bound
		// The date to find must be strictly less than our upper bound
		searchFilters.ExpireBefore = date.AddDate(0, 0, 1)
	}
	return nil
}

func listCertificates(_ *cobra.Command, _ []string) error {
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
	listCmd.Flags().StringVarP(&expireBefore, "expire-before", "e", "", "Certificate Expires On or Before Date (yyyy-mm-dd)")
	listCmd.Flags().StringVar(&searchFilters.San, "san", "", "Certificate SAN")
	listCmd.Flags().StringVar(&searchFilters.Serial, "serial", "", "Certificate Serial Number")
	listCmd.Flags().StringVarP(&searchFilters.Issuer, "issuer", "i", "", "Certificate Issuer Fields")
	listCmd.Flags().StringVar(&searchFilters.IssuerCn, "issuer-cn", "", "Certificate Issuer Common Name")
	listCmd.Flags().StringVar(&searchFilters.IssuerCountry, "issuer-country", "", "Certificate Issuer Country")
	listCmd.Flags().StringVar(&searchFilters.IssuerLocality, "issuer-locality", "", "Certificate Issuer Locality")
	listCmd.Flags().StringVar(&searchFilters.IssuerState, "issuer-state", "", "Certificate Issuer State or Province")
	listCmd.Flags().StringVar(&searchFilters.IssuerStreet, "issuer-street", "", "Certificate Issuer Street Address")
	listCmd.Flags().StringVar(&searchFilters.IssuerOrg, "issuer-org", "", "Certificate Organization")
	listCmd.Flags().StringVar(&searchFilters.IssuerOrgUnit, "issuer-org-unit", "", "Certificate Organization Unit")
	listCmd.Flags().StringVar(&searchFilters.IssuerPostalCode, "issuer-postal-code", "", "Certificate Postal Code")
	listCmd.Flags().StringVarP(&searchFilters.Subject, "subject", "s", "", "Certificate Subject Fields")
	listCmd.Flags().StringVar(&searchFilters.SubjectCn, "subject-cn", "", "Certificate Subject Common Name")
	listCmd.Flags().StringVar(&searchFilters.SubjectCountry, "subject-country", "", "Certificate Subject Country")
	listCmd.Flags().StringVar(&searchFilters.SubjectLocality, "subject-locality", "", "Certificate Subject Locality")
	listCmd.Flags().StringVar(&searchFilters.SubjectState, "subject-state", "", "Certificate Subject State or Province")
	listCmd.Flags().StringVar(&searchFilters.SubjectStreet, "subject-street", "", "Certificate Subject Street Address")
	listCmd.Flags().StringVar(&searchFilters.SubjectOrg, "subject-org", "", "Certificate Subject Organization")
	listCmd.Flags().StringVar(&searchFilters.SubjectOrgUnit, "subject-org-unit", "", "Certificate Subject Organization Unit")
	listCmd.Flags().StringVar(&searchFilters.SubjectPostalCode, "subject-postal-code", "", "Certificate Subject Postal Code")
	listCmd.Flags().StringSliceVarP(&searchFilters.PublicKeyAlgorithms, "public-key-algorithms", "p", nil, "Certificate Public Key Algorithms ("+common.PublicKeyAlgorithms+")")
	listCmd.Flags().BoolVar(&searchFilters.IsCA, "is-ca", false, "Certificate is a CA")
	listCmd.Flags().BoolVar(&searchFilters.NotCA, "not-ca", false, "Certificate is not a CA")
	listCmd.Flags().BoolVar(&searchFilters.HasPrivateKey, "has-private-key", false, "Certificate has a Private Key")
	listCmd.Flags().BoolVar(&searchFilters.NoPrivateKey, "no-private-key", false, "Certificate does not have a Private Key")

	listCmd.MarkFlagsMutuallyExclusive("is-ca", "not-ca")
	listCmd.MarkFlagsMutuallyExclusive("has-private-key", "no-private-key")
	rootCmd.AddCommand(listCmd)
}
