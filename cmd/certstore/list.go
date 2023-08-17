package main

import (
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func newListCommand(db *sql.DB) *cobra.Command {

	// Cobra does not parse dates directly
	// Use a temporary string variable to store the command line argument
	// The data will be parsed and adjusted in the PreRun function
	var expireBefore string

	var searchFilters storage.SearchFilter

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		PreRunE: func(_ *cobra.Command, args []string) error {
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
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			// Fetch certificate
			certs, err := storage.GetCertificates(db, &searchFilters)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to retrieve certificates from database: %v\n", err)
				os.Exit(1)
			}
			certificates.PrintCertificates(os.Stdout, certs)

			return nil
		},
	}
	f := cmd.Flags()
	// Add all filter flags
	f.StringVarP(&expireBefore, "expire-before", "e", "", "Certificate Expires On or Before Date (yyyy-mm-dd)")
	f.StringVar(&searchFilters.San, "san", "", "Certificate SAN")
	f.StringVar(&searchFilters.Serial, "serial", "", "Certificate Serial Number")
	f.StringVarP(&searchFilters.Issuer, "issuer", "i", "", "Certificate Issuer Fields")
	f.StringVar(&searchFilters.IssuerCn, "issuer-cn", "", "Certificate Issuer Common Name")
	f.StringVar(&searchFilters.IssuerCountry, "issuer-country", "", "Certificate Issuer Country")
	f.StringVar(&searchFilters.IssuerLocality, "issuer-locality", "", "Certificate Issuer Locality")
	f.StringVar(&searchFilters.IssuerState, "issuer-state", "", "Certificate Issuer State or Province")
	f.StringVar(&searchFilters.IssuerStreet, "issuer-street", "", "Certificate Issuer Street Address")
	f.StringVar(&searchFilters.IssuerOrg, "issuer-org", "", "Certificate Organization")
	f.StringVar(&searchFilters.IssuerOrgUnit, "issuer-org-unit", "", "Certificate Organization Unit")
	f.StringVar(&searchFilters.IssuerPostalCode, "issuer-postal-code", "", "Certificate Postal Code")
	f.StringVarP(&searchFilters.Subject, "subject", "s", "", "Certificate Subject Fields")
	f.StringVar(&searchFilters.SubjectCn, "subject-cn", "", "Certificate Subject Common Name")
	f.StringVar(&searchFilters.SubjectCountry, "subject-country", "", "Certificate Subject Country")
	f.StringVar(&searchFilters.SubjectLocality, "subject-locality", "", "Certificate Subject Locality")
	f.StringVar(&searchFilters.SubjectState, "subject-state", "", "Certificate Subject State or Province")
	f.StringVar(&searchFilters.SubjectStreet, "subject-street", "", "Certificate Subject Street Address")
	f.StringVar(&searchFilters.SubjectOrg, "subject-org", "", "Certificate Subject Organization")
	f.StringVar(&searchFilters.SubjectOrgUnit, "subject-org-unit", "", "Certificate Subject Organization Unit")
	f.StringVar(&searchFilters.SubjectPostalCode, "subject-postal-code", "", "Certificate Subject Postal Code")
	f.StringSliceVarP(&searchFilters.PublicKeyAlgorithms, "public-key-algorithms", "p", nil, "Certificate Public Key Algorithms ("+common.PublicKeyAlgorithms+")")
	f.BoolVar(&searchFilters.IsCA, "is-ca", false, "Certificate is a CA")
	f.BoolVar(&searchFilters.NotCA, "not-ca", false, "Certificate is not a CA")
	f.BoolVar(&searchFilters.HasPrivateKey, "has-private-key", false, "Certificate has a Private Key")
	f.BoolVar(&searchFilters.NoPrivateKey, "no-private-key", false, "Certificate does not have a Private Key")

	cmd.MarkFlagsMutuallyExclusive("is-ca", "not-ca")
	cmd.MarkFlagsMutuallyExclusive("has-private-key", "no-private-key")

	return cmd
}
