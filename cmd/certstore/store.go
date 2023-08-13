package certstore

import (
	"crypto/x509"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
)

var storeCmd = &cobra.Command{
	Use:     "store pem_file [...pem_file]",
	Args:    cobra.MinimumNArgs(1),
	Short:   "Store a certificate and/or a private key",
	PreRunE: parseFiles,
	RunE:    storeCertificate,
}

var certs []*x509.Certificate
var privateKeys []*common.PrivateKey

func parseFiles(_ *cobra.Command, args []string) error {
	for _, filepath := range args {
		// Read PEM file
		c, pk, err := certificates.ParsePEMFile(filepath)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to read file %s: %v\n", filepath, err)
			continue
		}
		certs = append(certs, c...)
		privateKeys = append(privateKeys, pk...)
	}
	// If we found one or more private keys, we need a password parameter
	if (len(privateKeys) > 0) && (password == "") {
		return fmt.Errorf("a password must be provided when storing private keys")
	}
	return nil
}

func storeCertificate(_ *cobra.Command, _ []string) error {
	db, err := openSQLite()
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		return err
	}

	// Store certificates in database
	for _, cert := range certs {
		certificateId, err := storage.StoreX509Certificate(db, cert)
		if err == nil {
			_, _ = fmt.Printf("Certificate %v successfully stored (certificate ID=%d)\n", cert.Subject, certificateId)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "failed to store certificate %v: %v\n", cert.Subject, err)
		}
	}

	// Store private keys in database
	for _, privateKey := range privateKeys {
		encryptedPrivateKey, err := storage.EncryptPrivateKey(privateKey, password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to encrypt private key: %v\n", err)
			continue
		}
		privateKeyId, err := storage.StorePrivateKey(db, encryptedPrivateKey, true)
		if err == nil {
			fmt.Printf("%s private key successfully stored (private key ID=%d)\n", privateKey.Type(), privateKeyId)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "failed to store %s private key: %v\n", privateKey.Type(), err)
		}
	}
	return nil
}

func init() {
	storeCmd.Flags().StringVarP(&password, passwordFlag, "p", "", "Private Key Password")
	rootCmd.AddCommand(storeCmd)
}
