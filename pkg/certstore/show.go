package certstore

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/storage"
	"io"
	"os"
	"strconv"
	"strings"
)

func PrintCertificate(w io.Writer, cert *storage.Certificate) {
	fmt.Fprintln(w, "Certificate:")
	fmt.Fprintf(w, "  Version: %d\n", cert.Version)
	fmt.Fprintf(w, "  Serial Number: %s\n", cert.SerialNumber)
	fmt.Fprintf(w, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Fprintf(w, "  Issuer: %v\n", cert.Issuer)
	fmt.Fprintf(w, "  Validity:\n")
	fmt.Fprintf(w, "    Not Before: %v\n", cert.NotBefore)
	fmt.Fprintf(w, "    Not After: %v\n", cert.NotAfter)
	fmt.Fprintf(w, "  Subject: %v\n", cert.Subject)
	fmt.Fprintf(w, "  Subject Public Key Info:\n")
	fmt.Fprintf(w, "    Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
	fmt.Fprintf(w, "  X509v3 Extensions:\n")
	if len(cert.KeyUsages) > 0 {
		fmt.Fprintf(w, "    X509v3 Key Usage: critical\n")
		for _, keyUsage := range cert.KeyUsages {
			fmt.Fprintf(w, "      %s\n", keyUsage)
		}
	}
	fmt.Fprintf(w, "    X509v3 Basic Constraints: critical\n")
	fmt.Fprintf(w, "      CA: %s\n", strings.ToUpper(strconv.FormatBool(cert.IsCA)))
	if len(cert.SANs) > 0 {
		fmt.Fprintf(w, "    X509v3 Subject Alternative Name:\n")
		fmt.Fprintf(w, "      ")
		first := true
		for sanType, sanValues := range cert.SANs {
			for _, sanValue := range sanValues {
				if first {
					first = false
				} else {
					fmt.Fprintf(w, ", ")
				}
				fmt.Fprintf(w, "%s: %s", sanType, sanValue)
			}
		}
		fmt.Fprintf(w, "\n")
	}
	// TODO: display PublicKey in human-friendly format
	// TODO: display Signature in human-friendly format
}

func ShowCertificate(certificateId int64, userName, userPassword, dbName string) error {

	// Connect to database
	db, err := storage.OpenMySqlDB(userName, userPassword, dbName)
	if err != nil {
		return err
	}
	defer db.Close()

	// Fetch certificate
	cert, err := storage.GetCertificate(db, certificateId)
	if err != nil {
		return err
	}
	PrintCertificate(os.Stdout, cert)

	return nil
}
