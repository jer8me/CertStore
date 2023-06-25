package certstore

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/jer8me/CertStore/pkg/storage"
	"io"
	"os"
	"strconv"
	"strings"
)

const columnNum = 16
const separator = ":"

// PrintHex prints a slice of bytes in am hexadecimal format, separated by colons.
// The indent parameter specifies the numbers of leading spaces to print for each line.
func PrintHex(w io.Writer, b []byte, indent int) {
	spaces := strings.Repeat(" ", indent)
	hexWriter := hex.NewEncoder(w)
	for i := range b {
		var buf bytes.Buffer
		// Check if this is a new line
		if (i % columnNum) == 0 {
			if i > 0 {
				// Print a new line first if this is not the first line
				buf.WriteRune('\n')
			}
			// Print leading spaces
			buf.WriteString(spaces)
		} else {
			// Print separator
			buf.WriteString(separator)
		}
		// Print buffer
		w.Write(buf.Bytes())
		// Print 1 byte
		hexWriter.Write(b[i : i+1])
	}
}

// PrintCertificate prints a certificate in a human-readable format
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
	fmt.Fprintf(w, "      Public Key:\n")
	PrintHex(w, cert.PublicKey, 8)
	fmt.Fprintln(w)
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
	fmt.Fprintf(w, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Fprintf(w, "  Signature:\n")
	PrintHex(w, cert.Signature, 4)
	fmt.Fprintln(w)
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
