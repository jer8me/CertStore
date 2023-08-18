package certificates

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/jer8me/CertStore/pkg/store"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
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

// PrintPublicKey prints the components of a public key based on the key type
func PrintPublicKey(w io.Writer, b []byte, indent int) {
	spaces := strings.Repeat(" ", indent)
	pub, _ := x509.ParsePKIXPublicKey(b)
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		modulusBytes := pub.N.Bytes()
		fmt.Fprintf(w, "%sRSA Public-Key: (%d bit)\n", spaces, len(modulusBytes)*8)
		fmt.Fprintf(w, "%sModulus:\n", spaces)
		PrintHex(w, modulusBytes, indent+2)
		fmt.Fprintf(w, "\n%sExponent: %d", spaces, pub.E)
	case *dsa.PublicKey:
		fmt.Fprintf(w, "%sY:\n", spaces)
		PrintHex(w, pub.Y.Bytes(), indent+2)
		fmt.Fprintf(w, "\n%sP:\n", spaces)
		PrintHex(w, pub.P.Bytes(), indent+2)
		fmt.Fprintf(w, "\n%sQ:\n", spaces)
		PrintHex(w, pub.Q.Bytes(), indent+2)
		fmt.Fprintf(w, "\n%sG:\n", spaces)
		PrintHex(w, pub.G.Bytes(), indent+2)
	case *ecdsa.PublicKey:
		fmt.Fprintf(w, "%sX:\n", spaces)
		PrintHex(w, pub.X.Bytes(), indent+2)
		fmt.Fprintf(w, "\n%sY:\n", spaces)
		PrintHex(w, pub.Y.Bytes(), indent+2)
		fmt.Fprintf(w, "\n%sNIST CURVE: %s", spaces, pub.Curve.Params().Name)
	case ed25519.PublicKey:
		fmt.Fprintf(w, "%sED25519 Public-Key:\n", spaces)
		PrintHex(w, pub, indent+2)
	default:
		// Default format
		fmt.Fprintf(w, "%sPublic-Key:\n", spaces)
		PrintHex(w, b, indent+2)
	}
	fmt.Fprintln(w)
}

// PrintCertificate prints a certificate in a human-readable format
func PrintCertificate(w io.Writer, cert *store.Certificate) {
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
	PrintPublicKey(w, cert.PublicKey, 6)
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

func PrintCertificates(w io.Writer, certs []*store.Certificate) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPUBLIC KEY\tVERSION\tSERIAL NUMBER\tSUBJECT\tISSUER\tNOT BEFORE\tNOT AFTER\tIS CA\tPRIV KEY")
	for _, cert := range certs {
		// Print timestamps as simple dates
		notBefore := cert.NotBefore.Format("Jan-02-2006")
		notAfter := cert.NotAfter.Format("Jan-02-2006")
		isCA := yOrN(cert.IsCA)
		hasPrivateKey := yOrN(cert.PrivateKeyId.Valid)
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cert.Id, cert.PublicKeyAlgorithm, cert.Version,
			cert.SerialNumber, cert.SubjectCN, cert.IssuerCN, notBefore, notAfter, isCA, hasPrivateKey)
	}
	tw.Flush()
}

func yOrN(b bool) string {
	if b {
		return "Y"
	}
	return "N"
}
