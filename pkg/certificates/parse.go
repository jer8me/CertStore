package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// ParsePEMFile reads the named PEM file and returns a Certificate structure.
// A successful call returns a nil error and a valid certificate.
// An error returns a nil certificate and a wrapped error.
func ParsePEMFile(filename string) (*x509.Certificate, error) {
	// Load certificate content into memory
	bytes, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate %s: %w", filename, err)
	}
	block, rest := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data for file %s: %w", filename, err)
	}
	// If the file contains a single certificate, we should not have any leftover bytes here.
	// For now, log the case when there is more data in the file.
	if len(rest) > 0 {
		log.Printf("certificate file %s had %d bytes left", filename, len(rest))
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate for file %s: %w", filename, err)
	}
	return certificate, nil
}
