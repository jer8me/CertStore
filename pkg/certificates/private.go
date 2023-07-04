package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// ParsePrivateKey parses a private key stored in a file.
// It supports the following formats:
//   - RSA / PKCS1
//   - RSA / PKCS8
//   - ECDSA / SEC1
//   - ECDSA / PKCS8
//   - ED25519 / PKCS8
//
// It returns an error if a valid private key cannot be parsed.
func ParsePrivateKey(filename string) (any, error) {
	// Load file content into memory
	bytes, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	block, rest := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM data: %w", err)
	}
	// If the file contains a single private key, we should not have any leftover bytes here.
	// For now, log the case when there is more data in the file.
	if len(rest) > 0 {
		log.Printf("private key file %s had %d bytes left", filename, len(rest))
	}
	var privateKey any
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key %s: %w", filename, err)
	}
	return privateKey, nil
}
