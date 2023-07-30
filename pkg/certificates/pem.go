package certificates

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"os"
	"strings"
)

const (
	RsaPrivateKey = "RSA PRIVATE KEY"
	EcPrivateKey  = "EC PRIVATE KEY"
	PrivateKey    = "PRIVATE KEY"
)

// ParsePEMFile reads the named PEM file and returns a slice of certificates and private keys.
// A successful call returns a nil error.
// The following private key formats are supported:
//   - RSA / PKCS1
//   - RSA / PKCS8
//   - ECDSA / SEC1
//   - ECDSA / PKCS8
//   - ED25519 / PKCS8
func ParsePEMFile(filename string) ([]*x509.Certificate, []*common.PrivateKey, error) {
	// Load file content into memory
	content, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	var certificates []*x509.Certificate
	var privateKeys []*common.PrivateKey
	for len(content) > 0 {
		var block *pem.Block
		block, content = pem.Decode(content)
		if block == nil {
			continue
		}
		if strings.Contains(block.Type, PrivateKey) {
			// Private key
			var privateKey crypto.PrivateKey
			switch block.Type {
			case RsaPrivateKey:
				privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			case EcPrivateKey:
				privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			default:
				privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			}
			if err != nil {
				return certificates, privateKeys, fmt.Errorf("failed to parse private key %s: %w", filename, err)
			}
			privateKeys = append(privateKeys, common.NewPrivateKey(block.Type, privateKey))
		} else {
			// Certificate
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certificates, privateKeys, fmt.Errorf("failed to parse certificate for file %s: %w", filename, err)
			}
			certificates = append(certificates, certificate)
		}
	}
	return certificates, privateKeys, nil
}

// WriteCertificate writes a x509 certificate to a PEM encoded file.
// Returns an error if the certificate is invalid or if it fails to write the file.
// If the file already exists, WriteCertificate returns an os.ErrExist error.
func WriteCertificate(filename string, certificate *x509.Certificate) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	// Encode PEM content
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}
	err = pem.Encode(f, block)
	if errc := f.Close(); errc != nil && err == nil {
		// Encoding errors take priority
		err = errc
	}
	return err
}
