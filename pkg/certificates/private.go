package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"log"
	"os"
)

const (
	RsaPrivateKey = "RSA PRIVATE KEY"
	EcPrivateKey  = "EC PRIVATE KEY"
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
func ParsePrivateKey(filename string) (*common.PrivateKey, error) {
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
	case RsaPrivateKey:
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case EcPrivateKey:
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key %s: %w", filename, err)
	}
	return common.NewPrivateKey(block.Type, privateKey), nil
}

func CheckPrivateKey(x509Cert *x509.Certificate, pk *common.PrivateKey) error {
	privateKey := pk.PrivateKey
	switch publicKey := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		privateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("certificates: private key type does not match public key type")
		}
		if publicKey.N.Cmp(privateKey.N) != 0 {
			return errors.New("certificates: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		privateKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("certificates: private key type does not match public key type")
		}
		if publicKey.X.Cmp(privateKey.X) != 0 || publicKey.Y.Cmp(privateKey.Y) != 0 {
			return errors.New("certificates: private key does not match public key")
		}
	case ed25519.PublicKey:
		privateKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("certificates: private key type does not match public key type")
		}
		if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
			return errors.New("certificates: private key does not match public key")
		}
	default:
		return errors.New("certificates: unknown public key algorithm")
	}
	return nil
}

// WritePrivateKey writes a private key to a PEM encoded file.
// The output format is derived from the PEM type value.
// Returns an error if the private key is invalid or if it fails to write the file.
// If the file already exists, WritePrivateKey returns an os.ErrExist error.
func WritePrivateKey(filename string, privateKey *common.PrivateKey) error {

	var err error
	var privateKeyBytes []byte

	// Marshal the private key into an ASN.1 DER form
	switch pk := privateKey.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if privateKey.PEMType == RsaPrivateKey {
			// RSA / PKCS1
			privateKeyBytes = x509.MarshalPKCS1PrivateKey(pk)
		}
	case *ecdsa.PrivateKey:
		if privateKey.PEMType == EcPrivateKey {
			// ECDSA / SEC1
			privateKeyBytes, err = x509.MarshalECPrivateKey(pk)
		}
	}
	if err == nil && len(privateKeyBytes) == 0 {
		// PKCS8
		privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey.PrivateKey)
	}
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 06444)
	if err != nil {
		return err
	}
	// Encode PEM content
	block := &pem.Block{Type: privateKey.PEMType, Bytes: privateKeyBytes}
	err = pem.Encode(f, block)
	if errc := f.Close(); errc != nil && err == nil {
		// Encoding errors take priority
		err = errc
	}
	return err
}
