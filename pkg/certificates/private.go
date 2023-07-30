package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/jer8me/CertStore/pkg/common"
	"os"
)

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

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
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
