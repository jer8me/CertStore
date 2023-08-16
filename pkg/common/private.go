package common

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// PrivateKey stores a crypto.PrivateKey along with the original PEM type
type PrivateKey struct {
	PEMType string
	crypto.PrivateKey
}

type privKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// NewPrivateKey creates a new PrivateKey object and returns a PrivateKey pointer.
func NewPrivateKey(pemType string, privateKey crypto.PrivateKey) *PrivateKey {
	return &PrivateKey{PEMType: pemType, PrivateKey: privateKey}
}

// PublicKey returns the public key part of the private key.
func (pk *PrivateKey) PublicKey() crypto.PublicKey {
	private := pk.PrivateKey.(privKey)
	return private.Public()
}

// Equal returns true if this private key has equivalent values to another private key.
func (pk *PrivateKey) Equal(other *PrivateKey) bool {
	private := pk.PrivateKey.(privKey)
	return private.Equal(other.PrivateKey)
}

// Type returns the type of the private key as a string.
// Types can be: RSA, ECDSA, Ed25519, ECDH or Unknown
func (pk *PrivateKey) Type() string {
	switch pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	case *ecdh.PrivateKey:
		return "ECDH"
	default:
		return "Unknown"
	}
}
