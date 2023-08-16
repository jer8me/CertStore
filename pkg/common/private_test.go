package common_test

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

type pubKey interface {
	Equal(x crypto.PublicKey) bool
}

type privKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

func generateRSAPrivateKey(rand io.Reader) (privKey, error) {
	return rsa.GenerateKey(rand, 4096)
}

func generateECDSAPrivateKey(rand io.Reader) (privKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand)
}

func generateEd25519PrivateKey(rand io.Reader) (privKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand)
	return privateKey, err
}

func generateECDHPrivateKey(rand io.Reader) (privKey, error) {
	x255189 := ecdh.X25519()
	return x255189.GenerateKey(rand)
}

func TestPrivateKey(t *testing.T) {
	tests := []struct {
		keyType string
		pemType string
		genFunc func(rand io.Reader) (privKey, error)
	}{
		{"RSA", "RSA PRIVATE KEY", generateRSAPrivateKey},
		{"ECDSA", "EC PRIVATE KEY", generateECDSAPrivateKey},
		{"Ed25519", "PRIVATE KEY", generateEd25519PrivateKey},
		{"ECDH", "PRIVATE KEY", generateECDHPrivateKey},
	}
	for _, tt := range tests {
		name := "Test" + tt.keyType
		t.Run(name, func(t *testing.T) {
			generatedPrivateKey, err := tt.genFunc(rand.Reader)
			require.NoError(t, err, "failed to generate %s private key", tt.keyType)

			privateKey := common.NewPrivateKey(tt.pemType, generatedPrivateKey)
			publicKey := privateKey.PublicKey().(pubKey)
			assert.True(t, publicKey.Equal(generatedPrivateKey.Public()), "%s public keys do not match", tt.keyType)
			assert.Equal(t, tt.keyType, privateKey.Type(), "invalid private key type")

			// Marshal key to DER
			der, err := x509.MarshalPKCS8PrivateKey(generatedPrivateKey)
			require.NoError(t, err, "failed to marshall %s private key", tt.keyType)
			pkcs8, err := x509.ParsePKCS8PrivateKey(der)
			pkcs8PrivateKey := common.NewPrivateKey("PRIVATE KEY", pkcs8)
			assert.True(t, privateKey.Equal(pkcs8PrivateKey), "private keys do not match")
		})
	}
}

func TestUnknownPrivateKey(t *testing.T) {
	privateKey := common.NewPrivateKey("PRIVATE KEY", &dsa.PrivateKey{})
	assert.Equal(t, "Unknown", privateKey.Type(), "invalid private key type")
}
