package certificates_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantType interface{}
		wantErr  assert.ErrorAssertionFunc
	}{
		{"TestRSAPrivateKey", "rsa2048.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestRSAPK8PrivateKey", "rsapk8.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestED25519PrivateKey", "ed25519.key", ed25519.PrivateKey{}, assert.NoError},
		{"TestECDSAPrivateKey", "secp521r1.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestECDSAPK8PrivateKey", "ecdsapk8.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestUnsupportedPrivateKey", "dsa.key", nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := path.Join("../../testdata", tt.filename)
			certs, privateKeys, err := certificates.ParsePEMFile(filename)
			if !tt.wantErr(t, err, fmt.Sprintf("ParsePrivateKey(%v)", tt.filename)) {
				return
			}
			if err != nil {
				return
			}
			assert.Nil(t, certs, "unexpected certificates found")
			assert.Len(t, privateKeys, 1, "expected exactly one private key")
			privateKey := privateKeys[0].PrivateKey
			assert.IsType(t, tt.wantType, privateKey)
			switch privateKey := privateKey.(type) {
			case *rsa.PrivateKey:
				assert.NoError(t, privateKey.Validate())
			case ed25519.PrivateKey:
				assert.Len(t, privateKey.Seed(), 32)
			case *ecdsa.PrivateKey:
				assert.Equal(t, privateKey.Curve.Params().Name, "P-521")
			default:
				assert.Fail(t, "invalid private key type", "unknown private key type: %T", privateKey)
			}
		})
	}
}

func TestCheckPrivateKey(t *testing.T) {
	tests := []struct {
		name        string
		certfile    string
		keyfile     string
		errContains string
	}{
		{"TestRSA2048PrivateKey", "rsa2048.crt", "rsa2048.key", ""},
		{"TestRSA2048PK8PrivateKey", "rsa2048.crt", "rsapk8.key", ""},
		{"TestED25519PrivateKey", "ed25519.crt", "ed25519.key", ""},
		{"TestECDSAPrivateKey", "ecdsa.crt", "secp521r1.key", ""},
		{"TestECDSAPK8PrivateKey", "ecdsa.crt", "ecdsapk8.key", ""},
		{"TestKeyTypeMismatch", "ed25519.crt", "rsa2048.key", "private key type does not match public key type"},
		{"TestKeyMismatch", "champlain.crt", "rsa2048.key", "private key does not match public key"},
		{"TestUnsupportedPublicKeyType", "dsa.crt", "rsa2048.key", "unknown public key algorithm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certfile := path.Join("../../testdata", tt.certfile)
			certs, privateKeys, err := certificates.ParsePEMFile(certfile)
			require.NoError(t, err, "failed to load X.509 certificate")
			assert.Nil(t, privateKeys, "unexpected private key found")
			assert.Len(t, certs, 1, "expected exactly one certificate")
			x509Certificate := certs[0]

			keyfile := path.Join("../../testdata", tt.keyfile)
			certs, privateKeys, err = certificates.ParsePEMFile(keyfile)
			require.NoError(t, err, "failed to load private key")
			assert.Nil(t, certs, "unexpected certificates found")
			assert.Len(t, privateKeys, 1, "expected exactly one private key")
			privateKey := privateKeys[0]

			err = certificates.CheckPrivateKey(x509Certificate, privateKey)
			if tt.errContains == "" {
				assert.NoError(t, err, "public and private key do no match")
			} else {
				assert.ErrorContains(t, err, tt.errContains)
			}
		})
	}
}

func TestReadWritePrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  assert.ErrorAssertionFunc
	}{
		{"TestRSA2048PrivateKey", "rsa2048.key", assert.NoError},
		{"TestRSA2048PK8PrivateKey", "rsapk8.key", assert.NoError},
		{"TestED25519PrivateKey", "ed25519.key", assert.NoError},
		{"TestECDSAPrivateKey", "secp521r1.key", assert.NoError},
		{"TestECDSAPK8PrivateKey", "ecdsapk8.key", assert.NoError},
		{"TestUnsupportedPrivateKey", "dsa.key", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := path.Join("../../testdata", tt.filename)
			certs, privateKeys, err := certificates.ParsePEMFile(filename)
			tt.wantErr(t, err, fmt.Sprintf("ParsePrivateKey(%v)", filename))
			if err != nil {
				return
			}
			assert.Nil(t, certs, "unexpected certificates found")
			assert.Len(t, privateKeys, 1, "expected exactly one private key")
			outfile := path.Join(t.TempDir(), path.Base(tt.filename))
			err = certificates.WritePrivateKey(outfile, privateKeys[0])
			require.NoError(t, err, "failed to write private key")
			expected, err := os.ReadFile(filename)
			require.NoError(t, err, "failed to read original private key")
			actual, err := os.ReadFile(outfile)
			require.NoError(t, err, "failed to read private key")
			assert.Equal(t, expected, actual, "private keys do not match")
		})
	}
}
