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
		{"TestRSAPrivateKey", "testdata/rsa2048.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestRSAPK8PrivateKey", "testdata/rsapk8.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestED25519PrivateKey", "testdata/ed25519.key", ed25519.PrivateKey{}, assert.NoError},
		{"TestECDSAPrivateKey", "testdata/secp521r1.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestECDSAPK8PrivateKey", "testdata/ecdsapk8.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestUnsupportedPrivateKey", "testdata/dsa.key", nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certificates.ParsePrivateKey(tt.filename)
			if !tt.wantErr(t, err, fmt.Sprintf("ParsePrivateKey(%v)", tt.filename)) {
				return
			}
			if err != nil {
				return
			}
			privateKey := got.PrivateKey
			assert.IsType(t, tt.wantType, privateKey)
			switch privateKey := privateKey.(type) {
			case *rsa.PrivateKey:
				assert.NoError(t, privateKey.Validate())
			case ed25519.PrivateKey:
				assert.Len(t, privateKey.Seed(), 32)
			case *ecdsa.PrivateKey:
				assert.Equal(t, privateKey.Curve.Params().Name, "P-521")
			default:
				assert.Fail(t, "invalid private key type", "unknown private key type: %T", got)
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
			certpath := path.Join("testdata", tt.certfile)
			x509Certificate, err := certificates.ParsePEMFile(certpath)
			assert.NoError(t, err, "failed to load X.509 certificate")

			keypath := path.Join("testdata", tt.keyfile)
			privateKey, err := certificates.ParsePrivateKey(keypath)
			assert.NoError(t, err, "failed to load private key")

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
			filepath := path.Join("testdata", tt.filename)
			privateKey, err := certificates.ParsePrivateKey(filepath)
			tt.wantErr(t, err, fmt.Sprintf("ParsePrivateKey(%v)", filepath))
			if err != nil {
				return
			}
			outfile := path.Join(t.TempDir(), path.Base(tt.filename))
			err = certificates.WritePrivateKey(outfile, privateKey)
			require.NoError(t, err, "failed to write private key")
			expected, err := os.ReadFile(filepath)
			require.NoError(t, err, "failed to read original private key")
			actual, err := os.ReadFile(outfile)
			require.NoError(t, err, "failed to read private key")
			assert.Equal(t, expected, actual, "private keys do not match")
		})
	}
}

func TestEncryptDecryptData(t *testing.T) {
	data := []byte("Hello world")
	key, err := certificates.GenerateCryptoRandom(32)
	require.NoError(t, err, "failed to generate encryption key")
	encrypted, err := certificates.EncryptData(data, key)
	require.NoError(t, err, "failed to encrypt data")
	plaintext, err := certificates.DecryptData(encrypted, key)
	require.NoError(t, err, "failed to decrypt data")
	assert.Equal(t, plaintext, data, "encrypted/decrypted data does not match original data")
}
