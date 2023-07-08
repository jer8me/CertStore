package certificates

import (
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/fs"
	"os"
	"path"
	"testing"
)

func TestParsePEMFile(t *testing.T) {
	type certificate struct {
		PublicKeyType     string
		Version           int
		IsCA              bool
		IssuerCommonName  string
		SubjectCommonName string
		DNSNames          []string
	}
	tests := []struct {
		name     string
		filename string
		want     *certificate
		wantErr  bool
	}{
		{
			"TestRSACertificate",
			"testdata/champlain.crt",
			&certificate{
				"RSA",
				3,
				false,
				"DigiCert TLS RSA SHA256 2020 CA1",
				"*.champlain.edu",
				[]string{"*.champlain.edu", "champlain.edu"},
			},
			false,
		},
		{
			"TestECDSACertificate",
			"testdata/github.crt",
			&certificate{
				"ECDSA",
				3,
				false,
				"DigiCert TLS Hybrid ECC SHA384 2020 CA1",
				"github.com",
				[]string{"github.com", "www.github.com"},
			},
			false,
		},
		{
			"TestEd25519Certificate",
			"testdata/ed25519.crt",
			&certificate{
				"Ed25519",
				3,
				false,
				"Jerome Root CA",
				"Jerome Meyer",
				[]string{"www.sdev435.edu", "sdev435.edu", "localhost"},
			},
			false,
		},
		{
			"TestDSACertificate",
			"testdata/dsa.crt",
			&certificate{
				"DSA",
				3,
				false,
				"Jerome Root CA",
				"Jerome Meyer",
				[]string{"www.sdev435.edu", "sdev435.edu"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePEMFile(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePEMFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want.PublicKeyType, got.PublicKeyAlgorithm.String(), "invalid public key type")
			assert.Equal(t, tt.want.Version, got.Version, "invalid certificate version")
			assert.Equal(t, tt.want.IsCA, got.IsCA, "invalid certificate isCA")
			assert.Equal(t, tt.want.IssuerCommonName, got.Issuer.CommonName, "invalid certificate Issuer CN")
			assert.Equal(t, tt.want.SubjectCommonName, got.Subject.CommonName, "invalid certificate Subject CN")
			assert.Equal(t, tt.want.DNSNames, got.DNSNames, "invalid certificate DNS Names")
		})
	}
}

func TestWritePEMFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			"TestRSACertificate",
			"testdata/champlain.crt",
			assert.NoError,
		},
		{
			"TestECDSACertificate",
			"testdata/github.crt",
			assert.NoError,
		},
		{
			"TestEd25519Certificate",
			"testdata/ed25519.crt",
			assert.NoError,
		},
		{
			"TestDSACertificate",
			"testdata/dsa.crt",
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x509Certificate, err := ParsePEMFile(tt.filename)
			require.NoError(t, err, "failed to parse certificate")
			outfile := path.Join(t.TempDir(), path.Base(tt.filename))
			tt.wantErr(t, WritePEMFile(outfile, x509Certificate), fmt.Sprintf("WritePEMFile(%v)", tt.filename))
			expected, err := os.ReadFile(tt.filename)
			require.NoError(t, err, "failed to read original certificate")
			actual, err := os.ReadFile(outfile)
			require.NoError(t, err, "failed to read original certificate")
			assert.Equal(t, expected, actual, "certificate files do not match")
		})
	}
	// Test for existing file
	t.Run("TestExistingFile", func(t *testing.T) {
		outfile := path.Join(t.TempDir(), path.Base("dummy.crt"))
		data := []byte("TEST DATA")
		err := os.WriteFile(outfile, data, 0644)
		require.NoError(t, err, "failed to write test file")
		dummyCert := &x509.Certificate{}
		err = WritePEMFile(outfile, dummyCert)
		assert.ErrorIs(t, err, fs.ErrExist, "WritePEMFile unexpected error")
	})
}
