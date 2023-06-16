package storage

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"strings"
	"testing"
)

// Helper function to open a database connection
func openMySQL(t *testing.T) *sql.DB {
	// Connect to database
	username := os.Getenv("DB_USERNAME")
	require.NotEmpty(t, username, "DB_USERNAME must be defined")
	password := os.Getenv("DB_PASSWORD")
	require.NotEmpty(t, username, "DB_PASSWORD must be defined")
	dbName := os.Getenv("DB_NAME")
	require.NotEmpty(t, username, "DB_NAME must be defined")

	db, err := OpenMySQL(username, password, dbName)
	if err != nil {
		require.NoError(t, err, "failed to open database '%s' for user '%s'", dbName, username)
	}
	return db
}

// Helper function to return the path of a certificate file
func certPath(filename string) string {
	return path.Join("../certificates/testdata", filename)
}

func TestStoreCertificate(t *testing.T) {

	// Read certificate
	x509cert, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	if err != nil {
		require.NoError(t, err, "failed to read certificate")
	}
	// Transform x509 certificate to certificate DB model
	certModel, err := ToCertificate(x509cert)
	if err != nil {
		require.NoError(t, err, "failed to transform x509 certificate")
	}

	// Connect to database
	db := openMySQL(t)
	defer db.Close()

	err = StoreCertificate(db, certModel)
	if err != nil {
		require.NoError(t, err, "failed to store certificate")
	}
}

func TestGetPublicKeyAlgorithmId(t *testing.T) {

	// Connect to database
	db := openMySQL(t)
	defer db.Close()

	tests := []struct {
		name               string
		publicKeyAlgorithm string
		wantErr            assert.ErrorAssertionFunc
	}{
		{"", "RSA", assert.NoError},
		{"", "DSA", assert.NoError},
		{"", "ECDSA", assert.NoError},
		{"", "Ed25519", assert.NoError},
		{"", "Invalid", assert.Error},
	}
	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = "Test" + tt.publicKeyAlgorithm + "PublicKeyAlgorithmId"
		}
		t.Run(name, func(t *testing.T) {
			got, err := GetPublicKeyAlgorithmId(db, tt.publicKeyAlgorithm)
			if !tt.wantErr(t, err, fmt.Sprintf("GetPublicKeyAlgorithmId(%s)", tt.publicKeyAlgorithm)) {
				return
			}
			if err == nil {
				assert.Positive(t, got)
			}
		})
	}
}

func TestGetSignatureAlgorithmId(t *testing.T) {

	// Connect to database
	db := openMySQL(t)
	defer db.Close()

	tests := []struct {
		name               string
		signatureAlgorithm string
		wantErr            assert.ErrorAssertionFunc
	}{
		{"", "MD2-RSA", assert.NoError},
		{"", "MD5-RSA", assert.NoError},
		{"", "SHA1-RSA", assert.NoError},
		{"", "SHA256-RSA", assert.NoError},
		{"", "SHA384-RSA", assert.NoError},
		{"", "SHA512-RSA", assert.NoError},
		{"", "DSA-SHA1", assert.NoError},
		{"", "DSA-SHA256", assert.NoError},
		{"", "ECDSA-SHA1", assert.NoError},
		{"", "ECDSA-SHA256", assert.NoError},
		{"", "ECDSA-SHA384", assert.NoError},
		{"", "ECDSA-SHA512", assert.NoError},
		{"", "SHA256-RSAPSS", assert.NoError},
		{"", "SHA384-RSAPSS", assert.NoError},
		{"", "SHA512-RSAPSS", assert.NoError},
		{"", "Ed25519", assert.NoError},
		{"", "Invalid", assert.Error},
	}
	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = "Test" + strings.ReplaceAll(tt.signatureAlgorithm, "-", "With") + "SignatureAlgorithmId"
		}
		t.Run(name, func(t *testing.T) {
			got, err := GetSignatureAlgorithmId(db, tt.signatureAlgorithm)
			if !tt.wantErr(t, err, fmt.Sprintf("GetSignatureAlgorithmId(%s)", tt.signatureAlgorithm)) {
				return
			}
			if err == nil {
				assert.Positive(t, got)
			}
		})
	}
}

func TestGetKeyUsages(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
		want     []string
	}{
		{"TestKeyUsageDigitalSignature", x509.KeyUsageDigitalSignature, []string{"DigitalSignature"}},
		{"TestKeyUsageContentCommitment", x509.KeyUsageContentCommitment, []string{"ContentCommitment"}},
		{"TestKeyUsageKeyEncipherment", x509.KeyUsageKeyEncipherment, []string{"KeyEncipherment"}},
		{"TestKeyUsageDataEncipherment", x509.KeyUsageDataEncipherment, []string{"DataEncipherment"}},
		{"TestKeyUsageKeyAgreement", x509.KeyUsageKeyAgreement, []string{"KeyAgreement"}},
		{"TestKeyUsageCertSign", x509.KeyUsageCertSign, []string{"KeyCertSign"}},
		{"TestKeyUsageCRLSign", x509.KeyUsageCRLSign, []string{"CRLSign"}},
		{"TestKeyUsageEncipherOnly", x509.KeyUsageEncipherOnly, []string{"EncipherOnly"}},
		{"TestKeyUsageDecipherOnly", x509.KeyUsageDecipherOnly, []string{"DecipherOnly"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeCertificate := &x509.Certificate{KeyUsage: tt.keyUsage}
			assert.Equalf(t, tt.want, GetKeyUsages(fakeCertificate), "GetKeyUsages(%v)", tt.keyUsage)
		})
	}
}

func TestCertificateKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     []string
	}{
		{"TestChamplainCertificate", certPath("champlain.crt"), []string{"DigitalSignature", "KeyEncipherment"}},
		{"TestDSACertificate", certPath("dsa.crt"), []string{"KeyEncipherment", "DataEncipherment"}},
		{"TestEd25519Certificate", certPath("ed25519.crt"), []string{"KeyEncipherment", "DataEncipherment"}},
		{"TestGithubCertificate", certPath("github.crt"), []string{"DigitalSignature"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x509certificate, err := certificates.ParsePEMFile(tt.filename)
			require.NoError(t, err, "failed to parse certificate")
			assert.Equalf(t, tt.want, GetKeyUsages(x509certificate), "GetKeyUsages(%v)", tt.filename)
		})
	}
}
