package storage

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestGetPublicKeyAlgorithmId(t *testing.T) {

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
	defer db.Close()

	tests := []struct {
		name               string
		signatureAlgorithm string
		wantErr            assert.ErrorAssertionFunc
	}{
		{"", "MD2WithRSA", assert.NoError},
		{"", "MD5WithRSA", assert.NoError},
		{"", "SHA1WithRSA", assert.NoError},
		{"", "SHA256WithRSA", assert.NoError},
		{"", "SHA384WithRSA", assert.NoError},
		{"", "SHA512WithRSA", assert.NoError},
		{"", "DSAWithSHA1", assert.NoError},
		{"", "DSAWithSHA256", assert.NoError},
		{"", "ECDSAWithSHA1", assert.NoError},
		{"", "ECDSAWithSHA256", assert.NoError},
		{"", "ECDSAWithSHA384", assert.NoError},
		{"", "ECDSAWithSHA512", assert.NoError},
		{"", "SHA256WithRSAPSS", assert.NoError},
		{"", "SHA384WithRSAPSS", assert.NoError},
		{"", "SHA512WithRSAPSS", assert.NoError},
		{"", "PureEd25519", assert.NoError},
		{"", "Invalid", assert.Error},
	}
	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = "Test" + tt.signatureAlgorithm + "SignatureAlgorithmId"
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
