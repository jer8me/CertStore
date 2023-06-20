package storage

import (
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"os"
	"strings"
	"testing"
)

// Helper function to open a database connection
func openMySql(t *testing.T) *sql.DB {
	// Connect to database
	username := os.Getenv("DB_USERNAME")
	require.NotEmpty(t, username, "DB_USERNAME must be defined")
	password := os.Getenv("DB_PASSWORD")
	require.NotEmpty(t, password, "DB_PASSWORD must be defined")
	dbName := os.Getenv("DB_NAME")
	require.NotEmpty(t, dbName, "DB_NAME must be defined")

	db, err := OpenMySqlDB(username, password, dbName)
	if err != nil {
		require.NoError(t, err, "failed to open database '%s' for user '%s'", dbName, username)
	}
	return db
}

func TestStoreCertificate(t *testing.T) {

	// Read certificate
	x509cert, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	if err != nil {
		require.NoError(t, err, "failed to read certificate")
	}
	// Transform x509 certificate to certificate DB model
	certificate, err := ToCertificate(x509cert)
	if err != nil {
		require.NoError(t, err, "failed to transform x509 certificate")
	}

	// Connect to database
	db := openMySql(t)
	defer db.Close()

	err = StoreCertificate(db, certificate)
	if err != nil {
		require.NoError(t, err, "failed to store certificate")
	}
}

func TestGetPublicKeyAlgorithmId(t *testing.T) {

	// Connect to database
	db := openMySql(t)
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
	db := openMySql(t)
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

// TestGetSANTypes tests the general sanity of the data populated in the SubjectAlternateNameType table
func TestGetSANTypes(t *testing.T) {

	// Connect to database
	db := openMySql(t)
	defer db.Close()

	sanTypes, err := GetSANTypes(db)
	if err != nil {
		require.NoError(t, err, "failed to get SAN types")
	}
	var sanIds []int
	var sanNames []string
	for _, sanType := range sanTypes {
		assert.False(t, slices.Contains(sanIds, sanType.Id), "duplicate SAN type ID")
		sanIds = append(sanIds, sanType.Id)
		assert.False(t, slices.Contains(sanNames, sanType.Name), "duplicate SAN type name")
		sanNames = append(sanNames, sanType.Name)
	}
	assert.Subset(t, sanNames, []string{DnsName, EmailAddress, IpAddress, URI})
}

// TestGetAttributeTypes tests the general sanity of the data populated in the AttributeType table
func TestGetAttributeTypes(t *testing.T) {

	// Connect to database
	db := openMySql(t)
	defer db.Close()

	attributeTypes, err := GetAttributeTypes(db)
	if err != nil {
		require.NoError(t, err, "failed to get attribute types")
	}
	var oids []string
	for _, attributeType := range attributeTypes {
		assert.False(t, slices.Contains(oids, attributeType.Oid), "duplicate attribute type")
		oids = append(oids, attributeType.Oid)
		assert.NotEmpty(t, attributeType.Name, "attribute type name is missing")
		assert.NotEmpty(t, attributeType.Description, "attribute type description is missing")
	}
}
