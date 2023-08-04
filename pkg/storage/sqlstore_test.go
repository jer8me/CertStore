package storage_test

import (
	"crypto/rsa"
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"path"
	"strings"
	"testing"
)

// Helper function to open a database connection
func openDB(t *testing.T) *sql.DB {
	dbpath := path.Join(t.TempDir(), "test.db")
	// Connect to database
	db, err := storage.OpenDatabase(dbpath)
	require.NoError(t, err, "failed to open database '%s'", dbpath)
	return db
}

func initDB(t *testing.T, db *sql.DB) {
	err := storage.InitDatabase(db)
	require.NoError(t, err, "failed to initialize database")
}

func closeDB(t *testing.T, db *sql.DB) {
	err := db.Close()
	require.NoError(t, err, "failed to close database")
}

func TestGetCertificate(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	// Read certificate file
	certs, privateKeys, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	require.NoError(t, err, "failed to read certificate file")
	assert.Nil(t, privateKeys, "unexpected private keys found")
	assert.Len(t, certs, 1, "expected exactly one certificate")

	// Store certificate in database
	certificateId, err := storage.StoreCertificate(db, storage.ToCertificate(certs[0]), false)
	require.NoError(t, err, "failed to store certificate")

	cert, err := storage.GetCertificate(db, certificateId)
	if err != nil {
		require.NoError(t, err, "failed to get certificate")
	}
	assert.NotNil(t, cert.Signature)
}

func TestStoreCertificate(t *testing.T) {

	// Read certificate
	certs, privateKeys, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	require.NoError(t, err, "failed to read certificate file")
	assert.Nil(t, privateKeys, "unexpected private keys found")
	assert.Len(t, certs, 1, "expected exactly one certificate")

	// Transform x509 certificate to certificate DB model
	certificate := storage.ToCertificate(certs[0])

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	certificateId, err := storage.StoreCertificate(db, certificate, false)
	if err != nil {
		require.NoError(t, err, "failed to store certificate")
	}
	assert.Positive(t, certificateId, "invalid certificate ID")
}

func TestGetPublicKeyAlgorithmId(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

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
			got, err := storage.GetPublicKeyAlgorithmId(db, tt.publicKeyAlgorithm)
			if !tt.wantErr(t, err, fmt.Sprintf("GetPublicKeyAlgorithmId(%s)", tt.publicKeyAlgorithm)) {
				return
			}
			if err == nil {
				assert.Positive(t, got)
			}
		})
	}
}

func TestGetPublicKeyAlgorithmName(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	tests := []struct {
		name                 string
		publicKeyAlgorithmId int
		want                 string
		wantErr              assert.ErrorAssertionFunc
	}{
		{"TestRSAPublicKeyAlgorithm", 1, "RSA", assert.NoError},
		{"TestDSAPublicKeyAlgorithm", 2, "DSA", assert.NoError},
		{"TestECDSAPublicKeyAlgorithm", 3, "ECDSA", assert.NoError},
		{"TestEd25519PublicKeyAlgorithm", 4, "Ed25519", assert.NoError},
		{"TestInvalidPublicKeyAlgorithm", 5, "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := storage.GetPublicKeyAlgorithmName(db, tt.publicKeyAlgorithmId)
			if !tt.wantErr(t, err, fmt.Sprintf("GetPublicKeyAlgorithmName(%v)", tt.publicKeyAlgorithmId)) {
				return
			}
			if err == nil {
				assert.Equalf(t, tt.want, got, "GetPublicKeyAlgorithmName(%v)", tt.publicKeyAlgorithmId)
			}
		})
	}
}

func TestGetSignatureAlgorithmId(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

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
			got, err := storage.GetSignatureAlgorithmId(db, tt.signatureAlgorithm)
			if !tt.wantErr(t, err, fmt.Sprintf("GetSignatureAlgorithmId(%s)", tt.signatureAlgorithm)) {
				return
			}
			if err == nil {
				assert.Positive(t, got)
			}
		})
	}
}

func TestGetSignatureAlgorithmName(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	tests := []struct {
		name                 string
		signatureAlgorithmId int
		want                 string
		wantErr              assert.ErrorAssertionFunc
	}{
		{"TestMD2RSASignatureAlgorithm", 1, "MD2-RSA", assert.NoError},
		{"TestSHA256RSASignatureAlgorithm", 4, "SHA256-RSA", assert.NoError},
		{"TestSHA512RSASignatureAlgorithm", 6, "SHA512-RSA", assert.NoError},
		{"TestEd25519SignatureAlgorithm", 16, "Ed25519", assert.NoError},
		{"TestInvalidSignatureAlgorithm", 17, "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := storage.GetSignatureAlgorithmName(db, tt.signatureAlgorithmId)
			if !tt.wantErr(t, err, fmt.Sprintf("GetSignatureAlgorithmName(%v)", tt.signatureAlgorithmId)) {
				return
			}
			assert.Equalf(t, tt.want, got, "GetSignatureAlgorithmName(%v)", tt.signatureAlgorithmId)
		})
	}
}

// TestGetSANTypes tests the general sanity of the data populated in the SubjectAlternateNameType table
func TestGetSANTypes(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	sanTypes, err := storage.GetSANTypes(db)
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
	assert.Subset(t, sanNames, []string{storage.DnsName, storage.EmailAddress, storage.IpAddress, storage.URI})
}

// TestGetAttributeTypes tests the general sanity of the data populated in the AttributeType table
func TestGetAttributeTypes(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	attributeTypes, err := storage.GetAttributeTypes(db)
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

func TestStorePrivateKey(t *testing.T) {

	// Connect to database
	db := openDB(t)
	defer closeDB(t, db)
	initDB(t, db)

	password := "password123"

	// Read private key file
	certs, privateKeys, err := certificates.ParsePEMFile(certPath("rsa2048.key"))
	require.NoError(t, err, "failed to read private keys")
	assert.Nil(t, certs, "unexpected certificates found")
	assert.Len(t, privateKeys, 1, "expected exactly one private key")
	rsaPrivateKey := privateKeys[0]

	encryptedPrivateKey, err := storage.EncryptPrivateKey(rsaPrivateKey, password)
	require.NoError(t, err, "failed to encrypt private key")

	// Store private key in database
	privateKeyId, err := storage.StorePrivateKey(db, encryptedPrivateKey, false)
	require.NoError(t, err, "failed to store private key")

	// Read stored encrypted private key
	privateKeyFound, err := storage.GetPrivateKey(db, privateKeyId)
	require.NoError(t, err, "failed to get private key")

	// Decrypt private key fetched from database
	privateKey, err := storage.DecryptPrivateKey(privateKeyFound, password)
	require.NoError(t, err, "failed to decrypt private key")

	assert.Equal(t, "RSA PRIVATE KEY", privateKey.PEMType)
	assert.IsType(t, &rsa.PrivateKey{}, privateKey.PrivateKey)
	assert.True(t, rsaPrivateKey.Equal(privateKey), "private keys do not match")
}
