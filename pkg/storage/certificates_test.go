package storage

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"net"
	"net/url"
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
	require.NotEmpty(t, password, "DB_PASSWORD must be defined")
	dbName := os.Getenv("DB_NAME")
	require.NotEmpty(t, dbName, "DB_NAME must be defined")

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

// Helper function to parse a URL. If the URL is invalid, it immediately fails the test
func parseUrl(t *testing.T, rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	require.NoError(t, err, "invalid URL")
	return u
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
			mockCertificate := &x509.Certificate{KeyUsage: tt.keyUsage}
			assert.Equalf(t, tt.want, GetKeyUsages(mockCertificate), "GetKeyUsages(%v)", tt.keyUsage)
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

func TestToCertificate(t *testing.T) {

	validCert, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	require.NoError(t, err, "failed to parse certificate")
	invalidCert := &x509.Certificate{PublicKey: []byte{0x10, 0x01}}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		want    *CertificateModel
		wantErr assert.ErrorAssertionFunc
	}{
		{"TestValidCertificate", validCert, nil, assert.NoError},
		{"TestInvalidCertificate", invalidCert, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToCertificate(tt.cert)
			if !tt.wantErr(t, err, fmt.Sprintf("ToCertificate(%v)", tt.cert)) {
				return
			}
			if err == nil {
				assert.NotNil(t, got)
			}
		})
	}
}

func TestGetSANs(t *testing.T) {
	// Mock some data
	dnsNames := []string{"*.champlain.edu", "champlain.edu"}
	emailAddresses := []string{"user1@champlain.edu", "user2@champlain.edu", "user3@champlain.edu"}
	ipAddresses := []net.IP{net.IPv4(208, 115, 107, 132), net.ParseIP("2001:db8::68")}
	testUrls := []string{"https://www.champlain.edu"}
	var uris []*url.URL
	for _, testUrl := range testUrls {
		uris = append(uris, parseUrl(t, testUrl))
	}

	mockCertificate := &x509.Certificate{DNSNames: dnsNames, EmailAddresses: emailAddresses,
		IPAddresses: ipAddresses, URIs: uris}
	sans := GetSANs(mockCertificate)
	assert.Contains(t, sans, DnsName)
	assert.Equal(t, sans[DnsName], dnsNames)
	assert.Contains(t, sans, EmailAddress)
	assert.Equal(t, sans[EmailAddress], emailAddresses)
	assert.Contains(t, sans, IpAddress)
	assert.Equal(t, sans[IpAddress], []string{"208.115.107.132", "2001:db8::68"})
	assert.Contains(t, sans, URI)
	assert.Equal(t, sans[URI], testUrls)
}

func TestGetSANTypes(t *testing.T) {

	// Connect to database
	db := openMySQL(t)
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
