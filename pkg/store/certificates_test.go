package store_test

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"path"
	"testing"
)

// Helper function to return the path of a certificate file
func certPath(filename string) string {
	return path.Join("../../testdata", filename)
}

// Helper function to parse a URL. If the URL is invalid, it immediately fails the test
func parseUrl(t *testing.T, rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	require.NoError(t, err, "invalid URL")
	return u
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
			assert.Equalf(t, tt.want, store.GetKeyUsages(mockCertificate), "GetKeyUsages(%v)", tt.keyUsage)
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
		{"TestEd25519Certificate", certPath("ed25519.crt"), []string{"DigitalSignature", "KeyEncipherment"}},
		{"TestGithubCertificate", certPath("github.crt"), []string{"DigitalSignature"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, privateKeys, err := certificates.ParsePEMFile(tt.filename)
			require.NoError(t, err, "failed to parse certificate")
			assert.Nil(t, privateKeys, "unexpected private key found")
			assert.Len(t, certs, 1, "expected exactly one certificate")
			assert.Equalf(t, tt.want, store.GetKeyUsages(certs[0]), "GetKeyUsages(%v)", tt.filename)
		})
	}
}

func TestToCertificate(t *testing.T) {

	certs, privateKeys, err := certificates.ParsePEMFile(certPath("champlain.crt"))
	require.NoError(t, err, "failed to parse certificate")
	require.Nil(t, privateKeys, "unexpected private key found")
	require.Len(t, certs, 1, "expected exactly one certificate")

	tests := []struct {
		name    string
		cert    *x509.Certificate
		want    *store.Certificate
		wantErr assert.ErrorAssertionFunc
	}{
		{"TestValidCertificate", certs[0], nil, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := store.ToCertificate(tt.cert)
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
	sans := store.GetSANs(mockCertificate)
	assert.Contains(t, sans, store.DnsName)
	assert.Equal(t, sans[store.DnsName], dnsNames)
	assert.Contains(t, sans, store.EmailAddress)
	assert.Equal(t, sans[store.EmailAddress], emailAddresses)
	assert.Contains(t, sans, store.IpAddress)
	assert.Equal(t, sans[store.IpAddress], []string{"208.115.107.132", "2001:db8::68"})
	assert.Contains(t, sans, store.URI)
	assert.Equal(t, sans[store.URI], testUrls)
}

// TestGetAttributes tests that a pkix Name structure is correctly parsed into a slice of attributes
func TestGetAttributes(t *testing.T) {
	countryName := "US"
	stateOrProvinceName := "Vermont"
	localityName := "Burlington"
	organizationName := "Champlain College"
	commonName := "*.champlain.edu"

	attributes := []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: countryName},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 8}, Value: stateOrProvinceName},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: localityName},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: organizationName},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName},
	}
	var rdns pkix.RDNSequence
	rdns = append(rdns, attributes)

	name := pkix.Name{}
	name.FillFromRDNSequence(&rdns)

	assert.Equal(t, []string{countryName}, name.Country, "invalid country name")
	assert.Equal(t, []string{stateOrProvinceName}, name.Province, "invalid state name")
	assert.Equal(t, []string{localityName}, name.Locality, "invalid locality name")
	assert.Equal(t, []string{organizationName}, name.Organization, "invalid organization name")
	assert.Equal(t, commonName, name.CommonName, "invalid common name")

	parsedAttributes := store.GetAttributes(name)
	assert.Len(t, parsedAttributes, 5, "invalid number of attributes")
	assert.Contains(t, parsedAttributes, store.Attribute{Oid: "2.5.4.6", Value: countryName})
	assert.Contains(t, parsedAttributes, store.Attribute{Oid: "2.5.4.8", Value: stateOrProvinceName})
	assert.Contains(t, parsedAttributes, store.Attribute{Oid: "2.5.4.7", Value: localityName})
	assert.Contains(t, parsedAttributes, store.Attribute{Oid: "2.5.4.10", Value: organizationName})
	assert.Contains(t, parsedAttributes, store.Attribute{Oid: "2.5.4.3", Value: commonName})
}

func TestEncryptDecryptPrivateKey(t *testing.T) {
	// Generate a KEK (Key Encryption Key)
	password := "password123"

	// Read private key file
	certs, privateKeys, err := certificates.ParsePEMFile(certPath("rsa2048.key"))
	require.NoError(t, err, "failed to read RSA private key")
	assert.Nil(t, certs, "unexpected certificate found")
	assert.Len(t, privateKeys, 1, "expected exactly one private key")

	rsaPrivateKey := privateKeys[0]
	encryptedPrivateKey, err := store.EncryptPrivateKey(rsaPrivateKey, password)
	require.NoError(t, err, "failed to encrypt private key")

	privateKey, err := store.DecryptPrivateKey(encryptedPrivateKey, password)
	require.NoError(t, err, "failed to decrypt private key")

	assert.Equal(t, "RSA PRIVATE KEY", privateKey.PEMType)
	assert.IsType(t, &rsa.PrivateKey{}, privateKey.PrivateKey)
	assert.True(t, rsaPrivateKey.Equal(privateKey), "private keys do not match")
}
