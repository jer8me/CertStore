package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const certfile = "testdata/champlain.pem"

func TestParseCertificates(t *testing.T) {
	bytes, err := os.ReadFile(certfile) // just pass the file name
	if err != nil {
		t.Fatalf("failed to read certificate '%s': %v\n", certfile, err)
	}
	block, rest := pem.Decode(bytes)
	if block == nil {
		t.Fatalf("failed to parse certificate PEM\n")
	}
	if len(rest) > 0 {
		t.Errorf("certificate PEM had %d bytes left, wanted none\n", len(rest))
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v\n", err)
	}
	assert.Equal(t, 3, certificate.Version, "invalid certificate version")
	assert.False(t, certificate.IsCA, "invalid certificate isCA")
	assert.Equal(t, "DigiCert TLS RSA SHA256 2020 CA1", certificate.Issuer.CommonName, "invalid certificate Issuer CN")
	assert.Equal(t, "*.champlain.edu", certificate.Subject.CommonName, "invalid certificate Subject CN")
	expectedDNSNames := []string{"*.champlain.edu", "champlain.edu"}
	assert.Equal(t, expectedDNSNames, certificate.DNSNames, "invalid certificate DNS Names")
}
