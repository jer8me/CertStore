package certificates

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDownloadCertificates(t *testing.T) {
	addr := "google.com:443"
	certificates, err := DownloadCertificates(addr)
	require.NoError(t, err, "failed to download certificates from %s", addr)
	// google.com should return 3 certificates: root, intermediate, leaf
	assert.Equal(t, 3, len(certificates), "invalid number of certificates for %s", addr)
}
