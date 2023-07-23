package common_test

import (
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptDecryptData(t *testing.T) {
	data := []byte("Hello world")
	key, err := common.GenerateCryptoRandom(32)
	require.NoError(t, err, "failed to generate encryption key")
	encrypted, err := common.EncryptGCM(data, key)
	require.NoError(t, err, "failed to encrypt data")
	plaintext, err := common.DecryptGCM(encrypted, key)
	require.NoError(t, err, "failed to decrypt data")
	assert.Equal(t, plaintext, data, "encrypted/decrypted data does not match original data")
}
