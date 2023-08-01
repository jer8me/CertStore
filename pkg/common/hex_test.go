package common_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	for n := 2; n < 4000; n = n * 2 {
		length := n - 1
		name := fmt.Sprintf("TestSHA256Hex-%d", length)
		t.Run(name, func(t *testing.T) {
			bytes := make([]byte, length)
			_, err := rand.Read(bytes)
			require.NoError(t, err, "failed to generate random bytes")
			computed := common.SHA256Hex(bytes)
			reference := fmt.Sprintf("%x", sha256.Sum256(bytes))
			assert.Equalf(t, computed, reference, "SHA-256 mismatch")
		})
	}
}
