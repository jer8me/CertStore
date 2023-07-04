package certificates

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantType interface{}
		wantErr  assert.ErrorAssertionFunc
	}{
		{"TestRSAPrivateKey", "testdata/rsa2048.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestRSAPK8PrivateKey", "testdata/rsapk8.key", &rsa.PrivateKey{}, assert.NoError},
		{"TestED25519PrivateKey", "testdata/ed25519.key", ed25519.PrivateKey{}, assert.NoError},
		{"TestECDSAPrivateKey", "testdata/secp521r1.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestECDSAPK8PrivateKey", "testdata/ecdsapk8.key", &ecdsa.PrivateKey{}, assert.NoError},
		{"TestUnsupportedPrivateKey", "testdata/dsa.key", nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tt.filename)
			if !tt.wantErr(t, err, fmt.Sprintf("ParsePrivateKey(%v)", tt.filename)) {
				return
			}
			if err != nil {
				return
			}
			assert.IsType(t, tt.wantType, got)
			switch got := got.(type) {
			case *rsa.PrivateKey:
				assert.NoError(t, got.Validate())
			case ed25519.PrivateKey:
				assert.Len(t, got.Seed(), 32)
			case *ecdsa.PrivateKey:
				assert.Equal(t, got.Curve.Params().Name, "P-521")
			default:
				assert.Fail(t, "invalid private key type", "unknown private key type: %T", got)
			}
		})
	}
}
