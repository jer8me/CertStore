package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidPublicKeyAlgorithm(t *testing.T) {
	tests := []struct {
		pka  string
		want bool
	}{
		{"", false},
		{"RSA", true},
		{"rsa", true},
		{"DSA", true},
		{"ECDSA", true},
		{"EcDsA", true},
		{"ed25519", true},
		{"Ed25519", true},
		{"ED25519", true},
		{"RS", false},
		{"RSA ", false},
		{" RSA", false},
	}
	for _, tt := range tests {
		name := "Test" + tt.pka
		t.Run(name, func(t *testing.T) {
			assert.Equalf(t, tt.want, ValidPublicKeyAlgorithm(tt.pka), "ValidPublicKeyAlgorithm(%v)", tt.pka)
		})
	}
}
