package storage

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestGetPublicKeyAlgorithmId(t *testing.T) {

	// Connect to database
	username := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	db, err := OpenMySQL(username, password, dbName)
	if err != nil {
		require.NoError(t, err, "failed to open database '%s' for user '%s'", dbName, username)
	}
	defer db.Close()

	tests := []struct {
		name               string
		publicKeyAlgorithm string
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			"TestRSAPublicKeyAlgorithmId",
			"RSA",
			assert.NoError,
		},
		{
			"TestDSAPublicKeyAlgorithmId",
			"DSA",
			assert.NoError,
		},
		{
			"TestECDSAPublicKeyAlgorithmId",
			"ECDSA",
			assert.NoError,
		},
		{
			"TestEd25519PublicKeyAlgorithmId",
			"Ed25519",
			assert.NoError,
		},
		{
			"TestRSAPublicKeyAlgorithmId",
			"InvalidPublicKeyAlgorithm",
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
