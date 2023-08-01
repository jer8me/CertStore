package common

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// HashHex computes a hash and returns the result as a hexadecimal encoded string.
func HashHex(data []byte, f func() hash.Hash) string {
	h := f()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// SHA256Hex computes a SHA-256 hash and returns the result as a hexadecimal encoded string.
func SHA256Hex(data []byte) string {
	return HashHex(data, sha256.New)
}
