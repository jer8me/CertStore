package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
)

var AuthError = errors.New("authentication error")

// GenerateCryptoRandom generates cryptographically random bytes of the size specified.
// For AES encryption, the size should be 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func GenerateCryptoRandom(size int) []byte {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Panicf("failed to generate random bytes: %s", err)
	}
	return key
}

// EncryptGCM encrypts a byte array with the key provided.
// Returns an error if the data cannot be encrypted.
func EncryptGCM(data []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Generate a random nonce
	// The nonce must be random but does not need to be secure - we still store it alongside the ciphertext
	nonce := GenerateCryptoRandom(aesgcm.NonceSize())
	// Allocate an array of bytes for the ciphertext
	// The format of the ciphertext is: [NONCE][ENCRYPTED DATA][SIGNATURE]
	size := aesgcm.NonceSize() + len(data) + aesgcm.Overhead()
	ciphertext := make([]byte, 0, size)
	ciphertext = append(ciphertext, nonce...)
	ciphertext = aesgcm.Seal(ciphertext, nonce, data, nil)

	return ciphertext, nil
}

// DecryptGCM decrypts an encrypted byte array with the key provided.
// Returns an error if the data cannot be decrypted.
func DecryptGCM(ciphertext []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Extract the nonce
	nonce := ciphertext[0:aesgcm.NonceSize()]
	// Decrypt and authenticate ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[aesgcm.NonceSize():], nil)
	if err != nil {
		// The message could not be authenticated: wrap the error in an AuthError
		return nil, errors.Join(AuthError, err)
	}
	return plaintext, nil
}
