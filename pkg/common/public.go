package common

import (
	"golang.org/x/exp/slices"
	"strings"
)

// Public Key Algorithms
const (
	RSA     = "RSA"
	DSA     = "DSA"
	ECDSA   = "ECDSA"
	Ed25519 = "Ed25519"
)

var publicKeyAlgorithms = []string{
	RSA, DSA, ECDSA, Ed25519,
}

var PublicKeyAlgorithms = strings.Join(publicKeyAlgorithms, ", ")

func compareIgnoreCase(s string) func(string) bool {
	return func(e string) bool {
		return strings.EqualFold(s, e)
	}
}

func ValidPublicKeyAlgorithm(s string) bool {
	return slices.ContainsFunc(publicKeyAlgorithms, compareIgnoreCase(s))
}
