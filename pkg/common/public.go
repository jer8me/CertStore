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

// PublicKeyAlgorithms is a comma separated list of valid public key algorithms
var PublicKeyAlgorithms = strings.Join(publicKeyAlgorithms, ", ")

func compareIgnoreCase(s string) func(string) bool {
	return func(e string) bool {
		return strings.EqualFold(s, e)
	}
}

// ValidPublicKeyAlgorithm checks that the string s is a valid public key algorithm
// Public key algorithm names are not case-sensitive.
func ValidPublicKeyAlgorithm(s string) bool {
	return slices.ContainsFunc(publicKeyAlgorithms, compareIgnoreCase(s))
}
