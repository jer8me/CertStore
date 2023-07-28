package storage

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"golang.org/x/crypto/scrypt"
	"log"
	"strconv"
	"strings"
	"time"
)

type Attribute struct {
	Oid   string
	Value string
}

type Attributes []Attribute

// Certificate represents the database model for a certificate
type Certificate struct {
	Id                 int64
	PublicKey          []byte
	PublicKeyAlgorithm string
	Version            int
	SerialNumber       string
	Subject            Attributes
	Issuer             Attributes
	SubjectCN          string
	IssuerCN           string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyUsages          []string
	Signature          []byte
	SignatureAlgorithm string
	SANs               map[string][]string
	IsCA               bool
	RawContent         []byte
	PrivateKeyId       sql.NullInt64
}

type AttributeType struct {
	Oid         string
	Name        string
	Description string
}

type SANType struct {
	Id   int
	Name string
}

// PrivateKey represents the database model for a private key
type PrivateKey struct {
	Id                int64
	EncryptedPKCS8    []byte
	Type              string
	PEMType           string
	DataEncryptionKey string
	SHA256Fingerprint string
}

const (
	DnsName      = "DNSName"
	EmailAddress = "EmailAddress"
	IpAddress    = "IPAddress"
	URI          = "URI"
)

const (
	Issuer  = "Issuer"
	Subject = "Subject"
)

// ToCertificate converts a x509 certificate into a certificate database model
func ToCertificate(x509certificate *x509.Certificate) *Certificate {
	return &Certificate{
		PublicKey:          x509certificate.RawSubjectPublicKeyInfo,
		PublicKeyAlgorithm: x509certificate.PublicKeyAlgorithm.String(),
		Version:            x509certificate.Version,
		SerialNumber:       GetSerialNumber(x509certificate),
		Subject:            GetAttributes(x509certificate.Subject),
		Issuer:             GetAttributes(x509certificate.Issuer),
		SubjectCN:          x509certificate.Subject.CommonName,
		IssuerCN:           x509certificate.Issuer.CommonName,
		NotBefore:          x509certificate.NotBefore,
		NotAfter:           x509certificate.NotAfter,
		KeyUsages:          GetKeyUsages(x509certificate),
		Signature:          x509certificate.Signature,
		SignatureAlgorithm: x509certificate.SignatureAlgorithm.String(),
		SANs:               GetSANs(x509certificate),
		IsCA:               x509certificate.IsCA,
		RawContent:         x509certificate.Raw,
	}
}

// EncryptPrivateKey converts a PrivateKey into an encrypted private key database model
// password is the password used to derive a Key Encryption Key (KEK).
func EncryptPrivateKey(privateKey *common.PrivateKey, password string, salt []byte) (*PrivateKey, error) {

	// Generate a unique encryption key for this private key
	dek := common.GenerateCryptoRandom(32)

	// Compute a derived Key Encryption Key (KEK) from the password provided
	derivedKey, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	// Encrypt the DEK (data encryption key) with the derived KEK (key encryption key)
	encryptedDEK, err := common.EncryptGCM(dek, derivedKey)
	if err != nil {
		return nil, err
	}

	// Marshal private key into a byte slice in PKCS 8 form
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the private key with the DEK
	encryptedPKCS8, err := common.EncryptGCM(pkcs8, dek)

	// Get the corresponding public key to calculate the fingerprint.
	// We must compute the fingerprint of the public key, not the private key.
	publicKey, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	sha256Sum := sha256.Sum256(publicKey)

	return &PrivateKey{
		EncryptedPKCS8:    encryptedPKCS8,
		Type:              privateKey.Type(),
		PEMType:           privateKey.PEMType,
		DataEncryptionKey: hex.EncodeToString(encryptedDEK),
		SHA256Fingerprint: hex.EncodeToString(sha256Sum[:]),
	}, nil
}

// DecryptPrivateKey converts an encrypted private key database model into a common private key.
// password is the password used to derive a Key Encryption Key (KEK).
func DecryptPrivateKey(privateKey *PrivateKey, password string, salt []byte) (*common.PrivateKey, error) {

	// Decode hex encoded key into a byte slice
	encryptedDEK, err := hex.DecodeString(privateKey.DataEncryptionKey)
	if err != nil {
		return nil, err
	}

	// Compute a derived Key Encryption Key (KEK) from the password provided
	derivedKey, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	// Decrypt the DEK (Data Encryption Key) with the KEK (Key Encryption Key)
	dek, err := common.DecryptGCM(encryptedDEK, derivedKey)

	// Decrypt the PKCS8 private key with the DEK
	pkcs8, err := common.DecryptGCM(privateKey.EncryptedPKCS8, dek)
	if err != nil {
		return nil, err
	}

	// Parse private key bytes into a private key object
	pk, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	pk = pk.(crypto.PrivateKey)

	return common.NewPrivateKey(privateKey.PEMType, pk), nil
}

// GetSerialNumber returns the serial number of the certificate as a hex string
func GetSerialNumber(x509certificate *x509.Certificate) string {
	bytes := x509certificate.SerialNumber.Bytes()
	return hex.EncodeToString(bytes)
}

// GetAttributes extracts the attribute types and values from an X.509 distinguished name.
func GetAttributes(dn pkix.Name) []Attribute {
	var attributes []Attribute
	for _, rdn := range dn.Names {
		attribute := Attribute{
			Oid:   rdn.Type.String(),
			Value: fmt.Sprint(rdn.Value),
		}
		attributes = append(attributes, attribute)
	}
	return attributes
}

// GetKeyUsages returns a slice of strings representing the key usages included in the certificate
func GetKeyUsages(x509certificate *x509.Certificate) []string {
	var keyUsages []string
	if (x509certificate.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
		keyUsages = append(keyUsages, "DigitalSignature")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageContentCommitment) != 0 {
		keyUsages = append(keyUsages, "ContentCommitment")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageKeyEncipherment) != 0 {
		keyUsages = append(keyUsages, "KeyEncipherment")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageDataEncipherment) != 0 {
		keyUsages = append(keyUsages, "DataEncipherment")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageKeyAgreement) != 0 {
		keyUsages = append(keyUsages, "KeyAgreement")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageCertSign) != 0 {
		keyUsages = append(keyUsages, "KeyCertSign")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageCRLSign) != 0 {
		keyUsages = append(keyUsages, "CRLSign")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageEncipherOnly) != 0 {
		keyUsages = append(keyUsages, "EncipherOnly")
	}
	if (x509certificate.KeyUsage & x509.KeyUsageDecipherOnly) != 0 {
		keyUsages = append(keyUsages, "DecipherOnly")
	}
	return keyUsages
}

// GetSANs returns the map of Subject Alternate Name values declared in the certificate.
// The key of the map is a SubjectAlternateNameType and the value of the map is a slice of strings.
// The slice of strings contains the SAN values.
func GetSANs(x509certificate *x509.Certificate) map[string][]string {
	sans := make(map[string][]string)
	// DNS Names
	if len(x509certificate.DNSNames) > 0 {
		sans[DnsName] = x509certificate.DNSNames
	}
	if len(x509certificate.EmailAddresses) > 0 {
		sans[EmailAddress] = x509certificate.EmailAddresses
	}
	if len(x509certificate.IPAddresses) > 0 {
		var ipAddresses []string
		for _, ipAddress := range x509certificate.IPAddresses {
			ipAddresses = append(ipAddresses, ipAddress.String())
		}
		sans[IpAddress] = ipAddresses
	}
	if len(x509certificate.URIs) > 0 {
		var uris []string
		for _, uri := range x509certificate.URIs {
			uris = append(uris, uri.String())
		}
		sans[URI] = uris
	}
	return sans
}

func ToObjectIdentifier(oidstring string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidstring, ".")
	if len(parts) == 0 {
		return nil, errors.New("OID string is empty")
	}
	var err error
	oid := make(asn1.ObjectIdentifier, len(parts), len(parts))
	for i, part := range parts {
		oid[i], err = strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
	}
	return oid, nil
}

func (attributes Attributes) String() string {
	var pkixAttributes []pkix.AttributeTypeAndValue
	for _, attribute := range attributes {
		oid, err := ToObjectIdentifier(attribute.Oid)
		if err != nil {
			// If we have an invalid OID string here, something is very wrong with the data stored in the database
			log.Panicf("invalid OID string: %v", err)
		}
		pkixAttribute := pkix.AttributeTypeAndValue{
			Type:  oid,
			Value: attribute.Value,
		}
		pkixAttributes = append(pkixAttributes, pkixAttribute)
	}
	var rdns pkix.RDNSequence
	rdns = append(rdns, pkixAttributes)

	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name.String()
}
