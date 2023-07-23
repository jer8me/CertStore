package storage

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"log"
)

func GetCertificate(db *sql.DB, certificateId int64) (*Certificate, error) {
	cert := &Certificate{Id: certificateId}
	var publicKeyAlgorithmId int
	var signatureAlgorithmId int
	// Fetch Certificate object
	err := db.QueryRow("SELECT publicKey, publicKeyAlgorithm_id, version, serialNumber, subject, issuer, notBefore, "+
		"notAfter, signature, signatureAlgorithm_id, isCa, rawContent FROM Certificate WHERE id = ?", certificateId).
		Scan(&cert.PublicKey, &publicKeyAlgorithmId, &cert.Version, &cert.SerialNumber, &cert.SubjectCN, &cert.IssuerCN,
			&cert.NotBefore, &cert.NotAfter, &cert.Signature, &signatureAlgorithmId, &cert.IsCA, &cert.RawContent)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid certificate ID: %d", certificateId)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate ID %d: %w", certificateId, err)
	}
	// Fetch Public Key Algorithm by ID
	cert.PublicKeyAlgorithm, err = GetPublicKeyAlgorithmName(db, publicKeyAlgorithmId)
	if err != nil {
		return nil, fmt.Errorf("failed to query public key algorithm name: %w", err)
	}

	// Fetch Signature Algorithm by ID
	cert.SignatureAlgorithm, err = GetSignatureAlgorithmName(db, signatureAlgorithmId)
	if err != nil {
		return nil, fmt.Errorf("failed to query signature algorithm name: %w", err)
	}

	// Fetch Subject Attributes for this certificate ID
	cert.Subject, err = GetCertificateAttributes(db, certificateId, Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate %s attributes: %w", Subject, err)
	}

	// Fetch Issuer Attributes for this certificate ID
	cert.Issuer, err = GetCertificateAttributes(db, certificateId, Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate %s attributes: %w", Issuer, err)
	}

	// Fetch Key Usages for this certificate ID
	cert.KeyUsages, err = GetCertificateKeyUsages(db, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to query key usages: %w", err)
	}

	// Fetch SANs for this certificate ID
	cert.SANs, err = GetCertificateSANs(db, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to query SANs: %w", err)
	}

	return cert, nil
}

func GetX509Certificate(db *sql.DB, certificateId int64) (*x509.Certificate, error) {
	var der []byte
	// Fetch raw certificate
	err := db.QueryRow("SELECT rawContent FROM Certificate WHERE id = ?", certificateId).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GetX509Certificate: invalid certificate ID: %d", certificateId)
	}
	if err != nil {
		return nil, fmt.Errorf("GetX509Certificate: failed to query certificate ID %d: %w", certificateId, err)
	}
	x509Certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("GetX509Certificate: failed to parse certificate ID %d: %w", certificateId, err)
	}
	return x509Certificate, nil
}

func GetCertificates(db *sql.DB) ([]*Certificate, error) {
	rows, err := db.Query("SELECT c.id, pka.name, c.version, c.serialNumber, c.subject, c.issuer, c.notBefore, " +
		"c.notAfter, c.isCa FROM Certificate c " +
		"INNER JOIN PublicKeyAlgorithm pka ON c.publicKeyAlgorithm_id = pka.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// A map of string slices to hold data from returned rows.
	// The key of the map is the type of the SAN (DNSName, EmailAddress, URI...).
	// The value is a slice of strings containing the SANs for the type.
	var certificates []*Certificate

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		cert := &Certificate{}
		if err := rows.Scan(&cert.Id, &cert.PublicKeyAlgorithm, &cert.Version, &cert.SerialNumber,
			&cert.SubjectCN, &cert.IssuerCN, &cert.NotBefore, &cert.NotAfter, &cert.IsCA); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return certificates, err
		}
		certificates = append(certificates, cert)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return certificates, err
	}
	return certificates, nil
}

func StoreCertificate(db *sql.DB, cert *Certificate) (int64, error) {

	// Get public key algorithm ID for string
	publicKeyAlgorithmId, err := GetPublicKeyAlgorithmId(db, cert.PublicKeyAlgorithm)
	if err != nil {
		return 0, err
	}
	// Get signature algorithm ID for string
	signatureAlgorithmId, err := GetSignatureAlgorithmId(db, cert.SignatureAlgorithm)
	if err != nil {
		return 0, err
	}
	// Get SAN types
	sanTypes, err := GetSANTypes(db)
	if err != nil {
		return 0, err
	}
	// Get attribute types
	attributeTypes, err := GetAttributeTypes(db)
	if err != nil {
		return 0, err
	}

	// Create context for transaction
	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	// Defer transaction rollback in case anything fails.
	defer tx.Rollback()

	// Compute SHA-256 Fingerprint
	sha256Sum := sha256.Sum256(cert.RawContent)
	sha256Fingerprint := hex.EncodeToString(sha256Sum[:])

	// Check if this certificate already exists in the database
	var certificateId int64
	err = tx.QueryRow("SELECT id FROM Certificate WHERE sha256Fingerprint = ?", sha256Fingerprint).Scan(&certificateId)
	if err == nil {
		// Found matching certificate: return id
		return certificateId, nil
	} else if err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query certificate by SHA-256 fingerprint: %w", err)
	}

	// Create a new row in the album_order table.
	result, err := tx.ExecContext(ctx, "INSERT INTO Certificate (publicKey, publicKeyAlgorithm_id, version, "+
		"serialNumber, subject, issuer, notBefore, notAfter, signature, signatureAlgorithm_id, isCa, rawContent, "+
		"sha256Fingerprint) VALUE (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cert.PublicKey, publicKeyAlgorithmId,
		cert.Version, cert.SerialNumber, cert.SubjectCN, cert.IssuerCN, cert.NotBefore, cert.NotAfter,
		cert.Signature, signatureAlgorithmId, cert.IsCA, cert.RawContent, sha256Fingerprint)
	if err != nil {
		return 0, err
	}
	// Get certificate ID from INSERT
	certificateId, err = result.LastInsertId()
	if err != nil {
		return 0, err
	}
	// Associate key usages with certificate
	for _, keyUsage := range cert.KeyUsages {
		// Lookup key usage
		var keyUsageId int
		err = tx.QueryRow("SELECT id FROM KeyUsage WHERE name = ?", keyUsage).Scan(&keyUsageId)
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("invalid key usage: %s", keyUsage)
		}
		if err != nil {
			return 0, fmt.Errorf("failed to query key usage ID: %w", err)
		}
		// Insert
		_, err = tx.ExecContext(ctx, "INSERT INTO CertificateKeyUsage (certificate_id, keyUsage_id) VALUE (?, ?)",
			certificateId, keyUsageId)
		if err != nil {
			return 0, fmt.Errorf("failed to insert CertificateKeyUsage: %w", err)
		}
	}

	// Store Issuer attributes
	for _, attribute := range cert.Issuer {
		if !knownOid(attribute.Oid, attributeTypes) {
			log.Printf("unknown %s attribute OID: %s, value: %s\n", Issuer, attribute.Oid, attribute.Value)
			continue
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO CertificateAttribute (certificate_id, type, oid, value) "+
			"VALUE (?, ?, ?, ?)", certificateId, Issuer, attribute.Oid, attribute.Value)
		if err != nil {
			return 0, fmt.Errorf("failed to insert %s CertificateAttribute: %w", Issuer, err)
		}
	}

	// Store Subject attributes
	for _, attribute := range cert.Subject {
		if !knownOid(attribute.Oid, attributeTypes) {
			log.Printf("unknown %s attribute OID: %s, value: %s\n", Subject, attribute.Oid, attribute.Value)
			continue
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO CertificateAttribute (certificate_id, type, oid, value) "+
			"VALUE (?, ?, ?, ?)", certificateId, Subject, attribute.Oid, attribute.Value)
		if err != nil {
			return 0, fmt.Errorf("failed to insert %s CertificateAttribute: %w", Subject, err)
		}
	}

	// Store Subject Alternate Name
	for certSanType, certSanValues := range cert.SANs {
		if len(certSanValues) == 0 {
			// No values: nothing to store
			continue
		}
		var sanTypeId int
		found := false
		// Find SAN Type ID
		for _, sanType := range sanTypes {
			if certSanType == sanType.Name {
				sanTypeId = sanType.Id
				found = true
				break
			}
		}
		if !found {
			// If we cannot find a valid type, something is badly misconfigured: panic
			log.Panicf("certificate SAN type %s not found in database", certSanType)
		}
		// Store SAN values for this SAN type
		for _, certSanValue := range certSanValues {
			result, err = tx.ExecContext(ctx, "INSERT INTO SubjectAlternateName (name, subjectAlternateNameType_id) "+
				"VALUE (?, ?)", certSanValue, sanTypeId)
			if err != nil {
				return 0, err
			}
			// Get SubjectAlternateName ID from INSERT
			sanId, err := result.LastInsertId()
			if err != nil {
				return 0, err
			}
			// Associate SAN ID with certificate
			_, err = tx.ExecContext(ctx, "INSERT INTO CertificateSAN (certificate_id, subjectAlternateName_id) "+
				"VALUE (?, ?)", certificateId, sanId)
			if err != nil {
				return 0, fmt.Errorf("failed to insert CertificateSAN: %w", err)
			}
		}
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit StoreCertificate transaction: %w", err)
	}

	return certificateId, err
}

// StoreX509Certificate stores an X.509 certificate structure into the database
func StoreX509Certificate(db *sql.DB, x509cert *x509.Certificate) (int64, error) {
	// Transform x509 certificate to certificate DB model
	certificate := ToCertificate(x509cert)
	return StoreCertificate(db, certificate)
}

func StorePrivateKey(db *sql.DB, privateKey *common.PrivateKey) (int64, error) {

	// Marshal private key into a byte slice in PKCS 8 form
	pkBytes, err := x509.MarshalPKCS8PrivateKey(privateKey.PrivateKey)
	if err != nil {
		return 0, err
	}

	// Get the corresponding public key to calculate the fingerprint.
	// We must compute the fingerprint of the public key, not the private key.
	publicKey := privateKey.PublicKey()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return 0, err
	}
	sha256Sum := sha256.Sum256(pubBytes)
	sha256Fingerprint := hex.EncodeToString(sha256Sum[:])

	// Get private key type ID
	privateKeyTypeId, err := GetPrivateKeyTypeId(db, privateKey.Type())
	if err != nil {
		return 0, err
	}

	// Create context for transaction
	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	// Defer transaction rollback in case anything fails.
	defer tx.Rollback()

	// Check if this private key already exists in the database
	var privateKeyId int64
	err = tx.QueryRow("SELECT id FROM PrivateKey WHERE sha256Fingerprint = ?", sha256Fingerprint).Scan(&privateKeyId)
	if err == nil {
		// Found matching private key: return id
		return privateKeyId, nil
	} else if err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query private key by SHA-256 fingerprint: %w", err)
	}

	dataEncryptionKey := []byte{0x01, 0x02}
	result, err := tx.Exec("INSERT INTO PrivateKey (encryptedPkcs8, privateKeyType_id, pemType, sha256Fingerprint, "+
		"dataEncryptionKey) VALUE (?, ?, ?, ?, ?)", pkBytes, privateKeyTypeId, privateKey.PEMType, sha256Fingerprint, dataEncryptionKey)
	if err != nil {
		return 0, err
	}
	// Get PrivateKey ID from INSERT
	privateKeyId, err = result.LastInsertId()
	if err != nil {
		return 0, err
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit StorePrivateKey transaction: %w", err)
	}

	return privateKeyId, nil
}

func GetPrivateKey(db *sql.DB, privateKeyId int64) (*common.PrivateKey, error) {
	var privateKeyBytes []byte
	var dataEncryptionKey []byte
	var pemType string

	// Fetch Private Key
	err := db.QueryRow("SELECT encryptedPkcs8, pemType, dataEncryptionKey FROM PrivateKey WHERE id = ?", privateKeyId).
		Scan(&privateKeyBytes, &pemType, &dataEncryptionKey)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid private key ID: %d", privateKeyId)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query private key ID %d: %w", privateKeyId, err)
	}

	// Parse private key bytes into a private key object
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key ID %d: %w", privateKeyId, err)
	}
	privateKey = privateKey.(crypto.PrivateKey)

	return common.NewPrivateKey(pemType, privateKey), nil
}

// GetPublicKeyAlgorithmId looks up the ID for a PublicKeyAlgorithm string
// Error is not nil if the string is invalid or if the database query fails.
func GetPublicKeyAlgorithmId(db *sql.DB, publicKeyAlgorithm string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM PublicKeyAlgorithm WHERE name = ?", publicKeyAlgorithm).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("invalid public key algorithm name: %s", publicKeyAlgorithm)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query public key algorithm ID: %w", err)
	}
	return id, nil
}

// GetPublicKeyAlgorithmName looks up the name for a PublicKeyAlgorithm based on its ID.
// Error is not nil if the ID is invalid or if the database query fails.
func GetPublicKeyAlgorithmName(db *sql.DB, publicKeyAlgorithmId int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM PublicKeyAlgorithm WHERE id = ?", publicKeyAlgorithmId).Scan(&name)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid public key algorithm ID: %d", publicKeyAlgorithmId)
	}
	if err != nil {
		return "", fmt.Errorf("failed to query public key algorithm ID: %w", err)
	}
	return name, nil
}

// GetSignatureAlgorithmId looks up the ID for a SignatureAlgorithm string
// Error is not nil if the string is invalid or if the database query fails.
func GetSignatureAlgorithmId(db *sql.DB, signatureAlgorithm string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM SignatureAlgorithm WHERE name = ?", signatureAlgorithm).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("invalid signature algorithm name: %s", signatureAlgorithm)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query signature algorithm ID: %w", err)
	}
	return id, nil
}

// GetSignatureAlgorithmName looks up the name for a SignatureAlgorithm based on its ID.
// Error is not nil if the ID is invalid or if the database query fails.
func GetSignatureAlgorithmName(db *sql.DB, signatureAlgorithmId int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM SignatureAlgorithm WHERE id = ?", signatureAlgorithmId).Scan(&name)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid signature algorithm ID: %d", signatureAlgorithmId)
	}
	if err != nil {
		return "", fmt.Errorf("failed to query signature algorithm ID: %w", err)
	}
	return name, nil
}

// GetPrivateKeyTypeId looks up the ID for a PrivateKeyType string
// Error is not nil if the string is invalid or if the database query fails.
func GetPrivateKeyTypeId(db *sql.DB, privateKeyType string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM PrivateKeyType WHERE type = ?", privateKeyType).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("invalid private key type name: %s", privateKeyType)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query private key type ID: %w", err)
	}
	return id, nil
}

// GetCertificateKeyUsages looks up the key usage names for a certificate ID.
// Error is not nil if the ID is invalid or if the database query fails.
func GetCertificateKeyUsages(db *sql.DB, certificateId int64) ([]string, error) {

	rows, err := db.Query("SELECT name FROM CertificateKeyUsage cks "+
		"INNER JOIN KeyUsage ku ON cks.keyUsage_id = ku.id "+
		"WHERE certificate_id = ?", certificateId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// A slice of strings to hold data from returned rows.
	var keyUsages []string

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var keyUsage string
		if err := rows.Scan(&keyUsage); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return keyUsages, err
		}
		keyUsages = append(keyUsages, keyUsage)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return keyUsages, err
	}
	return keyUsages, nil
}

// GetSANTypes returns a slice of SAN type as stored in the database
func GetSANTypes(db *sql.DB) ([]SANType, error) {

	rows, err := db.Query("SELECT id, name FROM SubjectAlternateNameType")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// A SANType slice to hold data from returned rows.
	var sanTypes []SANType

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var sanType SANType
		if err := rows.Scan(&sanType.Id, &sanType.Name); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return sanTypes, err
		}
		sanTypes = append(sanTypes, sanType)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return sanTypes, err
	}
	return sanTypes, nil
}

// GetCertificateSANs looks up the subject alternate names (SANs) for a certificate ID.
// Error is not nil if the ID is invalid or if the database query fails.
func GetCertificateSANs(db *sql.DB, certificateId int64) (map[string][]string, error) {

	rows, err := db.Query("SELECT san.name sanName, sanType.name sanType FROM CertificateSan cs "+
		"INNER JOIN SubjectAlternateName san ON cs.subjectAlternateName_id = san.id "+
		"INNER JOIN SubjectAlternateNameType sanType ON san.subjectAlternateNameType_id = sanType.id "+
		"WHERE certificate_id = ?", certificateId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// A map of string slices to hold data from returned rows.
	// The key of the map is the type of the SAN (DNSName, EmailAddress, URI...).
	// The value is a slice of strings containing the SANs for the type.
	sans := make(map[string][]string)

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var sanName, sanType string
		if err := rows.Scan(&sanName, &sanType); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return sans, err
		}
		sans[sanType] = append(sans[sanType], sanName)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return sans, err
	}
	return sans, nil
}

func GetAttributeTypes(db *sql.DB) ([]AttributeType, error) {

	rows, err := db.Query("SELECT oid, name, description FROM AttributeType")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// An AttributeType slice to hold data from returned rows.
	var attributeTypes []AttributeType

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var attributeType AttributeType
		if err := rows.Scan(&attributeType.Oid, &attributeType.Name, &attributeType.Description); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return attributeTypes, err
		}
		attributeTypes = append(attributeTypes, attributeType)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return attributeTypes, err
	}
	return attributeTypes, nil
}

// GetCertificateAttributes fetches the list of attributes for the certificate ID and the attribute type provided.
// Error is not nil if the ID is invalid or if the database query fails.
func GetCertificateAttributes(db *sql.DB, certificateId int64, attributeType string) ([]Attribute, error) {

	rows, err := db.Query("SELECT oid, value FROM CertificateAttribute attr "+
		"WHERE certificate_id = ? AND attr.type = ?", certificateId, attributeType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// An Attribute slice to hold data from returned rows.
	var attributes []Attribute

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var attribute Attribute
		if err := rows.Scan(&attribute.Oid, &attribute.Value); err != nil {
			// Error happened while scanning rows: return the rows we scanned so far and the error
			return attributes, err
		}
		attributes = append(attributes, attribute)
	}
	// Check if an error happened during the iteration
	if err = rows.Err(); err != nil {
		return attributes, err
	}
	return attributes, nil
}

func knownOid(oid string, attributeTypes []AttributeType) bool {
	for _, attributeType := range attributeTypes {
		if attributeType.Oid == oid {
			return true
		}
	}
	return false
}
