package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

func StoreCertificate(db *sql.DB, cert *Certificate) error {

	// Get public key algorithm ID for string
	publicKeyAlgorithmId, err := GetPublicKeyAlgorithmId(db, cert.PublicKeyAlgorithm)
	if err != nil {
		return err
	}
	// Get signature algorithm ID for string
	signatureAlgorithmId, err := GetSignatureAlgorithmId(db, cert.SignatureAlgorithm)
	if err != nil {
		return err
	}
	// Get SAN types
	sanTypes, err := GetSANTypes(db)
	if err != nil {
		return err
	}
	// Get attribute types
	attributeTypes, err := GetAttributeTypes(db)
	if err != nil {
		return err
	}

	// Create context for transaction
	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Defer transaction rollback in case anything fails.
	defer tx.Rollback()

	// Create a new row in the album_order table.
	result, err := tx.ExecContext(ctx, "INSERT INTO Certificate (publicKey, publicKeyAlgorithm_id, version, "+
		"serialNumber, subject, issuer, notBefore, notAfter, signature, signatureAlgorithm_id, isCa, rawContent) "+
		"VALUE (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.PublicKey, publicKeyAlgorithmId, cert.Version, cert.SerialNumber, cert.SubjectCN, cert.IssuerCN,
		cert.NotBefore, cert.NotAfter, cert.Signature, signatureAlgorithmId, cert.IsCA, cert.RawContent)
	if err != nil {
		return err
	}
	// Get certificate ID from INSERT
	certificateId, err := result.LastInsertId()
	if err != nil {
		return err
	}
	// Associate key usages with certificate
	for _, keyUsage := range cert.KeyUsages {
		// Lookup key usage
		var keyUsageId int
		err = tx.QueryRow("SELECT id FROM KeyUsage WHERE name = ?", keyUsage).Scan(&keyUsageId)
		if err == sql.ErrNoRows {
			return fmt.Errorf("invalid key usage: %s", keyUsage)
		}
		if err != nil {
			return fmt.Errorf("failed to query key usage ID: %w", err)
		}
		// Insert
		_, err = tx.ExecContext(ctx, "INSERT INTO CertificateKeyUsage (certificate_id, keyUsage_id) VALUE (?, ?)",
			certificateId, keyUsageId)
		if err != nil {
			return fmt.Errorf("failed to insert CertificateKeyUsage: %w", err)
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
			return fmt.Errorf("failed to insert %s CertificateAttribute: %w", Issuer, err)
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
			return fmt.Errorf("failed to insert %s CertificateAttribute: %w", Subject, err)
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
				return err
			}
			// Get SubjectAlternateName ID from INSERT
			sanId, err := result.LastInsertId()
			if err != nil {
				return err
			}
			// Associate SAN ID with certificate
			_, err = tx.ExecContext(ctx, "INSERT INTO CertificateSAN (certificate_id, subjectAlternateName_id) "+
				"VALUE (?, ?)", certificateId, sanId)
			if err != nil {
				return fmt.Errorf("failed to insert CertificateSAN: %w", err)
			}
		}
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit StoreCertificate transaction: %w", err)
	}

	return err
}

// GetPublicKeyAlgorithmId looks up the ID for a PublicKeyAlgorithm string
// Error is not nil if the string is invalid or if the database query fails
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

// GetSignatureAlgorithmId looks up the ID for a SignatureAlgorithm string
// Error is not nil if the string is invalid or if the database query fails
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

func knownOid(oid string, attributeTypes []AttributeType) bool {
	for _, attributeType := range attributeTypes {
		if attributeType.Oid == oid {
			return true
		}
	}
	return false
}
