package storage

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"log"
	"strconv"
	"strings"
)

type CertStore struct {
	db *sql.DB
}

func NewCertStore(db *sql.DB) *CertStore {
	return &CertStore{db: db}
}

func (cs *CertStore) GetCertificate(certificateId int64) (*Certificate, error) {
	cert := &Certificate{Id: certificateId}
	var publicKeyAlgorithmId int
	var signatureAlgorithmId int
	// Fetch Certificate object
	err := cs.db.QueryRow("SELECT publicKey, publicKeyAlgorithm_id, version, serialNumber, subject, "+
		"issuer, notBefore, notAfter, signature, signatureAlgorithm_id, isCa, rawContent, privateKey_id "+
		"FROM Certificate WHERE id = ?", certificateId).Scan(&cert.PublicKey, &publicKeyAlgorithmId,
		&cert.Version, &cert.SerialNumber, &cert.SubjectCN, &cert.IssuerCN, &cert.NotBefore, &cert.NotAfter,
		&cert.Signature, &signatureAlgorithmId, &cert.IsCA, &cert.RawContent, &cert.PrivateKeyId)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid certificate ID: %d", certificateId)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate ID %d: %w", certificateId, err)
	}
	// Fetch Public Key Algorithm by ID
	cert.PublicKeyAlgorithm, err = GetPublicKeyAlgorithmName(cs.db, publicKeyAlgorithmId)
	if err != nil {
		return nil, fmt.Errorf("failed to query public key algorithm name: %w", err)
	}

	// Fetch Signature Algorithm by ID
	cert.SignatureAlgorithm, err = GetSignatureAlgorithmName(cs.db, signatureAlgorithmId)
	if err != nil {
		return nil, fmt.Errorf("failed to query signature algorithm name: %w", err)
	}

	// Fetch Subject Attributes for this certificate ID
	cert.Subject, err = GetCertificateAttributes(cs.db, certificateId, Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate %s attributes: %w", Subject, err)
	}

	// Fetch Issuer Attributes for this certificate ID
	cert.Issuer, err = GetCertificateAttributes(cs.db, certificateId, Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate %s attributes: %w", Issuer, err)
	}

	// Fetch Key Usages for this certificate ID
	cert.KeyUsages, err = GetCertificateKeyUsages(cs.db, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to query key usages: %w", err)
	}

	// Fetch SANs for this certificate ID
	cert.SANs, err = GetCertificateSANs(cs.db, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to query SANs: %w", err)
	}

	return cert, nil
}

func (cs *CertStore) StoreCertificate(cert *Certificate, linkCert bool) (int64, error) {

	// Get public key algorithm ID for string
	publicKeyAlgorithmId, err := GetPublicKeyAlgorithmId(cs.db, cert.PublicKeyAlgorithm)
	if err != nil {
		return 0, err
	}
	// Get signature algorithm ID for string
	signatureAlgorithmId, err := GetSignatureAlgorithmId(cs.db, cert.SignatureAlgorithm)
	if err != nil {
		return 0, err
	}
	// Get SAN types
	sanTypes, err := GetSANTypes(cs.db)
	if err != nil {
		return 0, err
	}
	// Get attribute types
	attributeTypes, err := GetAttributeTypes(cs.db)
	if err != nil {
		return 0, err
	}

	// Create context for transaction
	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	// Compute certificate SHA-256 Fingerprint
	sha256Fingerprint := common.SHA256Hex(cert.RawContent)

	// Compute public key SHA-256 Fingerprint
	sha256PublicKey := common.SHA256Hex(cert.PublicKey)

	// Check if this certificate already exists in the database
	var certificateId int64
	err = tx.QueryRow("SELECT id FROM Certificate WHERE sha256Fingerprint = ?", sha256Fingerprint).Scan(&certificateId)
	if err == nil {
		// Found matching certificate: return id
		rollback(tx)
		return certificateId, nil
	} else if err != sql.ErrNoRows {
		rollback(tx)
		return 0, fmt.Errorf("failed to query certificate by SHA-256 fingerprint: %w", err)
	}

	var privateKeyId sql.NullInt64
	if linkCert {
		// Check if this certificate corresponds to a known private key
		err = tx.QueryRow("SELECT id FROM PrivateKey WHERE sha256Fingerprint = ?", sha256PublicKey).Scan(&privateKeyId)
		if err == sql.ErrNoRows {
			privateKeyId.Valid = false
		} else if err != nil {
			// Query error
			rollback(tx)
			return 0, fmt.Errorf("failed to query private key by SHA-256 fingerprint: %w", err)
		}
	}

	// Create a new row in the album_order table.
	result, err := tx.Exec("INSERT INTO Certificate (publicKey, publicKeyAlgorithm_id, version, "+
		"serialNumber, subject, issuer, notBefore, notAfter, signature, signatureAlgorithm_id, isCa, rawContent, "+
		"sha256Fingerprint, sha256PublicKey, privateKey_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", cert.PublicKey,
		publicKeyAlgorithmId, cert.Version, cert.SerialNumber, cert.SubjectCN, cert.IssuerCN, cert.NotBefore, cert.NotAfter,
		cert.Signature, signatureAlgorithmId, cert.IsCA, cert.RawContent, sha256Fingerprint, sha256PublicKey, privateKeyId)
	if err != nil {
		rollback(tx)
		return 0, fmt.Errorf("failed to insert Certificate: %w", err)
	}
	// Get certificate ID from INSERT
	certificateId, err = result.LastInsertId()
	if err != nil {
		rollback(tx)
		return 0, err
	}
	// Associate key usages with certificate
	for _, keyUsage := range cert.KeyUsages {
		// Lookup key usage
		var keyUsageId int
		err = tx.QueryRow("SELECT id FROM KeyUsage WHERE name = ?", keyUsage).Scan(&keyUsageId)
		if err == sql.ErrNoRows {
			rollback(tx)
			return 0, fmt.Errorf("invalid key usage: %s", keyUsage)
		}
		if err != nil {
			rollback(tx)
			return 0, fmt.Errorf("failed to query key usage ID: %w", err)
		}
		// Insert
		_, err = tx.Exec("INSERT INTO CertificateKeyUsage (certificate_id, keyUsage_id) VALUES (?, ?)",
			certificateId, keyUsageId)
		if err != nil {
			rollback(tx)
			return 0, fmt.Errorf("failed to insert CertificateKeyUsage: %w", err)
		}
	}

	// Store Issuer attributes
	for _, attribute := range cert.Issuer {
		if !knownOid(attribute.Oid, attributeTypes) {
			log.Printf("unknown %s attribute OID: %s, value: %s\n", Issuer, attribute.Oid, attribute.Value)
			continue
		}
		_, err = tx.Exec("INSERT INTO CertificateAttribute (certificate_id, type, oid, value) "+
			"VALUES (?, ?, ?, ?)", certificateId, Issuer, attribute.Oid, attribute.Value)
		if err != nil {
			rollback(tx)
			return 0, fmt.Errorf("failed to insert %s CertificateAttribute: %w", Issuer, err)
		}
	}

	// Store Subject attributes
	for _, attribute := range cert.Subject {
		if !knownOid(attribute.Oid, attributeTypes) {
			log.Printf("unknown %s attribute OID: %s, value: %s\n", Subject, attribute.Oid, attribute.Value)
			continue
		}
		_, err = tx.Exec("INSERT INTO CertificateAttribute (certificate_id, type, oid, value) "+
			"VALUES (?, ?, ?, ?)", certificateId, Subject, attribute.Oid, attribute.Value)
		if err != nil {
			rollback(tx)
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
			result, err = tx.Exec("INSERT INTO SubjectAlternateName (name, subjectAlternateNameType_id) "+
				"VALUES (?, ?)", certSanValue, sanTypeId)
			if err != nil {
				rollback(tx)
				return 0, err
			}
			// Get SubjectAlternateName ID from INSERT
			sanId, err := result.LastInsertId()
			if err != nil {
				rollback(tx)
				return 0, err
			}
			// Associate SAN ID with certificate
			_, err = tx.Exec("INSERT INTO CertificateSAN (certificate_id, subjectAlternateName_id) "+
				"VALUES (?, ?)", certificateId, sanId)
			if err != nil {
				rollback(tx)
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

func (cs *CertStore) GetCertificates(searchFilters *SearchFilter) ([]*Certificate, error) {
	query, args := SearchQuery(searchFilters)
	rows, err := cs.db.Query(query, args...)
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
			&cert.SubjectCN, &cert.IssuerCN, &cert.NotBefore, &cert.NotAfter, &cert.IsCA, &cert.PrivateKeyId); err != nil {
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

func (cs *CertStore) GetCertificatePrivateKeyId(certificateId int64) (int64, error) {
	var privateKeyId sql.NullInt64
	// Fetch Certificate object
	err := cs.db.QueryRow("SELECT privateKey_id FROM Certificate WHERE id = ?", certificateId).Scan(&privateKeyId)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("invalid certificate ID: %d", certificateId)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query certificate ID %d: %w", certificateId, err)
	}
	if !privateKeyId.Valid {
		// Certificate does not have a private key
		return 0, errors.New("certificate does not have a private key")
	}
	return privateKeyId.Int64, nil
}

func (cs *CertStore) GetPrivateKey(privateKeyId int64) (*PrivateKey, error) {
	privateKey := &PrivateKey{Id: privateKeyId}
	// Fetch Private Key
	err := cs.db.QueryRow("SELECT pk.encryptedPkcs8, pkt.type, pk.pemType, pk.dataEncryptionKey, pk.SHA256Fingerprint FROM PrivateKey pk "+
		"INNER JOIN PrivateKeyType pkt ON pk.privateKeyType_id = pkt.id WHERE pk.id = ?", privateKeyId).Scan(&privateKey.EncryptedPKCS8,
		&privateKey.Type, &privateKey.PEMType, &privateKey.DataEncryptionKey, &privateKey.SHA256Fingerprint)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid private key ID: %d", privateKeyId)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query private key ID %d: %w", privateKeyId, err)
	}
	return privateKey, nil
}

func (cs *CertStore) StorePrivateKey(privateKey *PrivateKey, linkCert bool) (int64, error) {

	// Get private key type ID
	privateKeyTypeId, err := GetPrivateKeyTypeId(cs.db, privateKey.Type)
	if err != nil {
		return 0, err
	}

	// Create context for transaction
	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	// Check if this private key already exists in the database
	var privateKeyId int64
	err = tx.QueryRow("SELECT id FROM PrivateKey WHERE sha256Fingerprint = ?", privateKey.SHA256Fingerprint).Scan(&privateKeyId)
	if err == nil {
		// Found matching private key: return id
		rollback(tx)
		return privateKeyId, nil
	} else if err != sql.ErrNoRows {
		rollback(tx)
		return 0, fmt.Errorf("failed to query private key by SHA-256 fingerprint: %w", err)
	}

	var certificateIds []int64
	if linkCert {
		// Only store the private key if we can find one or more matching certificate
		certificateIds, err = FindCertificateByPublicKey(tx, privateKey.PublicKey)
		if err != nil {
			rollback(tx)
			return 0, err
		}
		if len(certificateIds) == 0 {
			rollback(tx)
			return 0, errors.New("cannot store private key, no matching certificate found")
		}
	}

	result, err := tx.Exec("INSERT INTO PrivateKey (encryptedPkcs8, publicKey, privateKeyType_id, pemType, "+
		"sha256Fingerprint, dataEncryptionKey) VALUES (?, ?, ?, ?, ?, ?)", privateKey.EncryptedPKCS8, privateKey.PublicKey,
		privateKeyTypeId, privateKey.PEMType, privateKey.SHA256Fingerprint, privateKey.DataEncryptionKey)
	if err != nil {
		rollback(tx)
		return 0, err
	}
	// Get PrivateKey ID from INSERT
	privateKeyId, err = result.LastInsertId()
	if err != nil {
		rollback(tx)
		return 0, err
	}

	if len(certificateIds) > 0 {
		// Update all corresponding certificates with the private key ID
		var query strings.Builder
		query.WriteString("UPDATE Certificate SET privateKey_id = ? WHERE id IN(")
		for i, certificateId := range certificateIds {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteString(strconv.FormatInt(certificateId, 10))
		}
		query.WriteByte(')')

		_, err = tx.Exec(query.String(), privateKeyId)
		if err != nil {
			rollback(tx)
			return 0, err
		}
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit StorePrivateKey transaction: %w", err)
	}

	return privateKeyId, nil
}

func (cs *CertStore) GetX509Certificate(certificateId int64) (*x509.Certificate, error) {
	var der []byte
	// Fetch raw certificate
	err := cs.db.QueryRow("SELECT rawContent FROM Certificate WHERE id = ?", certificateId).Scan(&der)
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

// StoreX509Certificate stores an X.509 certificate structure into the database
func (cs *CertStore) StoreX509Certificate(x509cert *x509.Certificate) (int64, error) {
	// Transform x509 certificate to certificate DB model
	certificate := ToCertificate(x509cert)
	return cs.StoreCertificate(certificate, true)
}

func SearchQuery(searchFilters *SearchFilter) (string, []any) {
	qb := NewQueryBuilder()
	qb.WriteString("SELECT c.id, pka.name, c.version, c.serialNumber, c.subject, c.issuer, c.notBefore, c.notAfter, c.isCa, c.privateKey_id ")
	qb.WriteString("FROM Certificate c INNER JOIN PublicKeyAlgorithm pka ON c.publicKeyAlgorithm_id = pka.id ")
	// Setup potential filtering
	qb.WriteString("WHERE c.id IN(")
	if !searchFilters.ExpireBefore.IsZero() {
		qb.FilterCompare("SELECT DISTINCT id FROM Certificate WHERE notAfter", "<", searchFilters.ExpireBefore)
	}
	qb.FilterLike("SELECT DISTINCT cs.certificate_id FROM SubjectAlternateName sa JOIN CertificateSAN cs ON sa.id = cs.subjectAlternateName_id WHERE sa.name", searchFilters.San)
	qb.FilterLike("SELECT DISTINCT id FROM Certificate WHERE serialNumber", searchFilters.Serial)
	qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND value", searchFilters.Issuer)
	if searchFilters.Issuer == "" {
		// If the global Issuer search is not used, look into each Issuer field
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.3' AND value", searchFilters.IssuerCn)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.6' AND value", searchFilters.IssuerCountry)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.7' AND value", searchFilters.IssuerLocality)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.8' AND value", searchFilters.IssuerState)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.9' AND value", searchFilters.IssuerStreet)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.10' AND value", searchFilters.IssuerOrg)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.11' AND value", searchFilters.IssuerOrgUnit)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Issuer' AND oid = '2.5.4.17' AND value", searchFilters.IssuerPostalCode)
	}
	qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND value", searchFilters.Subject)
	if searchFilters.Subject == "" {
		// If the global Subject search is not used, look into each Subject field
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.3' AND value", searchFilters.SubjectCn)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.6' AND value", searchFilters.SubjectCountry)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.7' AND value", searchFilters.SubjectLocality)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.8' AND value", searchFilters.SubjectState)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.9' AND value", searchFilters.SubjectStreet)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.10' AND value", searchFilters.SubjectOrg)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.11' AND value", searchFilters.SubjectOrgUnit)
		qb.FilterLike("SELECT DISTINCT certificate_id FROM CertificateAttribute WHERE type = 'Subject' AND oid = '2.5.4.17' AND value", searchFilters.SubjectPostalCode)
	}
	// Public Key Algorithms
	if len(searchFilters.PublicKeyAlgorithms) > 0 {
		// Convert all string values to upper case because the IN operator is case-insensitive
		var pkas []any
		for _, pka := range searchFilters.PublicKeyAlgorithms {
			pkas = append(pkas, strings.ToUpper(pka))
		}
		qb.FilterIn("SELECT DISTINCT cert.id FROM Certificate cert JOIN PublicKeyAlgorithm pka ON cert.publicKeyAlgorithm_id = pka.id WHERE UPPER(pka.name)", pkas)
	}
	// Is CA
	isCA := -1
	if searchFilters.IsCA {
		isCA = 1
	} else if searchFilters.NotCA {
		isCA = 0
	}
	if (isCA == 0) || (isCA == 1) {
		qb.FilterCompare("SELECT DISTINCT id FROM Certificate WHERE isCa", "=", isCA)
	}
	// Has Private Key
	var condition string
	if searchFilters.HasPrivateKey {
		condition = "NOT NULL"
	} else if searchFilters.NoPrivateKey {
		condition = "IS NULL"
	}
	if condition != "" {
		qb.Filter("SELECT DISTINCT id FROM Certificate WHERE privateKey_id ", condition)
	}

	if !qb.HasFilter {
		// No filtering: include all certificate IDs
		qb.WriteString("c.id")
	}
	qb.WriteString(")")

	return qb.String(), qb.Args
}

// FindCertificateByPublicKey returns a slice of certificate IDs with the public key provided
func FindCertificateByPublicKey(tx *sql.Tx, publicKey []byte) ([]int64, error) {
	// Compute SHA-256
	sha256PublicKey := common.SHA256Hex(publicKey)

	rows, err := tx.Query("SELECT id, publicKey FROM Certificate WHERE sha256PublicKey = ?", sha256PublicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Slice of certificate IDs matching this private key's public key
	var certificateIds []int64
	for rows.Next() {
		var certificateId int64
		var certPublicKey []byte
		if err := rows.Scan(&certificateId, &certPublicKey); err != nil {
			return nil, err
		}
		if bytes.Equal(publicKey, certPublicKey) {
			// Found a certificate matching this public key
			certificateIds = append(certificateIds, certificateId)
		}
	}
	// Close rows
	rerr := rows.Close()
	if rerr != nil {
		return nil, rerr
	}
	// Rows.Err reports the last error encountered by Rows.Scan.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificateIds, nil
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
