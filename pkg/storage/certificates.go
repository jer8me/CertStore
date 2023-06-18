package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"log"
	"time"
)

// CertificateModel represents the database model for a certificate
type CertificateModel struct {
	Id                 int64
	PublicKey          []byte
	PublicKeyAlgorithm string
	Version            int
	SerialNumber       string
	Subject            string
	Issuer             string
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

type SANTypeModel struct {
	Id   int
	Name string
}

const (
	DnsName      = "DNSName"
	EmailAddress = "EmailAddress"
	IpAddress    = "IPAddress"
	URI          = "URI"
)

func OpenMySQL(userName, userPass, dbName string) (*sql.DB, error) {
	dbCfg := mysql.NewConfig()
	dbCfg.User = userName
	dbCfg.Passwd = userPass
	dbCfg.DBName = dbName

	connector, err := mysql.NewConnector(dbCfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// ToCertificate converts a x509 certificate into a certificate database model
func ToCertificate(x509certificate *x509.Certificate) (*CertificateModel, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(x509certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	certificateModel := &CertificateModel{
		PublicKey:          publicKey,
		PublicKeyAlgorithm: x509certificate.PublicKeyAlgorithm.String(),
		Version:            x509certificate.Version,
		SerialNumber:       GetSerialNumber(x509certificate),
		Subject:            x509certificate.Subject.CommonName,
		Issuer:             x509certificate.Issuer.CommonName,
		NotBefore:          x509certificate.NotBefore,
		NotAfter:           x509certificate.NotAfter,
		KeyUsages:          GetKeyUsages(x509certificate),
		Signature:          x509certificate.Signature,
		SignatureAlgorithm: x509certificate.SignatureAlgorithm.String(),
		SANs:               GetSANs(x509certificate),
		IsCA:               x509certificate.IsCA,
		RawContent:         x509certificate.Raw,
	}
	return certificateModel, nil
}

// GetSerialNumber returns the serial number of the certificate as a hex string
func GetSerialNumber(x509certificate *x509.Certificate) string {
	bytes := x509certificate.SerialNumber.Bytes()
	return hex.EncodeToString(bytes)
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
func GetSANTypes(db *sql.DB) ([]SANTypeModel, error) {

	rows, err := db.Query("SELECT id, name FROM SubjectAlternateNameType")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// An SANTypeModel slice to hold data from returned rows.
	var sanTypes []SANTypeModel

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var sanType SANTypeModel
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

func StoreCertificate(db *sql.DB, cert *CertificateModel) error {

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
		cert.PublicKey, publicKeyAlgorithmId, cert.Version, cert.SerialNumber, cert.Subject, cert.Issuer,
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
