package storage

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"time"
)

// CertificateModel represents the database model for a certificate
type CertificateModel struct {
	Id                 int64
	PublicKey          []byte
	PublicKeyAlgorithm int
	Version            int
	SerialNumber       string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	Signature          []byte
	SignatureAlgorithm int
	RawContent         []byte
	PrivateKeyId       sql.NullInt64
}

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
func ToCertificate(db *sql.DB, x509certificate x509.Certificate) (*CertificateModel, error) {
	var err error
	certificateModel := new(CertificateModel)
	certificateModel.PublicKey, err = x509.MarshalPKIXPublicKey(x509certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	certificateModel.PublicKeyAlgorithm, err = GetPublicKeyAlgorithmId(db, x509certificate.PublicKeyAlgorithm.String())
	if err != nil {
		return nil, err
	}
	certificateModel.Version = x509certificate.Version
	certificateModel.SerialNumber = x509certificate.SerialNumber.Text(16)
	certificateModel.Subject = x509certificate.Subject.CommonName
	certificateModel.Issuer = x509certificate.Issuer.CommonName
	certificateModel.NotBefore = x509certificate.NotBefore
	certificateModel.NotAfter = x509certificate.NotAfter
	certificateModel.Signature = x509certificate.Signature
	certificateModel.SignatureAlgorithm, err = GetSignatureAlgorithmId(db, x509certificate.SignatureAlgorithm.String())
	if err != nil {
		return nil, err
	}
	certificateModel.RawContent = x509certificate.Raw

	return certificateModel, nil
}

// GetPublicKeyAlgorithmId looks up the ID for a PublicKeyAlgorithm string
// Error is not nil if the string is invalid or if the database query fails
func GetPublicKeyAlgorithmId(db *sql.DB, publicKeyAlgorithm string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM publickeyalgorithm WHERE name = ?", publicKeyAlgorithm).Scan(&id)
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
	err := db.QueryRow("SELECT id FROM signaturealgorithm WHERE name = ?", signatureAlgorithm).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("invalid signature algorithm name: %s", signatureAlgorithm)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query signature algorithm ID: %w", err)
	}
	return id, nil
}
