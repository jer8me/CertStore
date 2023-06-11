package storage

import (
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
