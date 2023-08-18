package main

import (
	"crypto/x509"
	"fmt"
	"github.com/jer8me/CertStore/pkg/store"
	"os"
)

const version = "0.0.1"

type CertStore interface {
	GetCertificate(certificateId int64) (*store.Certificate, error)
	GetCertificates(searchFilters *store.SearchFilter) ([]*store.Certificate, error)
	GetCertificatePrivateKeyId(certificateId int64) (int64, error)
	GetPrivateKey(privateKeyId int64) (*store.PrivateKey, error)
	StorePrivateKey(privateKey *store.PrivateKey, linkCert bool) (int64, error)
	GetX509Certificate(certificateId int64) (*x509.Certificate, error)
	StoreX509Certificate(x509cert *x509.Certificate) (int64, error)
}

func errorExit(format string, v ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, v...)
	os.Exit(1)
}

func main() {
	// Open SQLite database
	db, err := openSQLite()
	if err != nil {
		errorExit("%s", err)
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		errorExit("%s", err)
	}

	cs := store.NewCertStore(db)
	cmd := newRootCommand(cs)
	if err := cmd.Execute(); err != nil {
		// Exit with an error code
		os.Exit(1)
	}
}
