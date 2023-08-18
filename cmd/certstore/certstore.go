package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/store"
	"os"
)

const version = "0.0.1"

// CertStore is an interface that contains all store operations.
type CertStore interface {
	GetCertificate(certificateId int64) (*store.Certificate, error)
	GetCertificates(searchFilters *store.SearchFilter) ([]*store.Certificate, error)
	GetCertificatePrivateKeyId(certificateId int64) (int64, error)
	GetPrivateKey(privateKeyId int64) (*store.PrivateKey, error)
	StorePrivateKey(privateKey *store.PrivateKey, linkCert bool) (int64, error)
	GetX509Certificate(certificateId int64) (*x509.Certificate, error)
	StoreX509Certificate(x509cert *x509.Certificate) (int64, error)
}

// RuntimeError represents an error that happened at runtime
// (i.e. after all parameters are validated)
type runtimeError struct{ err error }

func (re *runtimeError) Error() string {
	return re.err.Error()
}

func (re *runtimeError) Unwrap() error {
	return re.err
}

func NewRuntimeError(err error) error {
	return &runtimeError{err: err}
}

func errorExit(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func main() {
	// Open SQLite database
	db, err := openSQLite()
	if err != nil {
		errorExit(err)
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		errorExit(err)
	}

	cs := store.NewCertStore(db)
	cmd := newRootCommand(cs)
	if subCmd, err := cmd.ExecuteC(); err != nil {
		cmd.PrintErrf("Error: %v\n", err)
		var re *runtimeError
		if !errors.As(err, &re) {
			cmd.Println(subCmd.UsageString())
		}
		// Exit with an error code
		os.Exit(1)
	}
}
