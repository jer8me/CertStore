package certstore

import (
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/storage"
)

func StoreCertificate(certPath, userName, userPassword, dbName string) error {

	// Read certificate file
	x509cert, err := certificates.ParsePEMFile(certPath)
	if err != nil {
		return err
	}
	// Transform x509 certificate to certificate DB model
	certificate, err := storage.ToCertificate(x509cert)
	if err != nil {
		return err
	}

	// Connect to database
	db, err := storage.OpenMySqlDB(userName, userPassword, dbName)
	if err != nil {
		return err
	}
	defer db.Close()

	return storage.StoreCertificate(db, certificate)
}
