package storage

// CertificateRepository is a database agnostic interface that represents a certificate repository
type CertificateRepository interface {
	// Open a connection to the repository
	Open() error
	Close() error
	StoreCertificate(cert *Certificate) error
}
