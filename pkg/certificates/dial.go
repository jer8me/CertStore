package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/exp/slices"
	"net"
	"time"
)

func DownloadCertificates(addr string) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Return a copy of the certificates attached to the connection
	return slices.Clone(conn.ConnectionState().PeerCertificates), nil
}
