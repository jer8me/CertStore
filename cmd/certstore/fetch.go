package main

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/spf13/cobra"
	"net"
	"os"
)

// ensureHostPort ensure that the address has a valid port number.
// If no port is specified, we add the default HTTPS port: 443
func ensureHostPort(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("invalid address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

func newFetchCommand(cs CertStore) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch address [...address]",
		Args:  cobra.MinimumNArgs(1),
		Short: "Fetch the certificates from a TLS endpoint",
		RunE: func(_ *cobra.Command, args []string) error {
			var err error
			for _, address := range args {
				address, err = ensureHostPort(address)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "invalid address: %v\n", err)
					continue
				}
				fmt.Printf("Downloading certificates for address: %s\n", address)
				x509certificates, err := certificates.DownloadCertificates(address)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "failed to download certificates from address %s: %v\n", address, err)
					continue
				}
				// Store certificates in database
				for _, x509certificate := range x509certificates {
					certificateId, err := cs.StoreX509Certificate(x509certificate)
					if err == nil {
						fmt.Printf("Certificate with subject: %s successfully stored (certificate ID=%d)\n", x509certificate.Subject, certificateId)
					} else {
						_, _ = fmt.Fprintf(os.Stderr, "failed to store certificate with subject: %s: %v\n", x509certificate.Subject, err)
					}
				}
			}
			return nil
		},
	}
	return cmd
}
