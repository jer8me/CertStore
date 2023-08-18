package main

import (
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/store"
	"github.com/spf13/cobra"
	"strconv"
)

const (
	certFileFlag    = "cert-file"
	privKeyFileFlag = "priv-key-file"
	passwordFlag    = "password"
)

func saveCertificate(cs CertStore, certificateId int64, filename string) error {
	// Fetch certificate
	x509Certificate, err := cs.GetX509Certificate(certificateId)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate from database: %w", err)
	}
	// Save certificate to file
	err = certificates.WriteCertificate(filename, x509Certificate)
	if err != nil {
		return fmt.Errorf("failed to write certificate file %s: %w", filename, err)
	}
	return nil
}

func savePrivateKey(cs CertStore, privateKeyId int64, filename, password string) error {
	// Fetch private key
	encryptedPrivateKey, err := cs.GetPrivateKey(privateKeyId)
	if err != nil {
		return fmt.Errorf("failed to retrieve private key from database: %w", err)
	}
	privateKey, err := store.DecryptPrivateKey(encryptedPrivateKey, password)
	if errors.Is(err, common.AuthError) {
		return errors.New("invalid password")
	} else if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}
	// Save private key to file
	err = certificates.WritePrivateKey(filename, privateKey)
	if err != nil {
		return fmt.Errorf("failed to write private key file %s: %w", filename, err)
	}
	return nil
}

func newSaveCommand(cs CertStore) *cobra.Command {
	var certificateId int64
	var certificateFile string
	var privateKeyFile string
	var password string

	cmd := &cobra.Command{
		Use:   "save certificate_id",
		Args:  cobra.ExactArgs(1),
		Short: "Save a certificate and/or a private key to a file",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if certificateId, err = strconv.ParseInt(args[0], 10, 64); err != nil {
				return fmt.Errorf("invalid certificate ID")
			}
			if cmd.Flags().Lookup(certFileFlag).Changed {
				if certificateFile == "" {
					return fmt.Errorf("certificate file name cannot be empty")
				}
			}
			if cmd.Flags().Lookup(privKeyFileFlag).Changed {
				if privateKeyFile == "" {
					return fmt.Errorf("private key file name cannot be empty")
				}
				if password == "" {
					return fmt.Errorf("password cannot be empty")
				}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			if certificateFile != "" {
				err := saveCertificate(cs, certificateId, certificateFile)
				if err != nil {
					return NewRuntimeError(err)
				}
				fmt.Printf("certificate successfully saved to file %s\n", certificateFile)
			}

			if privateKeyFile != "" {
				// Retrieve certificate data from database
				privateKeyId, err := cs.GetCertificatePrivateKeyId(certificateId)
				if err != nil {
					return NewRuntimeError(err)
				}
				// Save private key to file
				err = savePrivateKey(cs, privateKeyId, privateKeyFile, password)
				if err != nil {
					return NewRuntimeError(err)
				} else {
					fmt.Printf("private key successfully saved to file %s\n", privateKeyFile)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&certificateFile, certFileFlag, "c", "", "Certificate Output File")
	f.StringVarP(&privateKeyFile, privKeyFileFlag, "k", "", "Private Key Output File")
	f.StringVarP(&password, passwordFlag, "p", "", "Private Key Password")
	cmd.MarkFlagsRequiredTogether(privKeyFileFlag, passwordFlag)

	return cmd
}
