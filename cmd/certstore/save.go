package certstore

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/storage"
	"github.com/spf13/cobra"
	"os"
	"strconv"
)

var (
	// Command
	saveCmd = &cobra.Command{
		Use:     "save certificate_id",
		Args:    cobra.ExactArgs(1),
		Short:   "Save a certificate and/or a private key to a file",
		PreRunE: checkSaveFlags,
		RunE:    save,
	}
)

func checkSaveFlags(cmd *cobra.Command, args []string) error {
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
}

func save(_ *cobra.Command, _ []string) error {
	db, err := openSQLite()
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		return err
	}

	if certificateFile != "" {
		err = saveCertificate(db, certificateId, certificateFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to save certificate: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("certificate successfully saved to file %s\n", certificateFile)
	}

	if privateKeyFile != "" {
		// Retrieve certificate data from database
		privateKeyId, err := storage.GetCertificatePrivateKeyId(db, certificateId)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to save private key: %s\n", err)
			os.Exit(1)
		}
		// Save private key to file
		err = savePrivateKey(db, privateKeyId, privateKeyFile, password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to save private key: %s\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("private key successfully saved to file %s\n", privateKeyFile)
		}
	}
	return nil
}

func saveCertificate(db *sql.DB, certificateId int64, filename string) error {
	// Fetch certificate
	x509Certificate, err := storage.GetX509Certificate(db, certificateId)
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

func savePrivateKey(db *sql.DB, privateKeyId int64, filename, password string) error {
	// Fetch private key
	encryptedPrivateKey, err := storage.GetPrivateKey(db, privateKeyId)
	if err != nil {
		return fmt.Errorf("failed to retrieve private key from database: %w", err)
	}
	privateKey, err := storage.DecryptPrivateKey(encryptedPrivateKey, password)
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

func init() {
	saveCmd.Flags().StringVarP(&certificateFile, certFileFlag, "c", "", "Certificate Output File")
	saveCmd.Flags().StringVarP(&privateKeyFile, privKeyFileFlag, "k", "", "Private Key Output File")
	saveCmd.Flags().StringVarP(&password, passwordFlag, "p", "", "Private Key Password")
	saveCmd.MarkFlagsRequiredTogether(privKeyFileFlag, passwordFlag)
	rootCmd.AddCommand(saveCmd)
}
