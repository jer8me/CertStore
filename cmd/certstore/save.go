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
)

var (
	// Command
	saveCmd = &cobra.Command{
		Use:     "save output_file",
		Args:    cobra.ExactArgs(1),
		Short:   "Save a certificate to a file",
		PreRunE: checkFlags,
		RunE:    save,
	}
)

func checkFlags(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Lookup(privFlag).Changed {
		privKeyFile, err := cmd.Flags().GetString(privFlag)
		if (privKeyFile == "") || (err != nil) {
			return fmt.Errorf("invalid private key file name")
		}
		pwd, err := cmd.Flags().GetString(pwdFlag)
		if (pwd == "") || (err != nil) {
			return fmt.Errorf("password cannot be empty")
		}
	}
	return nil
}

func save(cmd *cobra.Command, args []string) error {
	db, err := openSQLite()
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		return err
	}

	err = saveCertificate(db, certificateId, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to save certificate: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("certificate %s successfully saved\n", args[0])

	// Retrieve certificate data from database
	privateKeyId, err := storage.GetCertificatePrivateKeyId(db, certificateId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to save private key: %s\n", err)
		os.Exit(1)
	}
	privateKeyFile, err := cmd.Flags().GetString(privFlag)
	if err != nil {
		return err
	}
	pwd, err := cmd.Flags().GetString(pwdFlag)
	if err != nil {
		return err
	}
	// Save private key to file
	err = savePrivateKey(db, privateKeyId, privateKeyFile, pwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to save private key: %s\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("private key successfully saved to file %s\n", privateKeyFile)
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
		return errors.New("failed to decrypt private key: invalid password")
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
	addIdFlag(saveCmd, false)
	saveCmd.Flags().StringP(privFlag, "k", "", "Private Key File Name")
	saveCmd.Flags().StringP(pwdFlag, "p", "", "Private Key encryption password")
	saveCmd.MarkFlagsRequiredTogether(privFlag, pwdFlag)
	rootCmd.AddCommand(saveCmd)
}
