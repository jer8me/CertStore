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
	if cmd.Flags().Lookup(certIdFlag).Changed {
		return nil
	}
	if cmd.Flags().Lookup(pkIdFlag).Changed {
		pwd, err := cmd.Flags().GetString(pwdFlag)
		if (pwd == "") || (err != nil) {
			return fmt.Errorf("a password must be provided when retrieving a private key")
		}
		return nil
	}
	return fmt.Errorf("must specify a certificate ID or private key ID")
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

	if cmd.Flags().Lookup(certIdFlag).Changed {
		// Save certificate to file
		err = saveCertificate(db, certificateId, args[0])
	} else if cmd.Flags().Lookup(pkIdFlag).Changed {
		var pwd string
		pwd, err = cmd.Flags().GetString(pwdFlag)
		if err != nil {
			return err
		}
		// Save private key to file
		err = savePrivateKey(db, privateKeyId, args[0], pwd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	} else {
		fmt.Printf("file %s successfully saved\n", args[0])
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
	saveCmd.Flags().Int64VarP(&privateKeyId, pkIdFlag, "k", 0, "Private Key ID")
	saveCmd.Flags().StringP(pwdFlag, "p", "", "Private Key encryption password")
	saveCmd.MarkFlagsMutuallyExclusive(certIdFlag, pkIdFlag)
	rootCmd.AddCommand(saveCmd)
}
