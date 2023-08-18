package main

import (
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/spf13/cobra"
	"os"
	"strconv"
)

func newShowCommand(cs CertStore) *cobra.Command {
	var certificateId int64

	cmd := &cobra.Command{
		Use:   "show certificate_id",
		Args:  cobra.ExactArgs(1),
		Short: "Show a certificate",
		PreRunE: func(_ *cobra.Command, args []string) error {
			var err error
			if certificateId, err = strconv.ParseInt(args[0], 10, 64); err != nil {
				return fmt.Errorf("invalid certificate ID")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			// Fetch certificate
			cert, err := cs.GetCertificate(certificateId)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to retrieve certificate from database: %v\n", err)
				os.Exit(1)
			}
			certificates.PrintCertificate(os.Stdout, cert)

			return nil
		},
	}
	return cmd
}
