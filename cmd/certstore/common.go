package certstore

import "github.com/spf13/cobra"

const (
	certIdFlag = "cert" // Flag used to specify a certificate id
	pkIdFlag   = "pk"
	pwdFlag    = "pwd"
)

var certificateId int64
var privateKeyId int64

func addIdFlag(cmd *cobra.Command, required bool) {
	cmd.Flags().Int64VarP(&certificateId, certIdFlag, "c", 0, "Certificate ID")
	if required {
		cmd.MarkFlagRequired(certIdFlag)
	}
}
