package certstore

import "github.com/spf13/cobra"

const (
	idFlag  = "id" // Flag used to specify a certificate id
	pwdFlag = "pwd"
)

var certificateId int64

func addIdFlag(cmd *cobra.Command, required bool) {
	cmd.Flags().Int64VarP(&certificateId, idFlag, "i", 0, "Certificate Id")
	if required {
		cmd.MarkFlagRequired(idFlag)
	}
}
