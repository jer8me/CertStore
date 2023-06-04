package certstore

import (
	"fmt"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "List",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: display the list of certificates")
	},
}

func init() {
	cmd.AddCommand(listCmd)
}
