package certstore

import (
	"fmt"
	"github.com/spf13/cobra"
	"os/user"
)

var (
	// Command
	userCmd = &cobra.Command{
		Use:   "user",
		Short: "User information",
		Run: func(cmd *cobra.Command, args []string) {
			currentUser, err := user.Current()
			if err != nil {
				fmt.Errorf("failed to retrieve current user: %v\n", err)
			} else {
				fmt.Printf("username: %s, uid=%s, gid=%s\n", currentUser.Username, currentUser.Uid, currentUser.Gid)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(userCmd)
}
