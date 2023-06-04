package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const version = "0.0.1"

func main() {
	cmd := &cobra.Command{
		Use:     "CertStore",
		Version: version,
		Short:   "CertStore - a X.509 certificate management tool",
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while executing CLI: %s", err)
		os.Exit(1)
	}

}
