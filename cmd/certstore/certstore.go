package main

import (
	"fmt"
	"os"
)

const version = "0.0.1"

func errorExit(format string, v ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, v...)
	os.Exit(1)
}

func main() {
	// Open SQLite database
	db, err := openSQLite()
	if err != nil {
		errorExit("%s", err)
	}
	defer closeSQLite(db)
	if err := initSQLite(db); err != nil {
		errorExit("%s", err)
	}

	cmd := newRootCommand(db)
	if err := cmd.Execute(); err != nil {
		// Exit with an error code
		os.Exit(1)
	}
}
