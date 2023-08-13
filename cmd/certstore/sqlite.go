package certstore

import (
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/storage"
	"os"
)

const dbpath = "~/.certstore/certstore.db"

// openSQLite opens a new connection to a SQLite database
func openSQLite() (*sql.DB, error) {
	return storage.OpenDatabase(dbpath)
}

func initSQLite(db *sql.DB) error {
	return storage.InitDatabase(db)
}

func closeSQLite(db *sql.DB) {
	if err := db.Close(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to closed database: %s\n", err)
	}
}
