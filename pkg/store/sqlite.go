package store

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/jer8me/CertStore/pkg/common"
	"log"
	"os"
	"path"
	"regexp"
	"strings"

	_ "embed"
	_ "github.com/mattn/go-sqlite3"
)

var whitespaces = regexp.MustCompile(`\s*\n\s*`)

//go:embed sql/certstore.sql
var dbScript []byte

// OpenDatabase returns a DB object or an error if opening the database fails
func OpenDatabase(filepath string) (*sql.DB, error) {
	filepath, err := common.ResolvePath(filepath)
	if err != nil {
		return nil, err
	}
	dir, _ := path.Split(filepath)
	if dir != "" {
		err = os.MkdirAll(dir, 0600)
		if err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		log.Fatalf("failed to rollback transaction: %s\n", err)
	}
}

// InitDatabase checks that the database is initialized as expected
// and performs the initialization as needed.
func InitDatabase(db *sql.DB) error {
	// Start a transaction to process all database operations atomically
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	var exists bool
	err = tx.QueryRow("SELECT EXISTS(SELECT name FROM sqlite_schema WHERE type='table' AND name='Certificate')").Scan(&exists)
	if err != nil {
		rollback(tx)
		return fmt.Errorf("failed to query sqlite schema: %w", err)
	}
	if exists {
		// Certificate table exists: nothing to do
		rollback(tx)
		return nil
	}

	var builder strings.Builder
	reader := bytes.NewReader(dbScript)
	scanner := bufio.NewScanner(reader)
	// Remove comments and commented lines
	// scanner scans the buffer line by line
	for scanner.Scan() {
		// Cut out comments
		before, _, _ := bytes.Cut(scanner.Bytes(), []byte("--"))
		builder.Write(bytes.TrimSpace(before))
		builder.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		rollback(tx)
		return fmt.Errorf("failed to scan database script: %w", err)
	}

	// Split SQL statements base on the terminating colon
	statements := strings.Split(builder.String(), ";")
	for _, statement := range statements {
		s := whitespaces.ReplaceAllLiteralString(statement, " ")
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, err := tx.Exec(trimmed); err != nil {
			return fmt.Errorf("failed to execute database creation statement: %w", err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit database creation transaction: %w", err)
	}
	return nil
}
