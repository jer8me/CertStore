package test

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
)

func Test(userName, userPass, dbName string) {

	dbCfg := mysql.NewConfig()
	dbCfg.User = userName
	dbCfg.Passwd = userPass
	dbCfg.DBName = dbName

	connector, err := mysql.NewConnector(dbCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create DB connector: %s\n", err)
		return
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// Set default settings
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	// Build a test query
	// This is only to test the DB connection. This code will be removed.
	results, err := db.Query("SELECT id, name FROM TEST")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to execute DB query: %s\n", err)
		return
	}
	// Fetch and display each row of the result set
	for results.Next() {
		var id int
		var name string
		err = results.Scan(&id, &name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to fetch DB results: %s\n", err)
			return
		}
		fmt.Printf("ID: %d, Name: %s\n", id, name)
	}

}
