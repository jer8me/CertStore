package storage

import (
	"database/sql"
	"github.com/go-sql-driver/mysql"
)

// OpenMySqlDB opens a new connection to a MySQL database
func OpenMySqlDB(userName, userPass, dbName string) (*sql.DB, error) {

	cfg := mysql.NewConfig()
	cfg.User = userName
	cfg.Passwd = userPass
	cfg.DBName = dbName
	// Set ParseTime to true so timestamp can be parse to a time.Time value
	// See https://github.com/go-sql-driver/mysql/tree/master#user-content-timetime-support
	cfg.ParseTime = true

	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}

	return sql.OpenDB(connector), nil
}
