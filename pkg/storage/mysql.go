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

	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}

	return sql.OpenDB(connector), nil
}
