package certstore

import (
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/cobra"
	"os"
)

const (
	dbUsernameFlag         = "dbuser"
	dbUsernameEnvVar       = "DB_USERNAME"
	dbUsernameDefaultValue = "root"
	dbPasswordFlag         = "dbpass"
	dbPasswordEnvVar       = "DB_PASSWORD"
	dbPasswordDefaultValue = ""
	dbNameFlag             = "dbname"
	dbNameEnvVar           = "DB_NAME"
	dbNameDefaultValue     = "certstore"
)

// openMySqlDB opens a new connection to a MySQL database
func openMySqlDB() (*sql.DB, error) {

	mysqlCfg := mysql.NewConfig()

	mysqlCfg.User = viperCfg.GetString(dbUsernameFlag)
	if mysqlCfg.User == "" {
		return nil, fmt.Errorf("database username cannot be empty. "+
			"Set %s flag or %s environment variable", dbUsernameFlag, dbUsernameEnvVar)
	}

	mysqlCfg.Passwd = viperCfg.GetString(dbPasswordFlag)
	if mysqlCfg.Passwd == "" {
		return nil, fmt.Errorf("database password cannot be empty. "+
			"Set %s flag or %s environment variable", dbPasswordFlag, dbPasswordEnvVar)
	}

	mysqlCfg.DBName = viperCfg.GetString(dbNameFlag)
	if mysqlCfg.DBName == "" {
		return nil, fmt.Errorf("database name cannot be empty. "+
			"Set %s flag or %s environment variable", dbNameFlag, dbNameEnvVar)
	}

	// Set ParseTime to true so timestamp can be parse to a time.Time value
	// See https://github.com/go-sql-driver/mysql/tree/master#user-content-timetime-support
	mysqlCfg.ParseTime = true

	connector, err := mysql.NewConnector(mysqlCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to MySQL database: %v\n", err)
		os.Exit(1)
	}
	return sql.OpenDB(connector), nil
}

func addMySqlFlags(cmd *cobra.Command) error {
	flags := cmd.PersistentFlags()
	flags.String(dbUsernameFlag, dbUsernameDefaultValue, "Database Username")
	flags.String(dbPasswordFlag, dbPasswordDefaultValue, "Database Password")
	flags.String(dbNameFlag, dbNameDefaultValue, "Database Name")
	if err := viperCfg.BindPFlags(flags); err != nil {
		return err
	}
	viperCfg.MustBindEnv(dbUsernameFlag, dbUsernameEnvVar)
	viperCfg.MustBindEnv(dbPasswordFlag, dbPasswordEnvVar)
	viperCfg.MustBindEnv(dbNameFlag, dbNameEnvVar)

	return nil
}
