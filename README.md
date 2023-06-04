# CertStore
CertStore project

## Setup ##

1. Install MariaDB (https://mariadb.org/download/).
2. Run the DB creation script: sql/dbcreate.sql

## Build ##

```bash
go build
```

## Run ##

```bash
export DB_PASSWORD=<your_db_password>
.\CertStore test --dbpass $DB_PASSWORD
```
