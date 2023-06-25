# CertStore
CertStore project

## Setup ##

1. Install MariaDB (https://mariadb.org/download/).
2. Run the DB creation script: sql/dbcreate.sql

## Build ##

```bash
go build
```

## Using CertStore ##

### Storing a certificate ###

```bash
export DB_PASSWORD=<your_db_password>
.\CertStore store certificate.pem --dbpass $DB_PASSWORD
```

### Displaying a certificate ###

```bash
export DB_PASSWORD=<your_db_password>
.\CertStore show --id 1 --dbpass $DB_PASSWORD
```
