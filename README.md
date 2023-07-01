# CertStore
CertStore project

## Setup ##

1. Install MariaDB (https://mariadb.org/download/).
2. Run the DB creation script: sql/certstore.sql

## Build ##

```bash
go build
```

## Test ##

```bash
go test ./...
```

## Using CertStore ##

### Setup environment ###
```bash
export DB_USERNAME=root
export DB_PASSWORD=<db_password>
export DB_NAME=certstore
```

### List all stored certificates ###

```bash
CertStore list
```

### Store a certificate ###

```bash
CertStore store certificate.pem
```

### Display a certificate ###

```bash
CertStore show --id 1
```

### Save a stored certificate as a file ###

```bash
CertStore save --id 1 output_certificate.pem 
```
