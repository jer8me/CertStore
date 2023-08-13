# CertStore

A X.509 certificate management tool.

## Prerequisites

To build the project, a few prerequisites must be installed on your machine.

### Golang

CertStore is written is Golang and requires the Go tool chain to be built.
The instructions to install Go can be found on the Go website: https://go.dev/doc/install

### GCC

The gcc compiler is required to build the SQLite driver.

- Windows: MinGW-w64 supports GCC on Windows (https://www.mingw-w64.org/downloads/)
- Mac: gcc can be installed via Homebrew.
- Linux: gcc can be installed via a common package manager such as APT or YUM.

## Build

```bash
go build
```

## Test

```bash
go test ./...
```

## Using CertStore

### List stored certificates

```
CertStore list [flags]
```

#### Options

```
  -e, --expire-before string            Certificate Expires On or Before Date (yyyy-mm-dd)
      --has-private-key                 Certificate has a Private Key
  -h, --help                            help for list
      --is-ca                           Certificate is a CA
  -i, --issuer string                   Certificate Issuer Fields
      --issuer-cn string                Certificate Issuer Common Name
      --issuer-country string           Certificate Issuer Country
      --issuer-locality string          Certificate Issuer Locality
      --issuer-org string               Certificate Organization
      --issuer-org-unit string          Certificate Organization Unit
      --issuer-postal-code string       Certificate Postal Code
      --issuer-state string             Certificate Issuer State or Province
      --issuer-street string            Certificate Issuer Street Address
      --no-private-key                  Certificate does not have a Private Key
      --not-ca                          Certificate is not a CA
  -p, --public-key-algorithms strings   Certificate Public Key Algorithms (RSA, DSA, ECDSA, Ed25519)
      --san string                      Certificate SAN
      --serial string                   Certificate Serial Number
  -s, --subject string                  Certificate Subject Fields
      --subject-cn string               Certificate Subject Common Name
      --subject-country string          Certificate Subject Country
      --subject-locality string         Certificate Subject Locality
      --subject-org string              Certificate Subject Organization
      --subject-org-unit string         Certificate Subject Organization Unit
      --subject-postal-code string      Certificate Subject Postal Code
      --subject-state string            Certificate Subject State or Province
      --subject-street string           Certificate Subject Street Address
```

### Fetch certificates for a domain

Specify one or more domain names to fetch certificates from. If no port is specified, the default https port (443) will be used.

```
CertStore fetch address [...address] [flags]
```

#### Options

```
  -h, --help   help for fetch
```

#### Examples

```bash
CertStore fetch www.champlain.edu
CertStore fetch champlain.edu google.com
CertStore fetch champlain.edu:443
```

### Store a certificate

```
CertStore store pem_file [...pem_file] [flags]
```

#### Options

```
  -h, --help              help for store
  -p, --password string   Private Key Password
```

#### Note

A PEM file can be a certificate or a private key.
When storing one or more private keys:
- an associated certificate must be present in CertStore or provided in the list of PEM files.
- a password must be specified. The password will be used to safely store the given private keys.

### Display a certificate

```
CertStore show certificate_id [flags]
```

#### Options

```
  -h, --help   help for show
```

### Save certificates and private keys to file

Save a certificate and/or a private key to a file.

```
CertStore save certificate_id [flags]
```

#### Options

```
  -c, --cert-file string       Certificate Output File
  -h, --help                   help for save
  -p, --password string        Private Key Password
  -k, --priv-key-file string   Private Key Output File
```

#### Note

To retrieve a private key, the original password used to store the private key must be specified.
