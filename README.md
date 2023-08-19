# CertStore

An X.509 certificate management tool.

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
go build ./cmd/certstore
```

## Test

```bash
go test ./...
```

## Getting Started

The following steps should be executed from the openssl directory.
```bash
cd openssl
```

### Self-signed certificate with RSA

Generate RSA private key
```bash
openssl genrsa -out rsa4096.key 4096
```

Generate certificate
```bash
openssl req -new -x509 -key rsa4096.key -days 365 -config certstore.cnf -out rsa4096.crt
```

Store the certificate and private key in CertStore
```bash
certstore store rsa4096.key rsa4096.crt -p $PASSWORD
```

Check that the certificate and the private key are stored
```bash
certstore list
certstore show 1
```

Retrieve the certificate and the private key
```bash
certstore save 1 -c rsa4096out.crt -k rsa4096out.key -p $PASSWORD
```

### Self-signed certificate with Ed25519

Generate Ed25519 private key
```bash
openssl genpkey -algorithm ED25519 -out ed25519.key
```

Generate certificate
```bash
openssl req -new -x509 -key ed25519.key -days 365 -config certstore.cnf -out ed25519.crt
```

Store the certificate and private key in CertStore
```bash
certstore store ed25519.key ed25519.crt -p $PASSWORD
```

Check that the certificate and the private key are stored
```bash
certstore list
certstore show 2
```

Retrieve the certificate and the private key
```bash
certstore save 2 -c ed25519out.crt -k ed25519out.key -p $PASSWORD
```

### Self-signed certificate with Elliptic-curve

Generate Elliptic-curve private key
```bash
openssl ecparam -name secp521r1 -genkey -noout -out ecdsa521.key
```

Generate certificate
```bash
openssl req -new -x509 -key ecdsa521.key -days 365 -config certstore.cnf -out ecdsa521.crt
```

Store the certificate and private key in CertStore
```bash
certstore store ecdsa521.key ecdsa521.crt -p $PASSWORD
```

Check that the certificate and the private key are stored
```bash
certstore list
certstore show 3
```

Retrieve the certificate and the private key
```bash
certstore save 3 -c ecdsa521out.crt -k ecdsa521out.key -p $PASSWORD
```

### Self-signed certificate with DSA

> [!WARNING]
> DSA is not a secure algorithm and should not be used. The following example is given for testing purpose only.

Generate DSA private key
```bash
openssl dsaparam -out dsaparam.pem 2048
openssl gendsa -out dsa2048.key dsaparam.pem
```

Generate certificate
```bash
openssl req -new -x509 -key dsa2048.key -days 365 -config certstore.cnf -out dsa2048.crt
```

Store the certificate and private key in CertStore
```bash
certstore store dsa2048.crt
```

Check that the certificate and the private key are stored
```bash
certstore list
certstore show 4
```

Retrieve the certificate and the private key
```bash
certstore save 4 -c dsa2048out.crt
```

### Certificate signed by self-signed CA

Create a Root CA
```bash
openssl genrsa -out rootca.key 4096
openssl req -new -x509 -key rootca.key -days 3650 -config rootca.cnf -out rootca.crt
```

Store the Root CA certificate and private key in CertStore
```bash
certstore store rootca.key rootca.crt -p $PASSWORD
```

Create an End-Entity certificate signed by the Root CA
```bash
openssl ecparam -name prime256v1 -genkey -noout -out endentity.key
openssl req -new -out endentity.csr -key endentity.key -config certstore.cnf
openssl x509 -req -days 365 -in endentity.csr -extfile certstore.cnf -extensions req_ext -CA rootca.crt -CAkey rootca.key -CAcreateserial -out endentity.crt
```

Store the End-Entity certificate and private key in CertStore
```bash
certstore store endentity.key endentity.crt -p $PASSWORD
```

Check that the certificates and the private keys are stored
```bash
certstore list
certstore show 5
certstore show 6
```

Retrieve the End-Entity certificate and the private key
```bash
certstore save 6 -c endentityout.crt -k endentityout.key -p $PASSWORD
```

## Usage

### List stored certificates

```
certstore list [flags]
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
certstore fetch address [...address] [flags]
```

#### Options

```
  -h, --help   help for fetch
```

#### Examples

```bash
certstore fetch www.champlain.edu
certstore fetch champlain.edu google.com
certstore fetch champlain.edu:443
```

### Store a certificate

```
certstore store pem_file [...pem_file] [flags]
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
certstore show certificate_id [flags]
```

#### Options

```
  -h, --help   help for show
```

### Save certificates and private keys to file

Save a certificate and/or a private key to a file.

```
certstore save certificate_id [flags]
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
