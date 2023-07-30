-- -----------------------------------------------------
-- Schema certstore
-- -----------------------------------------------------

DROP DATABASE IF EXISTS certstore;
CREATE DATABASE IF NOT EXISTS certstore;
USE certstore;

-- -----------------------------------------------------
-- Table User
-- -----------------------------------------------------
DROP TABLE IF EXISTS User;

CREATE TABLE IF NOT EXISTS User (
  id INT NOT NULL,
  name VARCHAR(64) NOT NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table PublicKeyAlgorithm
-- -----------------------------------------------------
DROP TABLE IF EXISTS PublicKeyAlgorithm;

CREATE TABLE IF NOT EXISTS PublicKeyAlgorithm (
  id INT NOT NULL,
  name VARCHAR(32) NOT NULL,
  PRIMARY KEY (id ASC),
  UNIQUE (name ASC)
);


-- -----------------------------------------------------
-- Table SignatureAlgorithm
-- -----------------------------------------------------
DROP TABLE IF EXISTS SignatureAlgorithm;

CREATE TABLE IF NOT EXISTS SignatureAlgorithm (
  id INT NOT NULL,
  name VARCHAR(64) NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table PrivateKeyType
-- -----------------------------------------------------
DROP TABLE IF EXISTS PrivateKeyType;

CREATE TABLE IF NOT EXISTS PrivateKeyType (
  id INT NOT NULL,
  type VARCHAR(64) NOT NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table PrivateKey
-- -----------------------------------------------------
DROP TABLE IF EXISTS PrivateKey;

CREATE TABLE IF NOT EXISTS PrivateKey (
  id INT NOT NULL AUTO_INCREMENT,
  encryptedPkcs8 BLOB NOT NULL,
  publicKey BLOB NOT NULL,
  privateKeyType_id INT NOT NULL,
  pemType VARCHAR(64) NOT NULL,
  dataEncryptionKey VARCHAR(256) NOT NULL,
  sha256Fingerprint VARCHAR(64) NOT NULL,
  PRIMARY KEY (id ASC),
  INDEX (privateKeyType_id ASC),
  INDEX (sha256Fingerprint ASC),
  CONSTRAINT fk_PrivateKey_PrivateKeyType
    FOREIGN KEY (privateKeyType_id)
    REFERENCES PrivateKeyType (id)
);


-- -----------------------------------------------------
-- Table Certificate
-- -----------------------------------------------------
DROP TABLE IF EXISTS Certificate;

CREATE TABLE IF NOT EXISTS Certificate (
  id INT NOT NULL AUTO_INCREMENT,
  publicKey BLOB NOT NULL,
  publicKeyAlgorithm_id INT NOT NULL,
  version SMALLINT NOT NULL,
  serialNumber VARCHAR(128) NOT NULL,
  subject VARCHAR(1024) NOT NULL,
  issuer VARCHAR(1024) NOT NULL,
  notBefore TIMESTAMP NOT NULL,
  notAfter TIMESTAMP NOT NULL,
  signature BLOB NOT NULL,
  signatureAlgorithm_id INT NOT NULL,
  isCa TINYINT(1) NOT NULL,    -- boolean: 0=false, 1=true
  rawContent BLOB NOT NULL,
  sha256Fingerprint VARCHAR(64) NOT NULL,
  privateKey_id INT NULL,
  PRIMARY KEY (id ASC),
  INDEX (publicKeyAlgorithm_id ASC),
  INDEX (signatureAlgorithm_id ASC),
  INDEX (privateKey_id ASC),
  INDEX (sha256Fingerprint ASC),
  CONSTRAINT fk_Certificate_PublicKeyAlgorithm
    FOREIGN KEY (publicKeyAlgorithm_id)
    REFERENCES PublicKeyAlgorithm (id),
  CONSTRAINT fk_Certificate_SignatureAlgorithm
    FOREIGN KEY (signatureAlgorithm_id)
    REFERENCES SignatureAlgorithm (id),
  CONSTRAINT fk_Certificate_PrivateKey
    FOREIGN KEY (privateKey_id)
    REFERENCES PrivateKey (id)
);


-- -----------------------------------------------------
-- Table AttributeType
-- -----------------------------------------------------
DROP TABLE IF EXISTS AttributeType;

CREATE TABLE IF NOT EXISTS AttributeType (
  oid VARCHAR(128) NOT NULL,
  name VARCHAR(16) NOT NULL,
  description VARCHAR(64) NOT NULL,
  PRIMARY KEY (oid ASC)
);


-- -----------------------------------------------------
-- Table CertificateAttribute
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateAttribute;

CREATE TABLE IF NOT EXISTS CertificateAttribute (
  certificate_id INT NOT NULL,
  type VARCHAR(8) NOT NULL,    -- Issuer or Subject
  oid VARCHAR(128) NOT NULL,
  value VARCHAR(512),
  INDEX (certificate_id ASC),
  INDEX (oid ASC),
  INDEX (value ASC),
  CONSTRAINT fk_CertificateAttribute_Certificate
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateAttribute_AttributeType
    FOREIGN KEY (oid)
    REFERENCES AttributeType (oid)
);


-- -----------------------------------------------------
-- Table CertificateOwner
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateOwner;

CREATE TABLE IF NOT EXISTS CertificateOwner (
  certificate_id INT NOT NULL,
  user_id INT NOT NULL,
  INDEX (certificate_id ASC),
  INDEX (user_id ASC),
  CONSTRAINT fk_CertificateOwner_Certificate
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateOwner_User
    FOREIGN KEY (user_id)
    REFERENCES User (id)
);


-- -----------------------------------------------------
-- Table KeyUsage
-- -----------------------------------------------------
DROP TABLE IF EXISTS KeyUsage;

CREATE TABLE IF NOT EXISTS KeyUsage (
  id INT NOT NULL,
  name VARCHAR(64) NOT NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table CertificateKeyUsage
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateKeyUsage;

CREATE TABLE IF NOT EXISTS CertificateKeyUsage (
  certificate_id INT NOT NULL,
  keyUsage_id INT NOT NULL,
  INDEX (keyUsage_id ASC),
  INDEX (certificate_id ASC),
  CONSTRAINT fk_CertificateKeyUsage_Certificate
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateKeyUsage_KeyUsage
    FOREIGN KEY (keyUsage_id)
    REFERENCES KeyUsage (id)
);


-- -----------------------------------------------------
-- Table SubjectAlternateNameType
-- -----------------------------------------------------
DROP TABLE IF EXISTS SubjectAlternateNameType;

CREATE TABLE IF NOT EXISTS SubjectAlternateNameType (
  id INT NOT NULL,
  name VARCHAR(16) NOT NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table SubjectAlternateName
-- -----------------------------------------------------
DROP TABLE IF EXISTS SubjectAlternateName;

CREATE TABLE IF NOT EXISTS SubjectAlternateName (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(256) NOT NULL,
  subjectAlternateNameType_id INT NOT NULL,
  PRIMARY KEY (id ASC),
  INDEX (subjectAlternateNameType_id ASC),
  CONSTRAINT fk_SubjectAlternateName_SubjectAlternateNameType
    FOREIGN KEY (subjectAlternateNameType_id)
    REFERENCES SubjectAlternateNameType (id)
);


-- -----------------------------------------------------
-- Table CertificateSAN
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateSAN;

CREATE TABLE IF NOT EXISTS CertificateSAN (
  certificate_id INT NOT NULL,
  subjectAlternateName_id INT NOT NULL,
  INDEX (subjectAlternateName_id ASC),
  INDEX (certificate_id ASC),
  CONSTRAINT fk_CertificateSAN_Certificate
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateSAN_SubjectAlternateName
    FOREIGN KEY (subjectAlternateName_id)
    REFERENCES SubjectAlternateName (id)
);


-- -----------------------------------------------------
-- Populate SignatureAlgorithm
-- -----------------------------------------------------
INSERT INTO SignatureAlgorithm (id, name)
VALUES
  (0, 'Unknown'),
  (1, 'MD2-RSA'),
  (2, 'MD5-RSA'),
  (3, 'SHA1-RSA'),
  (4, 'SHA256-RSA'),
  (5, 'SHA384-RSA'),
  (6, 'SHA512-RSA'),
  (7, 'DSA-SHA1'),
  (8, 'DSA-SHA256'),
  (9, 'ECDSA-SHA1'),
  (10, 'ECDSA-SHA256'),
  (11, 'ECDSA-SHA384'),
  (12, 'ECDSA-SHA512'),
  (13, 'SHA256-RSAPSS'),
  (14, 'SHA384-RSAPSS'),
  (15, 'SHA512-RSAPSS'),
  (16, 'Ed25519')
;


-- -----------------------------------------------------
-- Populate PublicKeyAlgorithm
-- -----------------------------------------------------
INSERT INTO PublicKeyAlgorithm (id, name)
VALUES
  (0, 'Unknown'),
  (1, 'RSA'),
  (2, 'DSA'),
  (3, 'ECDSA'),
  (4, 'Ed25519')
;


-- -----------------------------------------------------
-- Populate KeyUsage
-- -----------------------------------------------------
INSERT INTO KeyUsage (id, name)
VALUES
  (0, 'DigitalSignature'),
  (1, 'ContentCommitment'),
  (2, 'KeyEncipherment'),
  (3, 'DataEncipherment'),
  (4, 'KeyAgreement'),
  (5, 'KeyCertSign'),
  (6, 'CRLSign'),
  (7, 'EncipherOnly'),
  (8, 'DecipherOnly')
;


-- -----------------------------------------------------
-- Populate SubjectAlternateNameType
-- See https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6
-- -----------------------------------------------------
INSERT INTO SubjectAlternateNameType (id, name)
VALUES
    (1, 'Other'),
    (2, 'EmailAddress'),
    (3, 'DNSName'),
    (4, 'X400Address'),
    (5, 'DirectoryName'),
    (6, 'EDIPartyName'),
    (7, 'URI'),
    (8, 'IPAddress'),
    (9, 'RegisteredID')
;


-- -----------------------------------------------------
-- Populate PrivateKeyType
-- -----------------------------------------------------
INSERT INTO PrivateKeyType (id, type)
VALUES
    (0, 'Unknown'),
    (1, 'RSA'),
    (2, 'ECDSA'),
    (3, 'Ed25519'),
    (4, 'ECDH')
;


-- -----------------------------------------------------
-- Populate AttributeType
-- -----------------------------------------------------
INSERT INTO AttributeType (oid, name, description)
VALUES
    ('2.5.4.3', 'CN', 'Common Name'),
    ('2.5.4.5', 'SERIALNUMBER', 'Serial Number'),
    ('2.5.4.6', 'C', 'Country Name'),
    ('2.5.4.7', 'L', 'Locality Name'),
    ('2.5.4.8', 'ST', 'State or Province Name'),
    ('2.5.4.9', 'STREET', 'Street Address'),
    ('2.5.4.10', 'O', 'Organization Name'),
    ('2.5.4.11', 'OU', 'Organization Unit Name'),
    ('2.5.4.17', 'POSTALCODE', 'Postal Code')
;
