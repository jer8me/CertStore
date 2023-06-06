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
  id INT NOT NULL,
  encryptedKey BLOB NOT NULL,
  privateKeyType_id INT NOT NULL,
  PRIMARY KEY (id ASC),
  INDEX (privateKeyType_id ASC),
  CONSTRAINT fk_PrivateKey_PrivateKeyType1
    FOREIGN KEY (privateKeyType_id)
    REFERENCES PrivateKeyType (id)
);


-- -----------------------------------------------------
-- Table Certificate
-- -----------------------------------------------------
DROP TABLE IF EXISTS Certificate;

CREATE TABLE IF NOT EXISTS Certificate (
  id INT NOT NULL,
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
  rawContent BLOB NOT NULL,
  privateKey_id INT NULL,
  PRIMARY KEY (id ASC),
  INDEX (publicKeyAlgorithm_id ASC),
  INDEX (signatureAlgorithm_id ASC),
  INDEX (privateKey_id ASC),
  CONSTRAINT fk_Certificate_PublicKeyAlgorithm
    FOREIGN KEY (publicKeyAlgorithm_id)
    REFERENCES PublicKeyAlgorithm (id),
  CONSTRAINT fk_Certificate_SignatureAlgorithm1
    FOREIGN KEY (signatureAlgorithm_id)
    REFERENCES SignatureAlgorithm (id),
  CONSTRAINT fk_Certificate_PrivateKey1
    FOREIGN KEY (privateKey_id)
    REFERENCES PrivateKey (id)
);


-- -----------------------------------------------------
-- Table PKIXName
-- -----------------------------------------------------
DROP TABLE IF EXISTS PKIXName;

CREATE TABLE IF NOT EXISTS PKIXName (
  id INT NOT NULL,
  PRIMARY KEY (id ASC)
);


-- -----------------------------------------------------
-- Table CertificateOwner
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateOwner;

CREATE TABLE IF NOT EXISTS CertificateOwner (
  certificate_id INT NOT NULL,
  user_id INT NOT NULL,
  INDEX (user_id ASC),
  INDEX (certificate_id ASC),
  CONSTRAINT fk_Certificate_has_User_Certificate1
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_Certificate_has_User_User1
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
  CONSTRAINT fk_Certificate_has_KeyUsage_Certificate1
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_Certificate_has_KeyUsage_KeyUsage1
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
  id INT NOT NULL,
  name VARCHAR(256) NOT NULL,
  subjectAlternateNameType_id INT NOT NULL,
  PRIMARY KEY (id ASC),
  INDEX (subjectAlternateNameType_id ASC),
  CONSTRAINT fk_SubjectAlternateName_SubjectAlternateNameType1
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
  CONSTRAINT fk_Certificate_has_SubjectAlternateName_Certificate1
    FOREIGN KEY (certificate_id)
    REFERENCES Certificate (id),
  CONSTRAINT fk_Certificate_has_SubjectAlternateName_SubjectAlternateName1
    FOREIGN KEY (subjectAlternateName_id)
    REFERENCES SubjectAlternateName (id)
);


-- -----------------------------------------------------
-- Populate SignatureAlgorithm
-- -----------------------------------------------------
INSERT INTO SignatureAlgorithm (id, name)
VALUES
  (1, 'UnknownSignatureAlgorithm'),
  (2, 'MD2WithRSA'),
  (3, 'MD5WithRSA'),
  (4, 'SHA1WithRSA'),
  (5, 'SHA256WithRSA'),
  (6, 'SHA384WithRSA'),
  (7, 'SHA512WithRSA'),
  (8, 'DSAWithSHA1'),
  (9, 'DSAWithSHA256'),
  (10, 'ECDSAWithSHA1'),
  (11, 'ECDSAWithSHA256'),
  (12, 'ECDSAWithSHA384'),
  (13, 'ECDSAWithSHA512'),
  (14, 'SHA256WithRSAPSS'),
  (15, 'SHA384WithRSAPSS'),
  (16, 'SHA512WithRSAPSS'),
  (17, 'PureEd25519')
;


-- -----------------------------------------------------
-- Populate PublicKeyAlgorithm
-- -----------------------------------------------------
INSERT INTO PublicKeyAlgorithm (id, name)
VALUES
  (1, 'UnknownPublicKeyAlgorithm'),
  (2, 'RSA'),
  (3, 'DSA'),
  (4, 'ECDSA'),
  (5, 'Ed25519')
;


-- -----------------------------------------------------
-- Populate KeyUsage
-- -----------------------------------------------------
INSERT INTO KeyUsage (id, name)
VALUES
  (1, 'KeyUsageDigitalSignature'),
  (2, 'KeyUsageContentCommitment'),
  (3, 'KeyUsageKeyEncipherment'),
  (4, 'KeyUsageDataEncipherment'),
  (5, 'KeyUsageKeyAgreement'),
  (6, 'KeyUsageCertSign'),
  (7, 'KeyUsageCRLSign'),
  (8, 'KeyUsageEncipherOnly'),
  (9, 'KeyUsageDecipherOnly')
;
