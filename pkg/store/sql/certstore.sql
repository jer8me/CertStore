-- -----------------------------------------------------
-- Table PublicKeyAlgorithm
-- -----------------------------------------------------
DROP TABLE IF EXISTS PublicKeyAlgorithm;

CREATE TABLE IF NOT EXISTS PublicKeyAlgorithm (
  id INTEGER PRIMARY KEY ASC,
  name VARCHAR(32) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_PublicKeyAlgorithm_Name ON PublicKeyAlgorithm(name ASC);


-- -----------------------------------------------------
-- Table SignatureAlgorithm
-- -----------------------------------------------------
DROP TABLE IF EXISTS SignatureAlgorithm;

CREATE TABLE IF NOT EXISTS SignatureAlgorithm (
  id INTEGER PRIMARY KEY ASC,
  name VARCHAR(64) NULL
);


-- -----------------------------------------------------
-- Table PrivateKeyType
-- -----------------------------------------------------
DROP TABLE IF EXISTS PrivateKeyType;

CREATE TABLE IF NOT EXISTS PrivateKeyType (
  id INTEGER PRIMARY KEY ASC,
  type VARCHAR(64) NOT NULL
);


-- -----------------------------------------------------
-- Table PrivateKey
-- -----------------------------------------------------
DROP TABLE IF EXISTS PrivateKey;

CREATE TABLE IF NOT EXISTS PrivateKey (
  id INTEGER PRIMARY KEY ASC,
  encryptedPkcs8 BLOB NOT NULL,
  publicKey BLOB NOT NULL,
  privateKeyType_id INTEGER NOT NULL,
  pemType VARCHAR(64) NOT NULL,
  dataEncryptionKey VARCHAR(256) NOT NULL,
  sha256Fingerprint VARCHAR(64) NOT NULL,
  CONSTRAINT fk_PrivateKey_PrivateKeyType FOREIGN KEY (privateKeyType_id) REFERENCES PrivateKeyType (id)
);

CREATE INDEX IF NOT EXISTS idx_PrivateKey_Type ON PrivateKey(privateKeyType_id ASC);
CREATE INDEX IF NOT EXISTS idx_PrivateKey_SHA256Fingerprint ON PrivateKey(sha256Fingerprint ASC);


-- -----------------------------------------------------
-- Table Certificate
-- -----------------------------------------------------
DROP TABLE IF EXISTS Certificate;

CREATE TABLE IF NOT EXISTS Certificate (
  id INTEGER PRIMARY KEY ASC,
  publicKey BLOB NOT NULL,
  publicKeyAlgorithm_id INTEGER NOT NULL,
  version SMALLINT NOT NULL,
  serialNumber VARCHAR(128) NOT NULL,
  subject VARCHAR(1024) NOT NULL,
  issuer VARCHAR(1024) NOT NULL,
  notBefore TIMESTAMP NOT NULL,
  notAfter TIMESTAMP NOT NULL,
  signature BLOB NOT NULL,
  signatureAlgorithm_id INTEGER NOT NULL,
  isCa TINYINT(1) NOT NULL,    -- boolean: 0=false, 1=true
  rawContent BLOB NOT NULL,
  sha256Fingerprint VARCHAR(64) NOT NULL,
  sha256PublicKey VARCHAR(64) NOT NULL,
  privateKey_id INTEGER,
  CONSTRAINT fk_Certificate_PublicKeyAlgorithm FOREIGN KEY (publicKeyAlgorithm_id) REFERENCES PublicKeyAlgorithm (id),
  CONSTRAINT fk_Certificate_SignatureAlgorithm FOREIGN KEY (signatureAlgorithm_id) REFERENCES SignatureAlgorithm (id),
  CONSTRAINT fk_Certificate_PrivateKey FOREIGN KEY (privateKey_id) REFERENCES PrivateKey (id)
);

CREATE INDEX IF NOT EXISTS idx_Certificate_PublicKeyAlgorithm ON Certificate(publicKeyAlgorithm_id ASC);
CREATE INDEX IF NOT EXISTS idx_Certificate_SignatureAlgorithm ON Certificate(signatureAlgorithm_id ASC);
CREATE INDEX IF NOT EXISTS idx_Certificate_PrivateKey ON Certificate(privateKey_id ASC);
CREATE INDEX IF NOT EXISTS idx_Certificate_SHA256Fingerprint ON Certificate(sha256Fingerprint ASC);
CREATE INDEX IF NOT EXISTS idx_Certificate_SHA256PublicKey ON Certificate(sha256PublicKey ASC);


-- -----------------------------------------------------
-- Table AttributeType
-- -----------------------------------------------------
DROP TABLE IF EXISTS AttributeType;

CREATE TABLE IF NOT EXISTS AttributeType (
  oid VARCHAR(128) PRIMARY KEY ASC,
  name VARCHAR(16) NOT NULL,
  description VARCHAR(64) NOT NULL
);


-- -----------------------------------------------------
-- Table CertificateAttribute
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateAttribute;

CREATE TABLE IF NOT EXISTS CertificateAttribute (
  certificate_id INTEGER NOT NULL,
  type VARCHAR(8) NOT NULL,    -- Issuer or Subject
  oid VARCHAR(128) NOT NULL,
  value VARCHAR(512),
  CONSTRAINT fk_CertificateAttribute_Certificate FOREIGN KEY (certificate_id) REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateAttribute_AttributeType FOREIGN KEY (oid) REFERENCES AttributeType (oid)
);

CREATE INDEX IF NOT EXISTS idx_CertificateAttribute_Certificate ON CertificateAttribute(certificate_id ASC);
CREATE INDEX IF NOT EXISTS idx_CertificateAttribute_Oid ON CertificateAttribute(oid ASC);
CREATE INDEX IF NOT EXISTS idx_CertificateAttribute_Value ON CertificateAttribute(value ASC);


-- -----------------------------------------------------
-- Table KeyUsage
-- -----------------------------------------------------
DROP TABLE IF EXISTS KeyUsage;

CREATE TABLE IF NOT EXISTS KeyUsage (
  id INTEGER PRIMARY KEY ASC,
  name VARCHAR(64) NOT NULL
);


-- -----------------------------------------------------
-- Table CertificateKeyUsage
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateKeyUsage;

CREATE TABLE IF NOT EXISTS CertificateKeyUsage (
  certificate_id INTEGER NOT NULL,
  keyUsage_id INTEGER NOT NULL,
  CONSTRAINT fk_CertificateKeyUsage_Certificate FOREIGN KEY (certificate_id) REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateKeyUsage_KeyUsage FOREIGN KEY (keyUsage_id) REFERENCES KeyUsage (id)
);

CREATE INDEX IF NOT EXISTS idx_CertificateKeyUsage_KeyUsage ON CertificateKeyUsage(keyUsage_id ASC);
CREATE INDEX IF NOT EXISTS idx_CertificateKeyUsage_Certificate ON CertificateKeyUsage(certificate_id ASC);

-- -----------------------------------------------------
-- Table SubjectAlternateNameType
-- -----------------------------------------------------
DROP TABLE IF EXISTS SubjectAlternateNameType;

CREATE TABLE IF NOT EXISTS SubjectAlternateNameType (
  id INTEGER PRIMARY KEY ASC,
  name VARCHAR(16) NOT NULL
);


-- -----------------------------------------------------
-- Table SubjectAlternateName
-- -----------------------------------------------------
DROP TABLE IF EXISTS SubjectAlternateName;

CREATE TABLE IF NOT EXISTS SubjectAlternateName (
  id INTEGER PRIMARY KEY ASC,
  name VARCHAR(256) NOT NULL,
  subjectAlternateNameType_id INTEGER NOT NULL,
  CONSTRAINT fk_SubjectAlternateName_SubjectAlternateNameType FOREIGN KEY (subjectAlternateNameType_id) REFERENCES SubjectAlternateNameType (id)
);

CREATE INDEX IF NOT EXISTS idx_SubjectAlternateName_Type ON SubjectAlternateName(subjectAlternateNameType_id ASC);


-- -----------------------------------------------------
-- Table CertificateSAN
-- -----------------------------------------------------
DROP TABLE IF EXISTS CertificateSAN;

CREATE TABLE IF NOT EXISTS CertificateSAN (
  certificate_id INTEGER NOT NULL,
  subjectAlternateName_id INTEGER NOT NULL,
  CONSTRAINT fk_CertificateSAN_Certificate FOREIGN KEY (certificate_id) REFERENCES Certificate (id),
  CONSTRAINT fk_CertificateSAN_SubjectAlternateName FOREIGN KEY (subjectAlternateName_id) REFERENCES SubjectAlternateName (id)
);

CREATE INDEX IF NOT EXISTS idx_CertificateSAN_SubjectAlternateName ON CertificateSAN(subjectAlternateName_id ASC);
CREATE INDEX IF NOT EXISTS idx_CertificateSAN_Certificate ON CertificateSAN(certificate_id ASC);


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
