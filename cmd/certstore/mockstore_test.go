package main

import (
	"crypto/x509"
	"fmt"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/common"
	"github.com/jer8me/CertStore/pkg/store"
	"path"
)

func newMockStore() *mockStore {
	ms := new(mockStore)
	ms.certificates = make(map[int64]*x509.Certificate)
	ms.privateKeys = make(map[int64]*store.PrivateKey)
	ms.certPrivateKey = make(map[int64]int64)
	return ms
}

// mockStore implements the CertStore interface for unit testing
type mockStore struct {
	certificates map[int64]*x509.Certificate
	privateKeys  map[int64]*store.PrivateKey
	// Map of certificateId -> privateKeyId
	certPrivateKey   map[int64]int64
	lastCertId       int64
	lastPrivateKeyId int64
}

func (mc *mockStore) GetCertificate(certificateId int64) (*store.Certificate, error) {
	x509Cert := mc.certificates[certificateId]
	if x509Cert == nil {
		return nil, fmt.Errorf("certificate ID %d does not exist", certificateId)
	}
	cert := store.ToCertificate(x509Cert)
	cert.Id = certificateId
	if privateKeyId, found := mc.certPrivateKey[certificateId]; found {
		cert.PrivateKeyId.Int64 = privateKeyId
		cert.PrivateKeyId.Valid = true
	}
	return cert, nil
}

func (mc *mockStore) GetCertificates(_ *store.SearchFilter) ([]*store.Certificate, error) {
	certs := make([]*store.Certificate, 0, len(mc.certificates))
	for id, x509Cert := range mc.certificates {
		cert := store.ToCertificate(x509Cert)
		cert.Id = id
		if privateKeyId, found := mc.certPrivateKey[id]; found {
			cert.PrivateKeyId.Int64 = privateKeyId
			cert.PrivateKeyId.Valid = true
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (mc *mockStore) GetCertificatePrivateKeyId(certificateId int64) (int64, error) {
	if privateKeyId, found := mc.certPrivateKey[certificateId]; found {
		return privateKeyId, nil
	}
	return 0, fmt.Errorf("certificate ID %d not found", certificateId)
}

func (mc *mockStore) GetPrivateKey(privateKeyId int64) (*store.PrivateKey, error) {
	privateKey := mc.privateKeys[privateKeyId]
	if privateKey == nil {
		return nil, fmt.Errorf("private key ID %d not found", privateKeyId)
	}
	return privateKey, nil
}

func (mc *mockStore) StorePrivateKey(privateKey *store.PrivateKey, linkCert bool) (int64, error) {
	mc.lastPrivateKeyId++
	mc.privateKeys[mc.lastPrivateKeyId] = privateKey
	if linkCert {
		// For testing purpose, we link this private key with the first certificate ID
		// which currently does not have a private key associated with it.
		var lastCertId int64
		for certId := range mc.certPrivateKey {
			if certId > lastCertId {
				lastCertId = certId
			}
		}
		mc.certPrivateKey[lastCertId+1] = mc.lastPrivateKeyId
	}
	return mc.lastPrivateKeyId, nil
}

func (mc *mockStore) GetX509Certificate(certificateId int64) (*x509.Certificate, error) {
	x509Certificate := mc.certificates[certificateId]
	if x509Certificate == nil {
		return nil, fmt.Errorf("certificate ID %d does not exist", certificateId)
	}
	return x509Certificate, nil
}

func (mc *mockStore) StoreX509Certificate(x509cert *x509.Certificate) (int64, error) {
	mc.lastCertId++
	mc.certificates[mc.lastCertId] = x509cert
	return mc.lastCertId, nil
}

func LoadCertificates(cs CertStore, filenames []string) error {
	for _, filename := range filenames {
		filepath := path.Join("../../testdata", filename)
		certs, privateKeys, err := certificates.ParsePEMFile(filepath)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			if _, err = cs.StoreX509Certificate(cert); err != nil {
				return err
			}
		}
		for _, privateKey := range privateKeys {
			pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey.PrivateKey)
			if err != nil {
				return err
			}
			publicKey, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
			if err != nil {
				return err
			}
			pk := &store.PrivateKey{
				// For testing purpose, we do not actually encrypt the private key, we store it as is
				EncryptedPKCS8:    pkcs8,
				PublicKey:         publicKey,
				Type:              privateKey.Type(),
				PEMType:           privateKey.PEMType,
				SHA256Fingerprint: common.SHA256Hex(publicKey),
			}
			if _, err := cs.StorePrivateKey(pk, true); err != nil {
				return err
			}
		}
	}
	return nil
}
