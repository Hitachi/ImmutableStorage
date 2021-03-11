/*
Copyright Hitachi, Ltd. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package immutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha256"
	"encoding/pem"
	"encoding/hex"
	"math/big"
	"time"
	"fmt"
)

func ReadCertificate(certPem []byte) (cert *x509.Certificate, pubSki [sha256.Size]byte, retErr error) {
	certData, _ := pem.Decode(certPem)
	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate: " + err.Error())
		return
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		retErr = fmt.Errorf("unsuppted type of key")
		return
	}
	pubSki = sha256.Sum256( elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y) )

	return
}

func ReadPrivateKey(privPem []byte) (privKey *ecdsa.PrivateKey, retErr error) {
	privData, _ := pem.Decode(privPem)
	if privData.Type != "PRIVATE KEY" {
		retErr = fmt.Errorf("unexpected private key (type=%s)", privData.Type)
		return
	}
	if x509.IsEncryptedPEMBlock(privData) {
		retErr = fmt.Errorf("not support encrypted PEM")
		return
	}
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		retErr = fmt.Errorf("unsupported key format: %s", err)
		return
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		retErr = fmt.Errorf("unexpected key type")
		return
	}

	return // success
}

func CheckKeyPair(privPem, pubPem []byte) (error) {
	_, ski, err:= ReadCertificate(pubPem)
	if err != nil {
		return err
	}

	privKey, err := ReadPrivateKey(privPem)
	if err != nil {
		return err
	}

	skiP := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y) )
	if ski != skiP {
		return fmt.Errorf("There is a mismatch between private and public key")
	}

	return nil
}

func GenerateKeyPair(subj *pkix.Name, dnsNames []string) (privPem, pubPem []byte, skiStr string, retErr error) {
	// generate a private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		retErr = fmt.Errorf("Failed to generate a private key: %s\n", err)
		return
	}

	privAsn1, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to marshal an ecdsa private key into ASN.1 DEF format: %s", err)
		return
	}
	privPem = pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )

	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )
	skiStr = hex.EncodeToString(ski[:])

	
	// generate a public key
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	nowT := time.Now().UTC()
	certTempl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore: nowT,
		NotAfter: nowT.Add(365*10*24*time.Hour).UTC(),
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: *subj,
		SubjectKeyId: ski[:],
	}
	
	if certTempl.Subject.CommonName != "" {
		certTempl.DNSNames = append(certTempl.DNSNames, certTempl.Subject.CommonName)
	}
	if dnsNames != nil {
		for _, dnsName := range dnsNames {
			certTempl.DNSNames = append(certTempl.DNSNames, dnsName)
		}
	}
	
	cert, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, privKey.Public(), privKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to create a certificate: %s", err)
		return
	}
	pubPem = pem.EncodeToMemory( &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return
}

func CreateCertificate(subj *pkix.Name, caPrivPem, caCertPem []byte, dnsNames []string) (privPem, certPem []byte, retErr error) {
	// generate a private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		retErr = fmt.Errorf("Failed to generate a private key: %s\n", err)
		return
	}

	privAsn1, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to marshal an ecdsa private key into ASN.1 DEF format: %s", err)
		return
	}
	privPem = pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )
	
	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )

	// generate a public key
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	nowT := time.Now().UTC()
	certTempl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore: nowT,
		NotAfter: nowT.Add(365*10*24*time.Hour).UTC(),
		BasicConstraintsValid: true,
		IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: *subj,
		SubjectKeyId: ski[:],
	}

	if certTempl.Subject.CommonName != "" {
		certTempl.DNSNames = append(certTempl.DNSNames, certTempl.Subject.CommonName)
	}
	if dnsNames != nil {
		for _, dnsName := range dnsNames {
			certTempl.DNSNames = append(certTempl.DNSNames, dnsName)
		}
	}

	caCert, _, retErr := ReadCertificate(caCertPem)
	if retErr != nil {
		return
	}

	caPrivKey, retErr := ReadPrivateKey(caPrivPem)
	if retErr != nil {
		return
	}
	
	cert, err := x509.CreateCertificate(rand.Reader, certTempl, caCert, privKey.Public(), caPrivKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to create a certificate: %s", err)
		return
	}
	certPem = pem.EncodeToMemory( &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return
}

func CreateTemporaryCert(baseCert *x509.Certificate, caPrivPem, caCertPem []byte) (privPem, certPem []byte, retErr error) {
	// generate a private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		retErr = fmt.Errorf("Failed to generate a private key: %s\n", err)
		return
	}

	privAsn1, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to marshal an ecdsa private key into ASN.1 DEF format: %s", err)
		return
	}
	privPem = pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )
	
	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )
	
	nowT := time.Now().UTC()
	certTempl := &x509.Certificate{
		SerialNumber: baseCert.SerialNumber,
		NotBefore: nowT,
		NotAfter: nowT.Add(5*time.Minute).UTC(),
		BasicConstraintsValid: true,
		IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: baseCert.Subject,
		ExtraExtensions: baseCert.ExtraExtensions,
		SubjectKeyId: ski[:],
		AuthorityKeyId: baseCert.AuthorityKeyId,
	}

	caCert, _, retErr := ReadCertificate(caCertPem)
	if retErr != nil {
		return
	}

	caPrivKey, retErr := ReadPrivateKey(caPrivPem)
	if retErr != nil {
		return
	}

	cert, err := x509.CreateCertificate(rand.Reader, certTempl, caCert, privKey.Public(), caPrivKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to create a certificate: %s", err)
		return
	}
	certPem = pem.EncodeToMemory( &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return
}

func NewCertSubject(baseCertPem []byte, hostname string) (subj *pkix.Name, retErr error) {
	baseCert, _, retErr := ReadCertificate(baseCertPem)
	if retErr != nil {
		return
	}

	org := baseCert.Subject.Organization[0]
	subj = &pkix.Name{
		Country: baseCert.Subject.Country,
		Organization: baseCert.Subject.Organization,
		Locality: baseCert.Subject.Locality,
		Province: baseCert.Subject.Province,
		CommonName: hostname + "." + org,
	}
	
	return
}
