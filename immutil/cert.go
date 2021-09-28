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
	"encoding/json"
	"math/big"
	"strings"
	"time"
	"fmt"

	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	cfgMapFedUser = "-feduser"
	cfgMapFedGrp = "-fedgrp"

	cmFedUserLabel = "federatedUser"
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


type certID struct{
	SerialNumber string `json:"sn"`
	AuthorityKeyId []byte `json:"aki"`
	AuthType string `json:"authtype,omitempty"`
}

func StoreCertID(certPem []byte, authType string) error {
	cert, _, err := ReadCertificate(certPem)
	if err != nil {
		return err
	}

	cfgMapClient, err := K8sGetConfigMapsClient()
	if err != nil {
		return err
	}

	fedName := strings.TrimPrefix(cert.Subject.CommonName, "@")
	cfgMapSuffix := cfgMapFedUser
	if fedName != cert.Subject.CommonName {
		cfgMapSuffix = cfgMapFedGrp
	}
	cfgMapName := cert.Issuer.CommonName + cfgMapSuffix

	if strings.Contains(fedName, "@") {
		return fmt.Errorf("invalid username: " + cert.Subject.CommonName)
	}
		
	fedMap, err := cfgMapClient.Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil || fedMap == nil {
		fedMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: cfgMapName,
				Labels: map[string] string{
					"config": cmFedUserLabel,
				},
			},
		}

		fedMap, err = cfgMapClient.Create(context.TODO(), fedMap, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create a ConfigMap for federated user: " + err.Error())
		}
	}

	id := &certID{
		SerialNumber: cert.SerialNumber.Text(62),
		AuthorityKeyId: cert.AuthorityKeyId,
	}
	if authType != "LDAP" {
		id.AuthType = authType
	}

	certIDRaw, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("failed to marshal a certificate ID: %s\n", err)
	}
	
	if fedMap.BinaryData == nil {
		fedMap.BinaryData = make(map[string][]byte)
	}
	fedMap.BinaryData[fedName] = certIDRaw
	_, err = cfgMapClient.Update(context.TODO(), fedMap, metav1.UpdateOptions{})
	return err
}

func loadBaseCert(username, caName string) (*x509.Certificate, error) {
	cfgMapClient, err := K8sGetConfigMapsClient()
	if err != nil {
		return nil, err
	}

	tmpStrs := strings.SplitN(username, "@", 2)
	fedName := tmpStrs[0]
	adminName := fedName
	cfgMapSuffix := cfgMapFedUser
	if len(tmpStrs) == 2 {
		fedName = tmpStrs[1]
		adminName = "@"+fedName
		cfgMapSuffix = cfgMapFedGrp
	}

	cfgMapName := caName + cfgMapSuffix
	fedMap, err := cfgMapClient.Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil || fedMap == nil {
		return nil, fmt.Errorf("not found user")
	}

	if fedMap.BinaryData == nil {
		return nil, fmt.Errorf("invalid configuration for federated user")
	}

	certIDRaw, ok := fedMap.BinaryData[fedName]
	if !ok {
		return nil, fmt.Errorf(username + " is not found in " + caName)
	}

	id := &certID{}
	err = json.Unmarshal(certIDRaw, id)
	if err != nil {
		return nil, fmt.Errorf("corrupted configuration for federated user")
	}

	sn := &big.Int{}
	sn.SetString(id.SerialNumber, 62)
	baseCert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: adminName,
			OrganizationalUnit: []string{"client"},
		},
		AuthorityKeyId: id.AuthorityKeyId,
	}

	return baseCert, nil
}

func loadBaseCertForJPKI(caName string) (*x509.Certificate, error) {
	cfgMapClient, err := K8sGetConfigMapsClient()
	if err != nil {
		return nil, err
	}

	cfgMapName := caName + cfgMapFedGrp
	cfgMap, err := cfgMapClient.Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil || cfgMap == nil {
		return nil, fmt.Errorf("There is no ConfigMap for JPKI administrator on this machine")
	}
	
	if cfgMap.BinaryData == nil  || len(cfgMap.BinaryData) == 0 {
		return nil, fmt.Errorf("unexpected configuration for JPKI administrator")
	}

	var certIDRaw []byte
	var adminName string
	id := &certID{}
	foundF := false
	for adminName, certIDRaw = range cfgMap.BinaryData {
		err = json.Unmarshal(certIDRaw, id)
		if err != nil {
			return nil, fmt.Errorf("corrupted configuration for JPKI administator")
		}

		if id.AuthType == "JPKI" {
			foundF = true
			break
		}
	}

	if foundF == false {
		return nil, fmt.Errorf("There is no administrator for JPKI in a ConfigMap")
	}
	
	sn := &big.Int{}
	sn.SetString(id.SerialNumber, 62)
	baseCert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: "@" + adminName,
			OrganizationalUnit: []string{"client"},
		},
		AuthorityKeyId: id.AuthorityKeyId,
	}

	return baseCert, nil
}

type AdminID struct{
	Name string
	Priv []byte
	Cert []byte
}

func GetAdminID(username, caName string) (id *AdminID, retErr error) {
	baseCert, err := loadBaseCert(username, caName)
	if err != nil {
		retErr = fmt.Errorf("not found administrator: " + err.Error())
		return
	}

	caPriv, caCert, err := K8sGetKeyPair(caName)
	if err != nil {
		retErr = fmt.Errorf("There is no CA on this server: " + err.Error())
		return
	}

	adminPriv, adminCert, err := CreateTemporaryCert(baseCert, caPriv, caCert)
	if err != nil {
		retErr = fmt.Errorf("failed to create a temporary certificate: " + err.Error())
		return
	}

	id = &AdminID{Name: baseCert.Subject.CommonName, Priv: adminPriv, Cert: adminCert, }
	return // success
}

func GetAdminJPKI(caName string) (id *AdminID, retErr error) {
	caPriv, caCert, err := K8sGetKeyPair(caName)
	if err != nil {
		retErr = fmt.Errorf("There is no CA on this server: " + err.Error())
		return
	}
	
	baseCert, err := loadBaseCertForJPKI(caName)
	if err != nil {
		retErr = fmt.Errorf("There is no administrator for JPKI: " + err.Error())
		return
	}
	
	tmpPriv, tmpCert, err := CreateTemporaryCert(baseCert, caPriv, caCert)
	if err != nil {
		retErr = fmt.Errorf("failed to create a temporary certificate: " + err.Error())
		return
	}

	adminName := baseCert.Subject.CommonName
	id = &AdminID{Name: adminName, Priv: tmpPriv, Cert: tmpCert, }
	return // success
}
