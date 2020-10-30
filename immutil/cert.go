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
	"io/ioutil"
	"math/big"
	"time"
	"fmt"
	"os"
)

func CreateSelfKeyPair(subj *pkix.Name, caKeyDir string) (caPrivFile, caCertFile string, retErr error) {
	caCertFile =  subj.CommonName + "-cert.pem"

	finfo, err := os.Lstat(caKeyDir)
	if err != nil {
		if os.IsNotExist(err) {
			err2 := os.MkdirAll(caKeyDir, 0755)
			if err2 != nil {
				retErr = fmt.Errorf("could not make a directory: %s\n", err2)
				return
			}
		} else {
			retErr = fmt.Errorf("%s is unexpected state: %s\n", caKeyDir, err)
			return
		}
	} else {
		if finfo.IsDir() == false {
			retErr = fmt.Errorf("%s is not direcotry\n", caKeyDir)
			return
		}
	}

	caCertPath := caKeyDir + "/" + caCertFile
	_, err = os.Stat(caCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			privPem, pubPem, skiStr, err2 := GenerateKeyPair(subj, nil)
			if err2 != nil {
				retErr = err2
				return
			}
			
			caPrivFile = skiStr + "_sk"
			err = ioutil.WriteFile(caKeyDir + "/" + caPrivFile, privPem, 0400)
			if err != nil {
				retErr = err
				return
			}
			
			err = ioutil.WriteFile(caCertPath, pubPem, 0444)
			if err != nil {
				retErr = err
				return
			}

			return
		}

		retErr = fmt.Errorf("%s is unexpected state: %s\n", caCertPath, err)
		return
	}

	pubPem, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		retErr = fmt.Errorf("failed to read %s\n", caCertPath)
		return
	}

	uCertData, _ := pem.Decode(pubPem)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		retErr = err
		return
	}
        
	pubkey, ok := uCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		retErr = fmt.Errorf("unexpected public key\n")
		return
	}
        
	ski := sha256.Sum256( elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y) )
	skiStr := hex.EncodeToString(ski[:])
	caPrivFile = skiStr + "_sk"

	privPem, err := ioutil.ReadFile(caKeyDir + "/" + caPrivFile)
	if err != nil {
		retErr = fmt.Errorf("could not read private key (%s): %s", caPrivFile, err)
		return
	}
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
	caPrivKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		retErr = fmt.Errorf("unexpected key file: %s", caPrivFile)
		return
	}

	skiP := sha256.Sum256( elliptic.Marshal(caPrivKey.Curve, caPrivKey.X, caPrivKey.Y) )
	if ski != skiP {
		retErr = fmt.Errorf("There is a mismatch between %s and %s", caPrivFile, caCertFile)
		return
	}

	return
}

func CheckKeyPair(privPem, pubPem []byte) (error) {
	uCertData, _ := pem.Decode(pubPem)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		return err
	}
        
	pubkey, ok := uCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unexpected public key")
	}        
	ski := sha256.Sum256( elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y) )
	
	privData, _ := pem.Decode(privPem)
	if privData.Type != "PRIVATE KEY" {
		return fmt.Errorf("unexpected key (type=%s)", privData.Type)
	}
	if x509.IsEncryptedPEMBlock(privData) {
		return fmt.Errorf("not support encrypted PEM")
	}
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		return fmt.Errorf("unsupported key format: %s", err)
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected private key type")
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

	caPrivData, _ := pem.Decode(caPrivPem)
	if caPrivData.Type != "PRIVATE KEY" {
		retErr = fmt.Errorf("unexpected private key (type=%s)", caPrivData.Type)
		return
	}
	if x509.IsEncryptedPEMBlock(caPrivData) {
		retErr = fmt.Errorf("not support encrypted PEM")
		return
	}
	caPrivKeyBase, err := x509.ParsePKCS8PrivateKey(caPrivData.Bytes)
	if err != nil {
		retErr = fmt.Errorf("unsupported key format: %s", err)
		return
	}
	caPrivKey, ok := caPrivKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		retErr = fmt.Errorf("unexpected key type")
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
