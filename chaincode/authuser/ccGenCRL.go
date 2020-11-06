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

package authuser

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/msp"	
	"crypto/x509"
//	"crypto/tls"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
	"encoding/pem"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"encoding/asn1"
	"math/big"
	"net/http"
	"bytes"
	"time"
	"io/ioutil"
	"fmt"
	"errors"
	"bufio"
	"os"

	"github.com/cloudflare/cfssl/api"
	"github.com/mitchellh/mapstructure"	
)

type CAKeys interface {
	name()  string
	cert()  *[]byte
	uCert() *[]byte
	uPriv() *[]byte
}

type CAAuthUser struct {
	ca CAKeys
}

type ECDSASignature struct {
        R, S *big.Int
}

// GenCRLRequest represents a request to get CRL for the specified certificate authority
type GenCRLRequest struct {
        CAName        string    `json:"caname,omitempty" skip:"true"`
        RevokedAfter  time.Time `json:"revokedafter,omitempty"`
        RevokedBefore time.Time `json:"revokedbefore,omitempty"`
        ExpireAfter   time.Time `json:"expireafter,omitempty"`
        ExpireBefore  time.Time `json:"expirebefore,omitempty"`
}

// The response to the POST /gencrl request
type genCRLResponseNet struct {
        // Base64 encoding of PEM-encoded CRL
        CRL string
}

func (au *CAAuthUser) setKeys(keys CAKeys) {
	au.ca = keys
}

const (
	permConfDir = "/var/lib/chainConf"
)

func (au *CAAuthUser) createClient(req_data []byte, req *http.Request) (*http.Client, error) {
	privRaw := au.ca.uPriv()
	if privRaw == nil {
		return nil, fmt.Errorf("could not read a private key")
	}

	uCertRaw := au.ca.uCert()
	if uCertRaw == nil {
		return nil, fmt.Errorf("could not read a certificate")
	}
	
/*
	certRaw := au.ca.Cert()
	if certRaw == nil {
		return nil, fmt.Errorf("could not read a CA certificate")
	}
*/
	
	privData, _ := pem.Decode(*privRaw)
	if x509.IsEncryptedPEMBlock(privData) {
		fmt.Printf("not support encrypted PEM\n")
		return nil, fmt.Errorf("not support encrypted PEM")
	}

	fmt.Printf("type: %s\npriv bytes: %s\n", privData.Type, hex.Dump(privData.Bytes))

	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		fmt.Printf("unsupported key format: %s\n", err)
		return nil, fmt.Errorf("not support key format")
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Printf("unexpected key\n")
		return nil, nil
	}	

	// generate token
	reqBase64 := base64.StdEncoding.EncodeToString(req_data)
	certBase64 := base64.StdEncoding.EncodeToString(*uCertRaw)
	fmt.Printf("cert:\n%s\n", *uCertRaw)
	fmt.Printf("base64_cert:%s\n", certBase64)
	fmt.Printf("msg:\n%s\n", reqBase64 + "." + certBase64)

	digest := sha256.Sum256( []byte(reqBase64 + "." + certBase64) )
	fmt.Printf("digest:\n%s\n", hex.Dump(digest[:]))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s\n", err)
	}
	baseN := privKey.Params().N
	if s.Cmp(new(big.Int).Rsh(baseN, 1)) == 1 {
		s.Sub(baseN, s)
	}
	signRaw, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %s\n", err)
	}

	token := certBase64 + "." + base64.StdEncoding.EncodeToString(signRaw)
	req.Header.Set("authorization", token)

/*
	rootCAPool := x509.NewCertPool()
	ok = rootCAPool.AppendCertsFromPEM(*certRaw)
	if !ok {
		fmt.Printf("failed to append a certfifcate file\n")
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAPool}}

	return &http.Client{Transport: tr}, nil
*/
	return &http.Client{}, nil
}

func (au *CAAuthUser) genCRL(caHost string) ([]byte, error) {
	req := &GenCRLRequest{}
	req_data, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("error: failed to marshal\n")
		return nil, err
	}

	gencrlURL := "https://" + caHost + ":7054/gencrl"
	gencrl_req, err := http.NewRequest("POST", gencrlURL, bytes.NewReader(req_data))
	if err != nil {
		fmt.Printf("error: NewRequest: %s\n", err)
		return nil, err
	}

	client, err := au.createClient(req_data, gencrl_req)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	resp, err := client.Do(gencrl_req)
	if (err != nil) || resp.Body == nil {
		fmt.Printf("failed to request\n")
		fmt.Printf("error: %s\n", err)
		return nil, err
	}
	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("failed to close the body: %s\n", err)
		}
	}()
	if err != nil {
		fmt.Printf("could not read the body: %s\n", err)
		return nil, err
	}

	fmt.Printf("body: \n%s\n", hex.Dump(respBody))
	
	body := &api.Response{}
	err = json.Unmarshal(respBody, body)
	if err != nil {
		fmt.Printf("unexpected body: %s\n", err)
		return nil, err
	}
	if len(body.Errors) > 0 {
		fmt.Printf("error response:\n")
		for i, errMsg := range body.Errors {
			fmt.Printf("error %d: %s: code=%d\n", i, errMsg.Message, errMsg.Code)
		}

		return nil, err
	}

	crl := &genCRLResponseNet{}
	mapstructure.Decode(body.Result, crl)
	crlRaw, err := base64.StdEncoding.DecodeString(crl.CRL)
	if err != nil {
		fmt.Printf("unexpected CRL format: %s\n", err)
		return nil, err
	}

	return crlRaw, nil	
}

func (au *CAAuthUser) GetUser(APIstub shim.ChaincodeStubInterface) (*x509.Certificate, error) {
	creator, err := APIstub.GetCreator()
	if err != nil {
		return nil, err
	}
	sId := &msp.SerializedIdentity{}
	err = proto.Unmarshal(creator, sId)
	p, _ := pem.Decode(sId.IdBytes)
	if p.Type != "CERTIFICATE" {
		return nil, errors.New("Unexpected identity")
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, errors.New("Unexpected identity")
	}

	return cert, nil
}


func (au CAAuthUser) ValidateUser(cert *x509.Certificate) bool {
	uCertRaw := au.ca.uCert()
	if uCertRaw == nil {
		return true // ignore CRL
	}

	uCertData, _ := pem.Decode(*uCertRaw)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return false
	}

	if (len(cert.Issuer.Organization) != 1) || (len(uCert.Issuer.Organization) != 1) {
		fmt.Printf("user org: %d, ca org: %d\n", len(cert.Issuer.Organization), len(uCert.Issuer.Organization)) 
		fmt.Printf("Unexpected organization\n")
		return false
	}

	if cert.Issuer.Organization[0] != uCert.Issuer.Organization[0] {
		fmt.Printf("We cannot validate the specified user in %s, because the user does not belong to %s.",
			cert.Issuer.Organization, uCert.Issuer.Organization)
		return true
	}

	caHost := cert.Issuer.CommonName
	crl, err := au.genCRL(caHost)
	if err != nil {
		return false
	}

	certList, err := x509.ParseCRL(crl)
	if err != nil {
		fmt.Printf("unexpected CRL\n")
		return false
	}

	for _, revokedCert := range certList.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return false
		}
	}

	return true
}

func (au *CAAuthUser) HasPermission(cert *x509.Certificate, funcName string) bool {
	if len(cert.Issuer.Organization) <= 0 {
		fmt.Printf("log: unexpected certificate\n")
		return false
	}
	org := cert.Issuer.Organization[0]

	allowFile := permConfDir + "/" + org + "." + funcName + "AllowedUser.list"
	denyFile  := permConfDir + "/" + org + "." + funcName + "DeniedUser.list"
	
	var deniedList, allowedList []byte
	deniedList, err := ioutil.ReadFile(denyFile)
	if os.IsNotExist(err) {
		allowedList, err = ioutil.ReadFile(allowFile)
		if os.IsNotExist(err) {
			return true
		}
	}
	
	fmt.Printf("log: check denied list\n")
	deniedScan := bufio.NewScanner(bytes.NewReader(deniedList))
	for deniedScan.Scan() {
		if cert.Subject.CommonName == deniedScan.Text() {
			return false
		}
	}

	fmt.Printf("log: check allowed list\n")
	allowedScan := bufio.NewScanner(bytes.NewReader(allowedList))
	for allowedScan.Scan() {
		if cert.Subject.CommonName == allowedScan.Text() {
			return true
		}
	}

	return false
}
