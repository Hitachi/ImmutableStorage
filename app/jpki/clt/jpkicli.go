/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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

package jpkicli

import (
	"encoding/asn1"
	"encoding/json"
	//	"encoding/hex"
	"encoding/base64"
	"encoding"
	"crypto/x509"
	"crypto/sha256"
	"crypto/tls"
	"crypto/rsa"
	"time"
	"math"
	"errors"
	"fmt"
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"immop"
	"immclient"
)

const (
	FGetRequiredPrivInfo = "GetRequiredPrivInfo"
	FRegisterJPKIUser = "RegisterJPKIUser"
	FGetJPKIUsername = "GetJPKIUsername"
	FEnrollJPKIUser = "EnrollJPKIUser"
	FDebugData = "DebugData"

	PrivTypePub = "publicKey"
	PrivTypeAuthCert = "authCert"
	PrivTypeSignCert = "signCert"
)

func GetHashStateUntilSKI(cert *x509.Certificate) (hashState []byte, retErr error) {
	var tag int64
	var offset int32 = 0
	var relativeOffset int32
	var length int32
	var isCompound bool
	var err error
	structLen := int32(0)
	subjKeyIdOidStr := string([]byte{0x55, 0x1d, 0x0e})
	
	raw := cert.RawTBSCertificate // get a TBS (To Be Signed)
	for {
		tag, relativeOffset, length, isCompound, err = ParseTagAndLen(raw[offset:])
		if err != nil {
			retErr = fmt.Errorf("failed to parse a TBS certificate: %s", err)
			return
		}

		if tag == asn1.TagOID /*6*/ {
			value := raw[offset+relativeOffset:]
			value = value[:length]
			valueStr := string(value)
			
			if valueStr == subjKeyIdOidStr {
				hashTBS := sha256.New()
				hashTBS.Write(raw[:offset+relativeOffset+length])
				hashState, _ = hashTBS.(encoding.BinaryMarshaler).MarshalBinary()
				return
			}

			for readLen := (relativeOffset+length); readLen < structLen; readLen +=  relativeOffset + length {
				offset += relativeOffset + length
				
				tag, relativeOffset, length, isCompound, err = ParseTagAndLen(raw[offset:])
				if err != nil {
					retErr = fmt.Errorf("failed to parse an extension structure: %s", err)
					return
				}

				switch tag {
				case asn1.TagOctetString: /* 4 */ 
					value = raw[offset+relativeOffset:]
					value = value[:length]
				case asn1.TagBoolean: /* 1 */
					value = raw[offset+relativeOffset:]
					if len(value) < 1 || length != 1 {
						retErr = fmt.Errorf("unexpected data length")
						return
					}

					value = value[:1]
				}
			}
		}

		if isCompound {
			offset += relativeOffset
			structLen = length
		} else {
			offset += relativeOffset + length
		}
		
		if int(offset) >= len(raw) {
			retErr = fmt.Errorf("SKI not found")
			return
		}
	}

	return
}


func ParseTagAndLen(raw []byte) (tag int64, offset, len int32, isCompound bool, retErr error) {
	// get ANS1 tag and length
	tagAndLen := raw

	b := tagAndLen[0]
	isCompound = (b & 0x20) == 0x20
	tag = int64(tagAndLen[0] & 0x1f)
	offset = 1
	tmp := int64(tagAndLen[offset])
	
	if (tag == 0x1f) && (tmp == 0x80) {
		retErr = fmt.Errorf("unexpected data") // error
		return 
	}

	if tag == 0x1f {
		for i := 1; i <= 5; i++ {
			if i == 5 {
				retErr = fmt.Errorf("unexpected tag in data") // error
				return
			}
			
			tag = tag << 7
			tag = tag | (tmp & 0x7f)
			
			offset++
			if (tmp&0x80) == 0 {
				if tag > math.MaxInt32 {
					retErr = fmt.Errorf("too large for a tag") // error
					return
				}
				break
			}
			tmp = int64(tagAndLen[offset])
		}
	}
	
	// max offset = 5
	tmpLen := int32(tagAndLen[offset])
	len = 0
	offset++

	if (tmpLen & 0x80) == 0 {
		len = tmpLen & 0x7f
	} else {
		n := tmpLen & 0x7f
		if (n == 0) || (n > 4) {
			retErr = fmt.Errorf("unexpected length") // error
			return
		}

		for i := 0; i < int(n); i++ {
			lenByte := int32(tagAndLen[offset])
			offset++

			if  len >= 1 << 23  {
				retErr = fmt.Errorf("length too large") // error
				return
			}

			len = len << 8
			len = len | lenByte
		}
		if len < 0x80 {
			retErr = fmt.Errorf("incorrect data") // error
			return
		}
    }

	return
}


func jpkiFunc(url, funcName string, req, reply interface{}) error {
	var reqJson []byte
	var err error
	if req != nil {
		reqJson, err = json.Marshal(req)
		if err != nil {
			return errors.New(funcName + ": unexpected request: " + err.Error())
		}
	}
	
	conn, err := grpc.Dial(url, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true,})))
	if err != nil {
		return errors.New(funcName + ": " + err.Error())
	}
	defer conn.Close()
	
	cli := immop.NewImmOperationClient(conn)
	reqGrpc := &immop.JPKIFuncRequest{
		Func: funcName,
		Req: reqJson,
	}

	rsp, err := cli.JPKIFunc(context.Background(), reqGrpc)
	if err != nil {
		return errors.New(funcName + ": " + err.Error())
	}
	
	err = json.Unmarshal(rsp.Rsp, reply)
	if err != nil {
		return errors.New(funcName + ": unexpected response: " + err.Error())
	}

	return nil // success
}

type RequiredPrivInfoReply struct {
	Type string `json:"cert"`
}

func GetRequiredPrivInfo(url string) (privType string, retErr error) {
	info := &RequiredPrivInfoReply{}
	err := jpkiFunc(url, FGetRequiredPrivInfo, nil, info)
	if err != nil {
		retErr = err
		return
	}

	privType = info.Type
	return // success
}

type RegisterJPKIUserRequest struct {
	AuthCert []byte `json:"AuthCert,omitempty"`
	
	AuthPub  []byte `json:"AuthPub,omitempty"`
	AuthHashState []byte `json:"AuthHashState,omitempty"`
	AuthCertSign []byte `json:"AuthCertSign,omitempty"`
	
	AuthDigest []byte `json:"AuthDigest"`
	AuthSignature []byte `json:"AuthSignature"`
	
	SignCert []byte `json:"SignCert,omitempty"`
	
	SignPub  []byte `json:"SignPub,omitempty"`
	SignHashState []byte `json:"SignHashState,omitempty"`
	SignCertSign []byte `json:"SignCertSign,omitempty"`
	
	SignDigest []byte `json:"SignDigest"`
	SignSignature []byte `json:"SignSignature"`

	GroupName string `json:"GroupName"`
}

type RegisterJPKIUserReply struct {
	Name string `json:"Name"`
}

func RegisterJPKIUser(url string, jpkiUser *RegisterJPKIUserRequest) (username string, retErr error) {
	rsp := &RegisterJPKIUserReply{}	
	err := jpkiFunc(url, FRegisterJPKIUser, jpkiUser, rsp)
	if err != nil {
		retErr = err
		return
	}

	username = rsp.Name
	return // success
}

type EnrollJPKIUserRequest struct {
	Digest []byte `json:"Digest"`
	Signature []byte `json:"Signature"`
	AuthPub []byte `json:"AuthPub,omitempty"`
	SignPub []byte `json:"SignPub,omitempty"`
	CSR []byte `json:"CSR"`
}

type EnrollJPKIUserReply struct {
	Cert []byte `json:"Cert"`
}

func EnrollJPKIUser(url, username string, user *EnrollJPKIUserRequest) (privPem, certPem []byte, retErr error) {
	privPem, csrPem, err := immclient.CreateCSR(username)
	if err != nil {
		retErr = err
		return
	}

	user.CSR = csrPem
	rsp := &EnrollJPKIUserReply{}
	err = jpkiFunc(url, FEnrollJPKIUser, user, rsp)
	if err != nil {
		retErr = err
		return
	}

	certPem = rsp.Cert
	return // success
}

type GetJPKIUsernameRequest struct {
	Digest []byte `json:"Digest"`
	Signature []byte `json:"Signature"`
	AuthPub []byte `json:"AuthPub,omitempty"`
	SignPub []byte `json:"SignPub,omitempty"`
	GroupName string `json:"GroupName"`
}

type GetJPKIUsernameReply struct {
	Name string `json:"Name"`
}

func GetJPKIUsername(url string, signStr *GetJPKIUsernameRequest) (username string, retErr error) {
	rsp := &GetJPKIUsernameReply{}	
	err := jpkiFunc(url, FGetJPKIUsername, signStr, rsp)
	if err != nil {
		retErr = err
		return
	}

	username = rsp.Name
	return // success
}

type JPKIRecord struct {
	Digest string `json:"Digest"`
	Signature string `json:"Signature"`
}

type DebugDataRequest struct {
	Data string `json:"Data"`
}

type DebugDataReply struct {
}

func DebugData(url string, dData *DebugDataRequest) (retErr error) {
	rsp := &DebugDataReply{}
	retErr = jpkiFunc(url, FDebugData, dData, rsp)
	return
}

type jsonCert struct {
	Cert string `json:"cert"`
	Err string `json:"err"`
}

type jsonSignature struct {
	Signature string `json:"signature"`
	Err string `json:"err"`
}

type GenerateSignatureRsp struct {
	Digest []byte
	Signature []byte
	PubAsn1 []byte
	CertAsn1 []byte
	Cert *x509.Certificate
}

type SignInf interface {
	SignData(pin, digest string) (signatureJson string)
	GetCert(pin string) (certJson string)
}

func SignData(si SignInf, pin, digest string) (signature []byte, retErr error) {
	signatureJson := si.SignData(pin, digest)
	jSign := &jsonSignature{}
	err := json.Unmarshal([]byte(signatureJson), jSign)
	if err != nil {
		retErr = errors.New("failed to create a signature: " + err.Error())
		return
	}
	if jSign.Err != "" {
		retErr = errors.New(jSign.Err)
		return
	}
	signature, err = base64.StdEncoding.DecodeString(jSign.Signature)
	if err != nil {
		retErr = errors.New("unexpected signature: " + err.Error())
		return
	}
	return // success
}

func GenerateSignature(si SignInf, pin string) (rsp *GenerateSignatureRsp, retErr error) {
	rsp = &GenerateSignatureRsp{}
	
	var err error
	rsp.Digest, err = time.Now().MarshalBinary()
	if err != nil {
		retErr = errors.New("failed to get current time: " + err.Error())
		return
	}

	hashVal := sha256.Sum256(rsp.Digest)
	digest := base64.StdEncoding.EncodeToString(hashVal[:])
	rsp.Signature, retErr = SignData(si, pin, digest)
	if retErr != nil {
		return
	}

	signCertJson := si.GetCert(pin)
	jCert := &jsonCert{}
	err = json.Unmarshal([]byte(signCertJson), jCert)
	if err != nil {
		retErr = errors.New("unexpected data: " + err.Error())
		return
	}
	if jCert.Err != "" {
		retErr = errors.New(jCert.Err)
		return
	}

	rsp.CertAsn1, err = base64.StdEncoding.DecodeString(jCert.Cert)
	if err != nil {
		retErr = err
		return
	}

	cert, err := x509.ParseCertificate(rsp.CertAsn1)
	if err != nil {
		retErr = errors.New("unexpected certificate: " + err.Error())
		return
	}
	rsp.Cert = cert

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		retErr = errors.New("unexpected public key")
		return
	}
	rsp.PubAsn1 = x509.MarshalPKCS1PublicKey(pubKey)

	return // success
}

