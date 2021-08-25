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

package main

import (
	"fmt"
	"strings"
	"math/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"encoding/json"
	"encoding"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha1"
	"crypto/sha256"
	"crypto"
	"time"
	"bytes"
	"github.com/golang/protobuf/proto"
	
	"immop"
	"immclient"
	"immutil"
	"jpkicli"

	_ "embed"
)

//go:embed authca01.cer
var authca01 []byte
//go:embed authca02.cer
var authca02 []byte
//go:embed signca01.cer
var signca01 []byte
//go:embed signca02.cer
var signca02 []byte


func registerJPKIAdmin(caCli *caClient, tmpPriv, tmpCert []byte, req *immop.RegisterUserRequest) ([]byte, error) {
	authParam := &immop.AuthParamJPKI{}
	err := proto.Unmarshal(req.AuthParam, authParam)
	if err != nil {
		return nil, fmt.Errorf("unexpected authentication parameter: %s", err)
	}

	fedGrpName := strings.TrimPrefix(authParam.UserNameOnCA, "@")
	if fedGrpName == authParam.UserNameOnCA {
		return nil, fmt.Errorf("invalid administrator name")
	}
	
	affiliation := affnJPKIPrefix + strings.ReplaceAll(authParam.UserNameOnCA, ".", ":")
	regReq := &immclient.RegistrationRequest{
		Name: authParam.UserNameOnCA,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: "JPKI.ImportItems", Value: authParam.ImportItems, ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Roles", Value: "client", ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Attributes", Value: "*", ECert: false},
		},
		Affiliation: affiliation,
		Type: "client",
		MaxEnrollments: -1, // unlimit
	}

	caRegID := &immclient.UserID{Name: "tmpUser", Priv: tmpPriv, Cert: tmpCert, Client: caCli}
	return caCli.registerAndEnrollAdmin(caRegID, regReq, 1/*one year*/)
}

func getAdminJPKI(caName string) (id *immclient.UserID, retErr error) {
	caPriv, caCert, err := immutil.K8sGetKeyPair(caName)
	if err != nil {
		retErr = fmt.Errorf("There is no CA on this server: " + err.Error())
		return
	}
	
	baseCert, err := loadBaseCertForJPKI(caName)
	if err != nil {
		retErr = fmt.Errorf("There is no administrator for JPKI: " + err.Error())
		return
	}
	
	tmpPriv, tmpCert, err := immutil.CreateTemporaryCert(baseCert, caPriv, caCert)
	if err != nil {
		retErr = fmt.Errorf("failed to create a temporary certificate: " + err.Error())
		return
	}

	adminName := baseCert.Subject.CommonName
	caCli := newCAClient("https://"+caName+defaultCAPortStr)
	id = &immclient.UserID{Name: adminName, Priv: tmpPriv, Cert: tmpCert, Client: caCli, }
	return // success
}

func getRequiredPrivInfo(caName string) (rsp []byte, retErr error) {
	var id *immclient.UserID
	id, retErr = getAdminJPKI(caName)
	if retErr != nil {
		return
	}

	privInfo := &jpkicli.RequiredPrivInfoReply{}
	privInfo.Type, retErr = getPrivInfoAttr(id)
	if retErr != nil {
		return
	}

	rsp, _ = json.Marshal(privInfo)
	return // sucess
}

func getPrivInfoAttr(id *immclient.UserID) (string, error) {
	adminAttr, err := id.GetIdentity("", id.Name)
	if err != nil {
		return "", fmt.Errorf("failed to get attributes of the administrator for JPKI: " + err.Error())
	}
	
	for _, attr := range adminAttr.Attributes {
		if attr.Name == "JPKI.ImportItems" {
			return attr.Value, nil // success
		}
	}
	
	return "", fmt.Errorf("unexpected CA response")
}

func registerJPKIUser(caName string, req []byte) (rsp []byte, retErr error) {
	var id *immclient.UserID
	id, retErr = getAdminJPKI(caName)
	if retErr != nil {
		return
	}

	uReq := &jpkicli.RegisterJPKIUserRequest{}
	err := json.Unmarshal(req, uReq)
	if err != nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	authPubKey, err := verifyCertSignature(uReq.AuthCert, uReq.AuthPub, uReq.AuthHashState, uReq.AuthCertSign,
		remainTBSForAuthCert, [][]byte{authca01, authca02})
	if err != nil {
		retErr = fmt.Errorf("authentication failure: " + err.Error())
		return
	}

	digest := sha256.Sum256(uReq.AuthDigest)
	err = rsa.VerifyPKCS1v15(authPubKey, 0/*crypto.SHA256*/, digest[:], uReq.AuthSignature)
	if err != nil {
		//retErr = fmt.Errorf("authentication failure")
		retErr = fmt.Errorf("authentication failure: authCert: %s", err)		
		return
	}

	privType, err := getPrivInfoAttr(id)
	if err != nil {
		retErr = err
		return
	}
	if (privType == jpkicli.PrivTypeAuthCert || privType == jpkicli.PrivTypeSignCert) && (uReq.AuthCert == nil) {
		retErr = fmt.Errorf("unexpected request")
		return
	}
	if privType == "signCert" && uReq.SignCert == nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	signPubKey, err := verifyCertSignature(uReq.SignCert, uReq.SignPub, uReq.SignHashState, uReq.SignCertSign,
		remainTBSForSignCert, [][]byte{signca01, signca02})
	if err != nil {
		retErr = fmt.Errorf("authentication failure: " + err.Error())
		return
	}

	digest = sha256.Sum256(uReq.SignDigest)
	err = rsa.VerifyPKCS1v15(signPubKey, 0/*crypto.SHA256*/, digest[:], uReq.SignSignature)
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	
	// authentication success
	authPubAsn1 := x509.MarshalPKCS1PublicKey(authPubKey)
	authPubBase64 := base64.StdEncoding.EncodeToString(authPubAsn1)
	signPubAsn1 := x509.MarshalPKCS1PublicKey(signPubKey)
	signPubBase64 := base64.StdEncoding.EncodeToString(signPubAsn1)

	fmt.Printf("authPubBase64:\n%s\n", authPubBase64)
	fmt.Printf("signPubBase64:\n%s\n", signPubBase64)

	jpkiUsername := "jp" + randName(8) + id.Name
	regReq := &immclient.RegistrationRequest{
		Name: jpkiUsername,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: "JPKI.AuthPub", Value: authPubBase64, ECert: false},
			immclient.Attribute{Name: "JPKI.SignPub", Value: signPubBase64, ECert: false},
		},
		Type: "client",
		MaxEnrollments: 1,
	}
	if privType == jpkicli.PrivTypeSignCert || privType == jpkicli.PrivTypeAuthCert {
		notBefore, notAfter, err := isValidCert(uReq.AuthCert)
		if err != nil {
			retErr = err
			return
		}

		regReq.Attributes = append(regReq.Attributes, immclient.Attribute{Name: "JPKI.NotBefore", Value: notBefore, ECert: false})
		regReq.Attributes = append(regReq.Attributes, immclient.Attribute{Name: "JPKI.NotAfter", Value: notAfter, ECert: false})
	}
	if privType == jpkicli.PrivTypeSignCert {
		privacyAttrs, err := getSignCertAttr(uReq.SignCert)
		if err != nil {
			retErr = err
			return
		}
		regReq.Attributes = append(regReq.Attributes, privacyAttrs...)
	}

	_, retErr = id.Client.(*caClient).registerCAUser(id, regReq)
	if retErr != nil {
		return
	}

	retErr = id.DisableEnrollment("", jpkiUsername)
	if retErr != nil {
		return
	}

	jsonRsp := &jpkicli.RegisterJPKIUserReply{
		Name: jpkiUsername,
	}

	rsp, err = json.Marshal(jsonRsp)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal your username: " + err.Error())
		return
	}
	
	return // success
}

func enrollJPKIUser(caName string, req []byte) (rsp []byte, retErr error) {
	uReq := &jpkicli.EnrollJPKIUserRequest{}
	err := json.Unmarshal(req, uReq)
	if err != nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	csrRaw, _ := pem.Decode(uReq.CSR)
	csrReq, err := x509.ParseCertificateRequest(csrRaw.Bytes)
	if err != nil {
		retErr = fmt.Errorf("unexpected requrest to create a certificate")
		return
	}

	username := csrReq.Subject.CommonName

	adminID, err := getAdminJPKI(caName)
	if err != nil {
		retErr = err
		return
	}

	userAttr, err := adminID.GetIdentity("", username)
	if err != nil {
		retErr = fmt.Errorf("authentication failrure")
		return
	}

	var userAuthPub []byte
	var userSignPub []byte
	var pub []byte
	for _, attr := range userAttr.Attributes {
		if attr.Name == "JPKI.AuthPub" {
			userAuthPub, _ = base64.StdEncoding.DecodeString(attr.Value)
			continue
		}
		if attr.Name == "JPKI.SignPub" {
			userSignPub, _ = base64.StdEncoding.DecodeString(attr.Value)
		}
	}

	if uReq.AuthPub != nil && bytes.Equal(uReq.AuthPub, userAuthPub) {
		pub = uReq.AuthPub
	}
	if uReq.SignPub != nil && bytes.Equal(uReq.SignPub, userSignPub) {
		pub = uReq.SignPub
	}
	if pub == nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}
	
	pubKey, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil {
		retErr = fmt.Errorf("unexpected public key")
		return
	}

	digest := sha256.Sum256(uReq.Digest)
	err = rsa.VerifyPKCS1v15(pubKey, 0/*crypto.SHA256*/, digest[:], uReq.Signature)
	if err != nil || uReq.Digest == nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	// authentication success
	secret := immclient.RandStr(8)
	_, err = adminID.ChangeSecret("", username, secret)
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	nowT := time.Now().UTC()
	enrollReq := &immclient.EnrollmentRequestNet{
		SignRequest: immclient.SignRequest{
			Request: string(uReq.CSR),
			NotBefore: nowT,
			NotAfter: nowT.Add(time.Hour).UTC(),
		},
	}
	
	cert, err := adminID.Client.(*caClient).enrollCAUser(username, secret, enrollReq)
	if err != nil {
		retErr = err
		return
	}

	jsonRsp := &jpkicli.EnrollJPKIUserReply{
		Cert: cert,
	}

	rsp, err = json.Marshal(jsonRsp)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a certificate: " + err.Error())
		return
	}
	
	return // success
}

func getJPKIUsername(caName string, req []byte) (rsp []byte, retErr error) {
	uReq := &jpkicli.GetJPKIUsernameRequest{}
	err := json.Unmarshal(req, uReq)
	if err != nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	var pub []byte
	if uReq.AuthPub != nil {
		pub = uReq.AuthPub
	} else if uReq.SignPub != nil {
		pub = uReq.SignPub
	}

	pubKey, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil || pub == nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	digest := sha256.Sum256(uReq.Digest)
	err = rsa.VerifyPKCS1v15(pubKey, 0/*crypto.SHA256*/, digest[:], uReq.Signature)
	if err != nil || uReq.Digest == nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	// authentication success
	adminID, err := getAdminJPKI(caName)
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	listIDs, err := adminID.GetAllIdentities("")
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	var tmpPub []byte
	for _, info := range listIDs {
		tmpPub = nil
		for _, attr := range info.Attributes {
			if attr.Name == "JPKI.AuthPub" {
				if uReq.AuthPub == nil {
					continue
				}
				
				tmpPub, _ = base64.StdEncoding.DecodeString(attr.Value)
				break
			}
			if attr.Name == "JPKI.SignPub" {
				if uReq.SignPub == nil {
					continue
				}

				tmpPub, _ = base64.StdEncoding.DecodeString(attr.Value)
				break
			}
		}

		if bytes.Equal(pub, tmpPub) {
			jsonRsp := &jpkicli.GetJPKIUsernameReply{
				Name: info.ID,
			}

			rsp, err = json.Marshal(jsonRsp)
			if err != nil {
				retErr = fmt.Errorf("failed to marhsal a username: " + err.Error())
				return
			}
			
			return // success
		}
	}

	retErr = fmt.Errorf("unknown user")
	return // failure
}

func randName(num int) string {
        availStr := []byte("abcdefghijklmnopqrstuvwxyz01234567")
        randStr := ""

        for i := 0; i < num; i++ {
                rand.Seed(time.Now().UnixNano())
                randStr += string(availStr[rand.Intn(len(availStr))])
        }

        return randStr
}

func verifyCertSignature(certAsn1, pub, hashState, certSign []byte, remainTBS func([]byte) ([]byte, error), certs [][]byte) (pubKey *rsa.PublicKey, retErr error) {
	var computedHash []byte
	var signature []byte
	var err error
	
	if certAsn1 != nil {
		cert, err := x509.ParseCertificate(certAsn1)
		if err != nil {
			retErr = fmt.Errorf("unexpected certificate")
			return
		}

		var ok bool
		pubKey, ok = cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			retErr = fmt.Errorf("unexpected public key")
			return
		}

		computedHash = hashTBS(nil, cert.RawTBSCertificate)
		signature = cert.Signature
	} else if pub != nil && hashState != nil && certSign != nil {
		pubKey, err = x509.ParsePKCS1PublicKey(pub)
		if err != nil {
			retErr = fmt.Errorf("unexpected public key")
			return
		}
		
		remain, _ := remainTBS(pub)
		computedHash = hashTBS(hashState, remain)
		signature = certSign
	}
	if signature == nil || computedHash == nil || pubKey == nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	err = verifySignature(computedHash, signature, certs)
	if err != nil {
		retErr = err
		return
	}

	return // success
}


func remainTBSForAuthCert(pubAsn1 []byte) (remain []byte, retErr error) {
	return remainTBSForSignCert(pubAsn1)
}

func remainTBSForSignCert(pubAsn1 []byte) (remain []byte, retErr error) {
	ski := sha1.Sum(pubAsn1)

	ext := pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 14},
	}

	var err error
	ext.Value, err = asn1.Marshal(ski[:])
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a SKI for an extension: %s", err)
		return
	}

	extAsn1, err := asn1.Marshal(ext)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a SKI: %s", err)
		return
	}
	remain = append(remain, extAsn1...)
	parseAsn1(remain)
	remain = remain[7:] // skip a tag, a length, and an OID (30 1d,  06 03 55 1d 0e)
	
	return
}

func parseAsn1(raw []byte) (retErr error) {
	//	var tag int64
	var offset int32 = 0
	var relativeOffset int32
	var length int32
	var isCompound bool
	var err error
	
	for {
		/*tag*/_, relativeOffset, length, isCompound, err = jpkicli.ParseTagAndLen(raw[offset:])
		if err != nil {
			retErr = fmt.Errorf("failed to parse a TBS certificate: %s", err)
			return
		}
		//fmt.Printf("tag=%02d length=%d\n", tag, length)
		if isCompound {
			offset += relativeOffset
			//fmt.Printf("compund: offset=%x\n", offset)
		} else {
			offset += relativeOffset + length
			//fmt.Printf("offset=%x\n", offset)
		}
		
		if int(offset) >= len(raw) {
			return
		}
	}
}

func hashTBS(hashState, remain []byte) (computedHash []byte) {
	h := sha256.New()
	if hashState != nil {
		h.(encoding.BinaryUnmarshaler).UnmarshalBinary(hashState)
	}
	h.Write(remain)
	computedHash = h.Sum(nil)
	return
}

func verifySignature(computedHash, signature []byte, caCerts [][]byte) error {
	for i, certAsn1 := range caCerts {
		cert, err := x509.ParseCertificate(certAsn1)
		if err != nil {
			return fmt.Errorf("unexpected CA certificate: %d", i)
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("unexpected CA public key: %d", i)
		}
	
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, computedHash, signature)
		if err == nil {
			return nil // success
		}
	}

	return fmt.Errorf("failed to verify a signature")
}

func debugDataJPKI(caName string, req[]byte) (rsp []byte, retErr error) {
	uReq := &jpkicli.DebugDataRequest{}
	err := json.Unmarshal(req, uReq)
	if err != nil {
		retErr = fmt.Errorf("unexpected request")
		return
	}

	fmt.Printf("debugData:\n%s\n", uReq.Data)
	jsonRsp := &jpkicli.DebugDataReply{}
	rsp, err = json.Marshal(jsonRsp)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal data: " + err.Error())
		return
	}

	return // success
}

func isValidCert(certAsn1 []byte) (notBefore, notAfter string, retErr error) {
	cert, err := x509.ParseCertificate(certAsn1)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate")
		return
	}

	now := time.Now()

	if now.Before(cert.NotBefore) {
		retErr = fmt.Errorf("current time %s is before %s", now.Format(time.RFC3339), cert.NotBefore.Format(time.RFC3339))
		return
	}

	if now.After(cert.NotAfter) {
		retErr = fmt.Errorf("current time %s is after %s", now.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		return
	}

	notBeforeRaw, err := cert.NotBefore.MarshalText()
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate: %s\n", err)
		return
	}
	notBefore = string(notBeforeRaw)

	notAfterRaw, err := cert.NotAfter.MarshalText()
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate: %s\n", err)
		return
	}
	notAfter = string(notAfterRaw)
	
	return // success
}

var fullNameOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x01})// 1.2.392.200149.8.5.5.1
var	birthdayOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x04})// 1.2.392.200149.8.5.5.4
var	genderOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x03})// 1.2.392.200149.8.5.5.3
var	addressOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x05})// 1.2.392.200149.8.5.5.5
var	altChInNameOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x02})// 1.2.392.200149.8.5.5.2
var	altChInAddrOidStr = string([]byte{0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x06})// 1.2.392.200149.8.5.5.6

func getSignCertAttr(certAsn1 []byte) (attrs []immclient.Attribute, retErr error) {
	cert, err := x509.ParseCertificate(certAsn1)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate")
		return
	}

	vals, err := getAltNames(cert.RawTBSCertificate)
	if err != nil {
		retErr = err
		return
	}

	if len(vals) != 6 {
		retErr = fmt.Errorf("unexpected subject alternative name certificate")
		return
	}

	attrs = append(attrs, immclient.Attribute{Name: "JPKI.FullName", Value: string(vals[fullNameOidStr]), ECert: false})
	attrs = append(attrs, immclient.Attribute{Name: "JPKI.Brithday", Value: string(vals[birthdayOidStr]), ECert: false})
	attrs = append(attrs, immclient.Attribute{Name: "JPKI.Gender", Value: string(vals[genderOidStr]), ECert: false})
	attrs = append(attrs, immclient.Attribute{Name: "JPKI.Address", Value: string(vals[addressOidStr]), ECert: false})
	attrs = append(attrs, immclient.Attribute{Name: "JPKI.AltChInName", Value: string(vals[altChInNameOidStr]), ECert: false})
	attrs = append(attrs, immclient.Attribute{Name: "JPKI.AltChInAddr", Value: string(vals[altChInAddrOidStr]), ECert: false})
	return // success
}

func getAltNames(raw []byte) (values map[string] []byte, retErr error) {
	subjAltNameOidStr := string([]byte{0x55, 0x1d, 0x11}) // 2.5.29.17
	val, err := getOidValues(raw, []string{subjAltNameOidStr})
	if err != nil {
		retErr = fmt.Errorf("not found subject alternative name: %s", err)
		return
	}

	values, err = getOidValues(val[subjAltNameOidStr],
		[]string{fullNameOidStr, birthdayOidStr, genderOidStr, addressOidStr, altChInNameOidStr, altChInAddrOidStr})
	if err != nil {
		retErr = fmt.Errorf("failed to parse alternative names: %s", err)
		return
	}

	return // success
}



func getOidValues(raw []byte, oids []string) (values map[string] []byte, retErr error) {
	values = make(map[string] []byte)
	
	var tag int64
	var offset int32 = 0
	var relativeOffset int32
	var length int32
	var isCompound bool
	var err error
	structLen := int32(0)
	valueStr := ""

	oidn := 1
	for {
		tag, relativeOffset, length, isCompound, err = jpkicli.ParseTagAndLen(raw[offset:])
		if err != nil {
			retErr = fmt.Errorf("failed to parse a TBS certificate: %s", err)
			return
		}

		if tag == asn1.TagOID /*6*/ {
			value := raw[offset+relativeOffset:]
			value = value[:length]
			valueStr = string(value)
			oidn++

			for readLen := (relativeOffset+length); readLen < structLen; readLen +=  relativeOffset + length {
				offset += relativeOffset + length
				
				tag, relativeOffset, length, isCompound, err = jpkicli.ParseTagAndLen(raw[offset:])
				if err != nil {
					retErr = fmt.Errorf("failed to parse an extension structure: %s", err)
					return
				}

				if tag == asn1.TagOctetString /* 4 */ || tag == asn1.TagUTF8String /* 12 */ {
					value = raw[offset+relativeOffset:]
					value = value[:length]
					for _, oidStr := range oids {
						if valueStr == oidStr {
							values[oidStr] = value
							break
						}
					}
				}
			}
		}

		if tag == asn1.TagOctetString /* 4 */ || tag == asn1.TagUTF8String /* 12 */ {
			value := raw[offset+relativeOffset:]
			value = value[:length]
			for _, oidStr := range oids {
				if valueStr == oidStr {
					values[oidStr] = value
					break
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
			return
		}
	}

	return	
}
