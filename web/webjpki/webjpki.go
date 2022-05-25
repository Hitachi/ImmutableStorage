/*
Copyright Hitachi, Ltd. 2022 All Rights Reserved.

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

package webjpki

import (
	"syscall/js"

	"immclient"
	"websto"
	"jpkicli"
	wu "webutil"
)

const (
	webAppNfcObj = "webAppNfc"
)

func GetWebAppNfc() (webAppNfc js.Value, retErr string) {
	gl := js.Global()
	webAppNfc = gl.Get(webAppNfcObj)
	if webAppNfc.Type() != js.TypeObject {
		retErr = "The NFC function is not found"
		return
	}

	isJPKIF := webAppNfc.Call("isJPKI")
	if isJPKIF.Bool() == false {
		retErr = "This card is not JPKI card"
		return
	}

	return // success
}

func IsAvailable() bool {
	_, err := GetWebAppNfc()
	return (err == "")
}

type SignCertImp struct{}
func (si *SignCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("signData", pin, digest).String()
}
func (si *SignCertImp) GetCert(pin string) (certJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("readSignCert", pin).String()
}

type AuthCertImp struct{}
func (si *AuthCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)	
	return webAppNfc.Call("signDataUsingAuthKey", pin, digest).String()
}
func (si *AuthCertImp) GetCert(pin string) (certJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)	
	return webAppNfc.Call("readAuthCert").String()
}

var gRegUser *jpkicli.RegisterJPKIUserRequest

var GetAuthCertPIN func() string = func() string {
	return ""
}
var GetSignCertPIN func() string = func() string {
	return ""
}

func ExportAuthCert(privacyType string) string {
	pin := GetAuthCertPIN()
	if pin == "" {
		return "The specified PIN is empty"
	}

	rsp, err := jpkicli.GenerateSignature(&AuthCertImp{}, pin)
	if err != nil {
		return err.Error()
	}

	gRegUser = &jpkicli.RegisterJPKIUserRequest{}
	gRegUser.AuthDigest = rsp.Digest
	gRegUser.AuthSignature = rsp.Signature

	if privacyType == jpkicli.PrivTypeAuthCert || privacyType == jpkicli.PrivTypeSignCert {
		gRegUser.AuthCert = rsp.CertAsn1
		return "" // success
	}

	// privacyType == "publicKey"
	gRegUser.AuthPub = rsp.PubAsn1
	gRegUser.AuthCertSign = rsp.Cert.Signature
	gRegUser.AuthHashState, err = jpkicli.GetHashStateUntilSKI(rsp.Cert)
	if err != nil {
		return err.Error()
	}
	
	return "" // success	
}

func ExportAuthCertOK(in []js.Value) string {
	return ExportAuthCert(jpkicli.PrivTypeAuthCert)
}

func exportSignCertWithType(privacyType, regGroupName string) (rsp *jpkicli.GenerateSignatureRsp, retErr string) {
	pin := GetSignCertPIN()
	if pin == "" {
		retErr = "The specified PIN is empty"
		return
	}

	if gRegUser == nil {
		retErr = "unexpected state"
		return
	}

	var err error
	rsp, err = jpkicli.GenerateSignature(&SignCertImp{}, pin)
	if err != nil {
		retErr = err.Error()
		return
	}

	gRegUser.SignDigest = rsp.Digest
	gRegUser.SignSignature = rsp.Signature
	gRegUser.GroupName = regGroupName	

	if  privacyType == jpkicli.PrivTypeSignCert {
		gRegUser.SignCert = rsp.CertAsn1
		return // success
	}

	// privacyType == "publicKey" || privacyType == "authCert"
	gRegUser.SignPub = rsp.PubAsn1
	gRegUser.SignCertSign = rsp.Cert.Signature
	gRegUser.SignHashState, err = jpkicli.GetHashStateUntilSKI(rsp.Cert)
	if err != nil {
		retErr =  err.Error()
		return
	}

	return // success
}

func ExportSignCertOK(in []js.Value, regGroupName string) string {
	url := wu.GetImmsrvURL()
	
	rsp, errStr := exportSignCertWithType(jpkicli.PrivTypeSignCert, regGroupName)
	if errStr != "" {
		return errStr
	}
	
	username, err := jpkicli.RegisterJPKIUser(url, gRegUser)
	if err != nil {
		return err.Error()
	}

	enrollReq := &jpkicli.EnrollJPKIUserRequest{
		Digest: rsp.Digest,
		Signature: rsp.Signature,
		SignPub: rsp.PubAsn1,
	}
	privPem, certPem, err := jpkicli.EnrollJPKIUser(url, username, enrollReq)
	if err != nil {
		return err.Error()
	}

	id := &immclient.UserID{Name: username, Priv: privPem, Cert: certPem, }
	websto.StoreKeyPair(username, id)
	websto.SetCurrentUsername(id.Name)
	return "" // success	
}

func ExportSignCert(privacyType, regGroupName string) (username, retErr string) {
	_, retErr = exportSignCertWithType(privacyType, regGroupName)
	if retErr != "" {
		return
	}

	url := wu.GetImmsrvURL()
	var err error
	username, err = jpkicli.RegisterJPKIUser(url, gRegUser)
	if err != nil {
		retErr = err.Error()
		return
	}

	return // success	
}
