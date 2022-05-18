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

func getWebAppNfc() (webAppNfc js.Value, retErr string) {
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
	_, err := getWebAppNfc()
	return (err == "")
}

type signCertImp struct{}
func (si *signCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("signData", pin, digest).String()
}
func (si *signCertImp) GetCert(pin string) (certJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("readSignCert", pin).String()
}

type authCertImp struct{}
func (si *authCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)	
	return webAppNfc.Call("signDataUsingAuthKey", pin, digest).String()
}
func (si *authCertImp) GetCert(pin string) (certJson string) {
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

func ExportAuthCertOK(in []js.Value) string {
	pin := GetAuthCertPIN()
	if pin == "" {
		return "The specified PIN is empty"
	}

	rsp, err := jpkicli.GenerateSignature(&authCertImp{}, pin)
	if err != nil {
		return err.Error()
	}

	gRegUser = &jpkicli.RegisterJPKIUserRequest{}
	gRegUser.AuthDigest = rsp.Digest
	gRegUser.AuthSignature = rsp.Signature
	gRegUser.AuthCert = rsp.CertAsn1
	return "" // success
}

func ExportSignCertOK(in []js.Value, regGroupName string) string {
	url := wu.GetImmsrvURL()

	pin := GetSignCertPIN()
	if pin == "" {
		return "The specified PIN is empty"
	}

	if gRegUser == nil {
		return "unexpected state"
	}

	rsp, err := jpkicli.GenerateSignature(&signCertImp{}, pin)
	if err != nil {
		return err.Error()
	}

	gRegUser.SignDigest = rsp.Digest
	gRegUser.SignSignature = rsp.Signature
	gRegUser.SignCert = rsp.CertAsn1
	gRegUser.GroupName = regGroupName

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
