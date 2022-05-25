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
	"syscall/js"
	"encoding/json"
	"encoding/base64"

	"immclient"
	"jpkicli"

	wu "webutil"
	"webjpki"

	//"encoding/hex"
)

const (
	webAppNfcObj = "webAppNfc"
)

func main() {
	ch := make(chan struct{}, 0)
	registerCallback()
	makeContent()
	<- ch
}

func registerCallback() {
	gl := js.Global()
	gl.Set("registerJPKIUser", js.FuncOf(registerJPKIUser))
	gl.Set("enterSignPIN", js.FuncOf(enterSignPIN))
	gl.Set("reregisterJPKIUser", js.FuncOf(reregisterJPKIUser))
	gl.Set("recordLedger", js.FuncOf(recordLedger))	

	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
	wu.AppendReqBox("exportAuthCert", exportAuthCertOK, nil)
	wu.AppendReqBox("exportSignCert", exportSignCertOK, nil)
	
	wu.AppendReqBox("enterSignPIN", enterSignPINOK, nil)
	wu.AppendReqBox("enterAuthPIN", enterAuthPINOK, nil)
}

func makeContent() {
	go func() {
		_, errStr := webjpki.GetWebAppNfc()
		if errStr != "" {
			wu.VisibleSimpleMsgBox(errStr)
			return
		}

		name := getRegisteredUsername()
		if name == "" {
			makeRegisterJPKIUserContent()
			return
		}

		makeEnterSignPINContent()
		return
	}()
}

func makeRegisterJPKIUserContent() {
	doc := js.Global().Get("document")
	html := `
      <div class="immDSBtn">
        <button onclick="registerJPKIUser()" id="registerJPKIUserBtn">Register my ID</button>
      </div>`
	nfcContent := doc.Call("getElementById", "nfcContent")
	nfcContent.Set("innerHTML", html)
}

func makeRegisterJPKIUserContentAndClick() {
	doc := js.Global().Get("document")
	makeRegisterJPKIUserContent()
	registerBtn := doc.Call("getElementById", "registerJPKIUserBtn")
	registerBtn.Call("click")
}

func makeEnterSignPINContent() {
	doc := js.Global().Get("document")
	html := `
      <div class="immDSBtn">
        <button onclick="enterSignPIN()" id="enterSignPINBtn">Enter your PIN to sign a message</button>
      </div>
      <div class="immDSBtn">
        <button onclick="reregisterJPKIUser()" id="reregisterJPKIUserBtn">Reregister my ID</button>
      </div>`
	nfcContent := doc.Call("getElementById", "nfcContent")
	nfcContent.Set("innerHTML", html)
}

func registerJPKIUser(this js.Value, in []js.Value) interface{}{
	url := wu.GetImmsrvURL()
	
	go func() {
		privacyType, err := jpkicli.GetRequiredPrivInfo(url)
		if err != nil {
			wu.VisibleMsgBox(err.Error())
			return
		}
		
		makeExportAuthCertBoxContent(privacyType)
	}()

	return nil
}

func makeExportAuthCertBoxContent(privacyType string) {
	header := `  <label>You will send a pubilc key and a signature in your certificate for authentication. These data will be authenticated by Immutable Server. Please enter your PIN.</label>`
	if privacyType == jpkicli.PrivTypeAuthCert || privacyType == jpkicli.PrivTypeSignCert {
		header = `  <label>You will send your certificate for authentication. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}
	header += `  <input type="number" id="authPIN">`
	
	webjpki.GetAuthCertPIN = func() string {
		doc := js.Global().Get("document")
		return doc.Call("getElementById", "authPIN").Get("value").String()
	}	
	
	footer := `  <input id="privacyType" type="hidden" value="` + privacyType + `">`
	wu.MakeReqBox("exportAuthCert", header, footer, true, true)
}

func exportAuthCertOK(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	privacyType := doc.Call("getElementById", "privacyType").Get("value").String()
	errMsg := webjpki.ExportAuthCert(privacyType)
	if errMsg != "" {
		wu.VisibleMsgBox(errMsg)
		return
	}

	makeExportSignCertBoxContent(privacyType)
	return
}

func makeExportSignCertBoxContent(privacyType string) {
	header := `  <label>You will send a pubilc key and a signature in your certificate for signature. These data will be authenticated by Immutable Server. Please enter your PIN.</label>`
	if privacyType == jpkicli.PrivTypeSignCert {
		header = `  <label>You will send your certificate for signature. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}
	header += `  <input type="text" id="signPIN">`
	
	webjpki.GetSignCertPIN = func() string {
		doc := js.Global().Get("document")
		return doc.Call("getElementById", "signPIN").Get("value").String()
	}	

	footer := `  <input id="privacyType" type="hidden" value="` + privacyType + `">`
	wu.MakeReqBox("exportSignCert", header, footer, true, true)
}

func exportSignCertOK(in []js.Value) {
	doc := js.Global().Get("document")
	privacyType := doc.Call("getElementById", "privacyType").Get("value").String()

	username, errMsg := webjpki.ExportSignCert(privacyType, "")
	if errMsg != "" {
		wu.VisibleMsgBox(errMsg)
		return
	}
	
	setRegisteredUsername(username)
	makeEnterSignPINContent()
	
	wu.CloseReqBox(nil)
	return // success
}

func reregisterJPKIUser(this js.Value, in []js.Value) interface{}{
	setRegisteredUsername("") // clear cached username

	header := `  <label>Please enter your PIN to authenticate you.</label>`
	header += `  <input type="number" id="authPIN">`
	wu.MakeReqBox("enterAuthPIN", header, "", true, true)
	return nil
}

func enterAuthPINOK(in []js.Value) {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "authPIN").Get("value").String()
	if pin == "" {
		return // ignore
	}
	
	rsp, err := jpkicli.GenerateSignature(&webjpki.AuthCertImp{}, pin)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}

	signStr := &jpkicli.GetJPKIUsernameRequest{
		Digest: rsp.Digest,
		Signature: rsp.Signature,
		AuthPub: rsp.PubAsn1,
	}
	username, err := jpkicli.GetJPKIUsername(url, signStr)
	if err != nil {
		makeRegisterJPKIUserContentAndClick()
		return
	}

	setRegisteredUsername(username)
	wu.VisibleMsgBox("Success")
	return
}

func getRegisteredUsername() string {
	gl := js.Global()
	storage := gl.Get("localStorage")

	nameStorage := storage.Call("getItem", "registeredUsername")
	if nameStorage.IsNull() {
		return "" // not found
	}

	return nameStorage.String()
}

func setRegisteredUsername(name string) {
	gl := js.Global()
	storage := gl.Get("localStorage")
	storage.Call("setItem", "registeredUsername", name)
}

var cacheUser struct{
	id *immclient.UserID
	pin string
}

func enterSignPIN(this js.Value, in []js.Value) interface{}{
	header := `  <label>Please enter your PIN to sign a message.</label>`
	header += `  <input type="text" id="signPIN">`
	wu.MakeReqBox("enterSignPIN", header, "", true, true)
	return nil
}

func enterSignPINOK(in []js.Value) {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "signPIN").Get("value").String()
	if pin == "" {
		return // ignore
	}

	rsp, err := jpkicli.GenerateSignature(&webjpki.SignCertImp{}, pin)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}

	username := getRegisteredUsername()
	userReq := &jpkicli.EnrollJPKIUserRequest{
		Digest: rsp.Digest,
		Signature: rsp.Signature,
		SignPub: rsp.PubAsn1,
	}
	privPem, certPem, err := jpkicli.EnrollJPKIUser(url, username, userReq)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}

	id := &immclient.UserID{Name: username, Priv: privPem, Cert: certPem, }
	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}
	if len(storageGrpList) < 1 {
		wu.VisibleMsgBox("There is no stroage in the server.")
		return
	}

	cacheUser.id = id
	cacheUser.pin = pin

	html := `<div class="cert-area">`
	html += `<div class="row">`
	
	html += `  <div class="cert-item"><label for="storageGrp">Storage group</label></div>`
	html += `  <div class="cert-input">`
	html += `    <select id="recordStorageGrp">`
	for _, storageGrp := range storageGrpList {
		html += `      <option value="`+storageGrp+`">`+storageGrp+`</option>`
	}
	html += `    </select>`
	html += `  </div>`
	html += `</div>`
	
	html += `<div class="row">`
	html += `  <div class="cert-item"><label>Ledger</label></div>`
	html += `  <div class="cert-input"><input type="text" id="recordLedgerText"></div>`
	html += `    <div class="immDSBtn">`
	html += `      <button onclick="recordLedger(event)" id="recordLedgerBtn">Record</button>`
	html += "    </div>"
	html += `</div>`
		
	html += `</div>`

	nfcContent := doc.Call("getElementById", "nfcContent")
	nfcContent.Set("innerHTML", html)
	wu.CloseReqBox(in)
	return
}

func recordLedger(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		if cacheUser.id == nil {
			wu.VisibleMsgBox("The specified storage is not ready.")
			return
		}

		recordLogText := doc.Call("getElementById", "recordLedgerText").Get("value").String()
		if recordLogText == "" {
			wu.VisibleMsgBox("empty text")
			return
		}

		signedText, err := jpkicli.SignData(&webjpki.SignCertImp{}, cacheUser.pin, recordLogText)
		if err != nil {
			wu.VisibleMsgBox("JPKI error: " + err.Error())
			return
		}

		rec := &jpkicli.JPKIRecord{
			Digest: recordLogText,
			Signature: base64.StdEncoding.EncodeToString(signedText),
		}
		recJson, err := json.Marshal(rec)
		if err != nil {
			wu.VisibleMsgBox("unexpected input: " + err.Error())
			return
		}

		err = cacheUser.id.RecordLedger(storageGrp, "jpki", string(recJson), url)
		if err != nil {
			wu.VisibleMsgBox("failed to record ledger: " + err.Error())
			return
		}
		wu.VisibleMsgBox("Success")
		return
	}()

	return nil
}
