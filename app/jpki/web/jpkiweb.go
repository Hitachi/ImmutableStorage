package main

import (
	"syscall/js"
	"encoding/json"
	"encoding/base64"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"errors"
	"time"

	"immclient"
	"jpkicli"

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

type jsonCert struct {
	Cert string `json:"cert"`
	Err string `json:"err"`
}

type jsonSignature struct {
	Signature string `json:"signature"`
	Err string `json:"err"`
}

func registerCallback() {
	gl := js.Global()
	gl.Set("registerJPKIUser", js.FuncOf(registerJPKIUser))
	gl.Set("enterSignPIN", js.FuncOf(enterSignPIN))
	gl.Set("reregisterJPKIUser", js.FuncOf(reregisterJPKIUser))
	gl.Set("reqBoxOk", js.FuncOf(reqBoxOk))
	gl.Set("reqBoxCancel", js.FuncOf(reqBoxCancel))
	gl.Set("recordLedger", js.FuncOf(recordLedger))
}

func makeContent() {
	gl := js.Global()
	doc := js.Global().Get("document")

	go func() {
		var visibleErrMsg = func(msg string) {
			nfcContent := doc.Call("getElementById", "nfcContent")
			nfcContent.Set("innerHTML", msg)
		}

		webAppNfc := gl.Get(webAppNfcObj)
		if webAppNfc.Type() != js.TypeObject {
			visibleErrMsg("The NFC function is not found")
			return
		}

		isJPKIF := webAppNfc.Call("isJPKI")
		if isJPKIF.Bool() == false {
			visibleErrMsg("This card is not JPKI card")
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
        <button onclick="enterSignPIN()" id="enterSignPinBtn">Enter your PIN to sign a message</button>
      </div>
      <div class="immDSBtn">
        <button onclick="reregisterJPKIUser()" id="reregisterJPKIUserBtn">Reregister my ID</button>
      </div>`
	nfcContent := doc.Call("getElementById", "nfcContent")
	nfcContent.Set("innerHTML", html)
}

func getImmsrvURL() string {
	loc := js.Global().Get("location")
	return loc.Get("protocol").String() + "//" + loc.Get("host").String()+"/immsrv"
}

func registerJPKIUser(this js.Value, in []js.Value) interface{}{
	url := getImmsrvURL()
	
	go func() {
		privacyType, err := jpkicli.GetRequiredPrivInfo(url)
		if err != nil {
			makeErrorMsgBoxContent(err.Error())
			return
		}
		
		makeExportAuthCertBoxContent(privacyType)
	}()

	return nil
}

func makeErrorMsgBoxContent(msg string) {
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	html += `  <label>` + msg + `</label>`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxCancel(event, 'errorMsg')" id="reqBoxCancelBtn">Ok</button>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")			
}

func makeExportAuthCertBoxContent(privacyType string) {
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	if privacyType == jpkicli.PrivTypeAuthCert || privacyType == jpkicli.PrivTypeSignCert {
		html += `  <label>You will send your certificate for authentication. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}else {
		html += `  <label>You will send a pubilc key and a signature in your certificate for authentication. These data will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}
	html += `  <input type="number" id="authPIN">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'exportAuthCert')" id="reqBoxOkBtn" name="` + privacyType + `">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'exportAuthCert')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="exportAuthCertResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")		
}

var gRegUser *jpkicli.RegisterJPKIUserRequest

func exportAuthCertOk(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	target := in[0].Get("target")
	privacyType := target.Get("name").String()

	pin := doc.Call("getElementById", "authPIN").Get("value").String()
	if pin == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "exportAuthCertResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}

	rsp, err := genSignatureUsingAuthCert(pin)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	gRegUser = &jpkicli.RegisterJPKIUserRequest{}
	gRegUser.AuthDigest = rsp.Digest
	gRegUser.AuthSignature = rsp.Signature

	if privacyType == jpkicli.PrivTypeAuthCert || privacyType == jpkicli.PrivTypeSignCert {
		gRegUser.AuthCert = rsp.CertAsn1
		closeReqBox(nil)
		makeExportSignCertBoxContent(privacyType)
		return
	}

	// privacyType == "publicKey"
	gRegUser.AuthPub = rsp.PubAsn1
	gRegUser.AuthCertSign = rsp.Cert.Signature
	gRegUser.AuthHashState, err = jpkicli.GetHashStateUntilSKI(rsp.Cert)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}
	
	closeReqBox(nil)
	makeExportSignCertBoxContent(privacyType)
	return
}

func makeExportSignCertBoxContent(privacyType string) {
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	if privacyType == jpkicli.PrivTypeSignCert {
		html += `  <label>You will send your certificate for signature. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}else {
		html += `  <label>You will send a pubilc key and a signature in your certificate for signature. These data will be authenticated by Immutable Server. Please enter your PIN.</label>`
	}
	html += `  <input type="text" id="signPin">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'exportSignCert')" id="reqBoxOkBtn" name="` + privacyType + `">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'exportSignCert')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="exportSignCertResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")			
}

func exportSignCertOk(in []js.Value) {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	target := in[0].Get("target")
	privacyType := target.Get("name").String()

	pin := doc.Call("getElementById", "signPin").Get("value").String()
	if pin == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "exportSignCertResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}

	if gRegUser == nil {
		visibleErrMsg("unexpected state")
		return
	}

	rsp, err := genSignSignature(pin)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}
	gRegUser.SignDigest = rsp.Digest
	gRegUser.SignSignature = rsp.Signature

	var registerUser = func() {
		username, err2 := jpkicli.RegisterJPKIUser(url, gRegUser)
		if err2 != nil {
			visibleErrMsg(err2.Error())
			return
		}

		setRegisteredUsername(username)
		closeReqBox(nil)

		makeEnterSignPINContent()
		return // success
	}
	
	if  privacyType == jpkicli.PrivTypeSignCert {
		gRegUser.SignCert = rsp.CertAsn1
		registerUser()
		return
	}
	
	// privacyType == "publicKey" || privacyType == "authCert"
	gRegUser.SignPub = rsp.PubAsn1
	gRegUser.SignCertSign = rsp.Cert.Signature
	gRegUser.SignHashState, err = jpkicli.GetHashStateUntilSKI(rsp.Cert)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	registerUser()
	return
}

func reregisterJPKIUser(this js.Value, in []js.Value) interface{}{
	setRegisteredUsername("") // clear cached username

	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	html += `  <label>Please enter your PIN to authenticate you.</label>`
	html += `  <input type="number" id="authPIN">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'enterAuthPIN')" id="reqBoxOkBtn">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'enterAuthPIN')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="enterAuthPINResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")

	return nil
}

func enterAuthPINOk(in []js.Value) {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "authPIN").Get("value").String()
	if pin == "" {
		return // ignore
	}
	
	result := doc.Call("getElementById", "enterAuthPINResult")

	rsp, err := genSignatureUsingAuthCert(pin)
	if err != nil {
		result.Set("innerHTML", err.Error())
		return
	}

	signStr := &jpkicli.GetJPKIUsernameRequest{
		Digest: rsp.Digest,
		Signature: rsp.Signature,
		AuthPub: rsp.PubAsn1,
	}
	username, err := jpkicli.GetJPKIUsername(url, signStr)
	closeReqBox(nil)
	if err != nil {
		makeRegisterJPKIUserContentAndClick()
		return
	}

	setRegisteredUsername(username)
	result.Set("innerHTML", "Success")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	okBtn.Set("hidden", false)
	return
}

func reqBoxAction(in []js.Value, funcSuffix string) interface{} {
	if len(in) != 2 {
		return nil
	}
	reqStr := in[1].String() + funcSuffix

	reqFunc, ok := reqBoxFunc[reqStr]
	if !ok {
		return nil
	}

	go reqFunc(in)
	return nil
}

var reqBoxFunc = map[string] func([]js.Value){
	"exportAuthCertOk": exportAuthCertOk,
	"exportAuthCertCancel": closeReqBox,
	"exportSignCertOk": exportSignCertOk,
	"exportSignCertCancel": closeReqBox,
	"enterSignPINOk": enterSignPINOk,
	"enterSignPINCancel": closeReqBox,
	"errorMsgCancel": closeReqBox,
	"enterAuthPINOk": enterAuthPINOk,
	"enterAuthPINCancel": closeReqBox,
}

func closeReqBox(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "none")	
}

func reqBoxOk(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "Ok")
}

func reqBoxCancel(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "Cancel")
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

type GenSignSignatureRsp struct {
	Digest []byte
	Signature []byte
	PubAsn1 []byte
	CertAsn1 []byte
	Cert *x509.Certificate
}

func signDataWithSignFunc(signFuncName, pin, digest string) (signature []byte, retErr error) {
	gl := js.Global()
	webAppNfc := gl.Get(webAppNfcObj)

	signatureObj := webAppNfc.Call(signFuncName, pin, digest)
	jSign := &jsonSignature{}
	err := json.Unmarshal([]byte(signatureObj.String()), jSign)
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

type signInf interface {
	SignData(pin, digest string) (signature []byte, retErr error)
	GetCert(pin string) (cert js.Value)
}

func genSignSignatureInf(si signInf, pin string) (rsp *GenSignSignatureRsp, retErr error) {
	rsp = &GenSignSignatureRsp{}
	
	var err error
	rsp.Digest, err = time.Now().MarshalBinary()
	if err != nil {
		retErr = errors.New("failed to get current time: " + err.Error())
		return
	}

	hashVal := sha256.Sum256(rsp.Digest)
	digest := base64.StdEncoding.EncodeToString(hashVal[:])
	rsp.Signature, retErr = si.SignData(pin, digest)
	if retErr != nil {
		return
	}

	signCertRaw := si.GetCert(pin)
	jCert := &jsonCert{}
	err = json.Unmarshal([]byte(signCertRaw.String()), jCert)
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

type signCertImp struct{}
func (si *signCertImp) SignData(pin, digest string) (signature []byte, retErr error) {
	return signDataWithSignFunc("signData", pin, digest)
}

func (si *signCertImp) GetCert(pin string) (cert js.Value) {
	gl := js.Global()
	webAppNfc := gl.Get(webAppNfcObj)
	return webAppNfc.Call("readSignCert", pin)
}

func genSignSignature(pin string) (rsp *GenSignSignatureRsp, retErr error) {
	return genSignSignatureInf(&signCertImp{}, pin)
}

type authCertImp struct{}
func (si *authCertImp) SignData(pin, digest string) (signature []byte, retErr error) {
	return signDataWithSignFunc("signDataUsingAuthKey", pin, digest)
}

func (si *authCertImp) GetCert(pin string) (cert js.Value) {
	gl := js.Global()
	webAppNfc := gl.Get(webAppNfcObj)
	return webAppNfc.Call("readAuthCert")
}

func genSignatureUsingAuthCert(pin string) (rsp *GenSignSignatureRsp, retErr error) {
	return genSignSignatureInf(&authCertImp{}, pin)
}


func enterSignPIN(this js.Value, in []js.Value) interface{}{
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	html += `  <label>Please enter your PIN to sign a message.</label>`
	html += `  <input type="text" id="signPin">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'enterSignPIN')" id="reqBoxOkBtn">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'enterSignPIN')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="enterSignPINResult"></p>`
	html += `  </div>`
	html += `</div>`
		
	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")

	return nil
}

func enterSignPINOk(in []js.Value) {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "signPin").Get("value").String()
	if pin == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "enterSignPINResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}

	rsp, err := genSignSignature(pin)
	if err != nil {
		result.Set("innerHTML", err.Error())
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
		visibleErrMsg(err.Error())
		return
	}

	id := &immclient.UserID{Name: username, Priv: privPem, Cert: certPem, }
	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}
	if len(storageGrpList) < 1 {
		visibleErrMsg("There is no stroage in the server.")
		return
	}

	cacheUser.id = id
	cacheUser.pin = pin

	closeReqBox(nil)
	nfcContent := doc.Call("getElementById", "nfcContent")
	nfcContent.Set("innerHTML", "") // clear
	
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
	html += `      <p id="recordLedgerResult"></p>`
	html += "    </div>"
	html += `</div>`
		
	html += `</div>`

	nfcContent.Set("innerHTML", html)
	return
}

func recordLedger(this js.Value, in []js.Value) interface{} {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	result := doc.Call("getElementById", "recordLedgerResult")
	var visibleResult = func(msg string) {
		result.Set("innerHTML", msg)
	}
		
	go func() {
		if cacheUser.id == nil {
			visibleResult("The specified storage is not ready.")
			return
		}

		recordLogText := doc.Call("getElementById", "recordLedgerText").Get("value").String()
		if recordLogText == "" {
			visibleResult("empty text")
			return
		}

		signedText, err := (&signCertImp{}).SignData(cacheUser.pin, recordLogText)
		if err != nil {
			visibleResult("JPKI error: " + err.Error())
			return
		}

		rec := &jpkicli.JPKIRecord{
			Digest: recordLogText,
			Signature: base64.StdEncoding.EncodeToString(signedText),
		}
		recJson, err := json.Marshal(rec)
		if err != nil {
			visibleResult("unexpected input: " + err.Error())
			return
		}

		err = cacheUser.id.RecordLedger(storageGrp, "jpki", string(recJson), url)
		if err != nil {
			visibleResult("failed to record ledger: " + err.Error())
			return
		}
		visibleResult("Success")
		return
	}()

	return nil
}
