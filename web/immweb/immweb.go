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

package immweb

import (
	"strings"
	"strconv"
	"syscall/js"
	"sync/atomic"
	"encoding/json"
	"time"
	"errors"
	"google.golang.org/protobuf/proto"
	
	"immclient"
	"immop"
	"websto"
	wu "webutil"
	"webcli"
	"immadmin"
)

func RegisterCallback() {
	gl := js.Global()
	gl.Set("enroll", js.FuncOf(enroll))
	gl.Set("selectedUserType", js.FuncOf(selectedUserType))
	gl.Set("inputtedRegisterName", js.FuncOf(inputtedRegisterName))
	gl.Set("selectedAuthType", js.FuncOf(selectedAuthType))
	gl.Set("register", js.FuncOf(register))
	gl.Set("switchUser", js.FuncOf(switchUser))
	gl.Set("exportService", js.FuncOf(exportService))
	gl.Set("addAnchorPeer", js.FuncOf(addAnchorPeer))
	gl.Set("removeService", js.FuncOf(removeService))
	gl.Set("joinChannel", js.FuncOf(joinChannel))
	gl.Set("exportChannel", js.FuncOf(exportChannel))
	gl.Set("enableChannel", js.FuncOf(enableChannel))
	gl.Set("dropdownIDFunc", js.FuncOf(dropdownIDFunc))
	gl.Set("removeID", js.FuncOf(removeID))
	gl.Set("revokeID", js.FuncOf(revokeID))
	gl.Set("dismiss", js.FuncOf(dismiss))
	gl.Set("enableEnrollment", js.FuncOf(enableEnrollment))
	gl.Set("disableEnrollment", js.FuncOf(disableEnrollment))
	gl.Set("onOffEnrollment", js.FuncOf(onOffEnrollment))
	gl.Set("changeSecret", js.FuncOf(changeSecret))
	gl.Set("exportKey", js.FuncOf(exportKey))
	gl.Set("encryptKey", js.FuncOf(encryptKey))
	gl.Set("setPermGrpMember", js.FuncOf(setPermGrpMember))

	wu.InitTab("openTab")
	wu.RegisterTab("enroll", updateEnrollContent)
	wu.RegisterTab("user", updateUserContent)
	wu.RegisterTab("switchUser", updateSwitchUserContent)	

	wu.RegisterTab("register", updateRegisterContent)	
	wu.RegisterTab("listUser",  updateListUserContent)
	wu.RegisterTab("keyManage", updateKeyManageContent)
	wu.RegisterTab("action", updateActionContent)
	wu.RegisterTab("listApps", updateListAppsContent)
	wu.RegisterTab("storageSvc", updateStorageSvcContent)
	wu.RegisterTab("storageGrp", updateStorageGrpContent)

	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
	wu.AppendReqBox("encrypt", encryptOk, nil)
	wu.AppendReqBox("decrypt", decryptOk, decryptCancel)
	wu.AppendReqBox("removeId", removeIdOk, nil)
	wu.AppendReqBox("revokeId", revokeIdOk, nil)
	wu.AppendReqBox("changeSecret", changeSecretOk, nil)
}

func isCurIdEncrypted() bool {
	_, err := websto.GetCurrentID()
	if err == nil {
		return false
	}

	return err.Error() == websto.ERR_ENCRYPTED_KEY
}

func getCurrentIdWithDecryptingKey() (*immclient.UserID, error) {
	id, err := websto.GetCurrentID()
	if err == nil {
		return id, nil
	}

	if err.Error() != websto.ERR_ENCRYPTED_KEY {
		return nil, err
	}

	decryptedErr := make(chan error)
	makeDecryptionReqBoxContent(decryptedErr)
	err2 := <- decryptedErr
	if err2 != nil {
		if err2.Error() == "cancel" {
			return nil, err
		}
		return nil, err2
	}

	id, err = websto.GetCurrentID()
	return id, err
}

func MakeFirstTabs(){
	thtml := wu.Tabs["enroll"].MakeHTML("Enroll", "1")
	thtml.AppendTab(wu.Tabs["user"].MakeHTML(""/*hidden*/, "1"))
	thtml.AppendTab(wu.Tabs["switchUser"].MakeHTML("Switch User", "1"))	

	html := thtml.MakeHTML()
	doc := js.Global().Get("document")
	mainContent := doc.Call("getElementById", "mainImmSTContent")
	mainContent.Set("innerHTML", html)

	var defaultTab *js.Value
	id, err := getCurrentIdWithDecryptingKey()
	if err == nil {
		makeUserTab(id.Name, id)
		defaultTab = wu.Tabs["user"].GetButton()
	} else {
		defaultTab = wu.Tabs["enroll"].GetButton()
	}
	defaultTab.Call("click")
}

func updateEnrollContent(tabC *js.Value) {
	html := `<h3>Enroll user</h3>`

	items := wu.InitItems()
	items.AppendTextInput("username", "Username", "", "")
	items.AppendPasswordInput("secret", "Secret", "", "")
	items.AppendButton("Enroll user", "enroll")
	items.AppendRow(`<p id="result"></p>`)
	html += items.MakeHTML()
	tabC.Set("innerHTML", html)
}

func enroll(this js.Value, i []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	username := doc.Call("getElementById", "username").Get("value").String()
	enSecret := doc.Call("getElementById", "secret").Get("value").String()
	doc.Call("getElementById", "secret").Set("value", "") // clear

	go func() {
		resultPara := doc.Call("getElementById", "result")
		resultPara.Set("innerHTML", "enroll " + username)

		id, err := immclient.EnrollUser(username, immclient.OneYear, enSecret, url)
		if err != nil {
			resultPara.Set("innerHTML", err.Error())
			return
		}
		resultPara.Set("innerHTML", "Success")

		// save certificate
		websto.StoreKeyPair(username, id)
		websto.SetCurrentUsername(id.Name)

		makeUserTab(id.Name, id)

		adminHost := id.GetStorageAdminHost()
		adminGrpHost := id.GetGrpAdminHost()
		if adminHost == "" && adminGrpHost == "" {
			return
		}

		var hostname string
		if adminGrpHost != "" {
			// create storage group service
			hostname = adminGrpHost
		}

		if adminHost != "" {
			// create storage service
			hostname = adminHost
		}
		
		hostID, err := immclient.EnrollUser(hostname, immclient.TenYears, enSecret, url)
		if err != nil {
			return
		}

		// save certificate and private key
		websto.StoreKeyPair(websto.HOST_PREFIX + hostname, hostID)

		// create a service
		err = id.CreateService("", hostID.Priv, hostID.Cert, url)
		if err != nil {
			resultPara.Set("innerHTML", err.Error())
		}
		return
	}()

	return nil
}


type caIdentities struct {
	lock int32
	execUser string
	list []immclient.IdentityInfo
}

var caIDs = &caIdentities{lock: 0}
func updateListUserContent(tabContent *js.Value){
	if atomic.CompareAndSwapInt32(&caIDs.lock, 0, 1) == false {
		return
	}
	defer func() { caIDs.lock = 0 }()

	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	defer func() { caIDs.execUser = id.Name }()
	if (caIDs.execUser == id.Name) {
		return
	}

	users, err := id.GetAllIdentities(wu.GetImmsrvURL())
	if err != nil {
		print("error: getAllIdentities: " +  err.Error() + "\n")
		return
	}
	caIDs.list = users

	if tabContent == nil {
		tabContent = wu.Tabs["listUser"].GetContent()
	}
	makeListUserInternal(tabContent)
}

func makeListUserInternal(tabContent *js.Value){
	html := `<table id="userListTable">`

	html += "<tr>"
	html += `  <td>#</td><td>Name</td><td>Type</td><td>Max Enrollments</td><td>Attributes</td> <td>Affiliation</td>`
	html += "</tr>"

	for i, user := range caIDs.list {
		html += "<tr>"
		html += "<td>" + strconv.Itoa(i+1) + "</td>"
		html += `<td class="dropdown" onmousedown="dropdownIDFunc(event, '` + user.ID + `')">`
		html += `<div class="dropdownMenu">`
		html += `  <div class="userNameOnList">` + user.ID + `</div>`// Name
		html += `  <div class="dropdownContent" id="dropdown` + user.ID + `">`
		html += `    <a href="javascript:void(0);" onclick="removeID('` + user.ID + `')">Remove</a>`
		html += `    <a href="javascript:void(0);" onclick="revokeID('` + user.ID + `')">Revoke</a>`
		html += `    <a href="javascript:void(0);" onclick="changeSecret('` + user.ID + `')">Change Secret</a>`
		html += `    <a href="javascript:void(0);" onclick="dismiss()">Dismiss</a>`
		html += `  </div>`
		html += `</div>`
		html += "</td>"
		html += `<td onmousedown="dismiss()">` + user.GetUserType() + "</td>" // Type

		strMaxEnroll := strconv.Itoa(user.MaxEnrollments)
		if user.MaxEnrollments == -1 {
			strMaxEnroll = "unlimited"
		}
		if user.MaxEnrollments == 0 {
			strMaxEnroll = "disabled"
		}

		html += `<td  class="dropdown" onmousedown="onOffEnrollment(event, '` + user.ID + `')">`
		html += `<div class="dropdownMenu">`
		html += `  <div id="setMaxEnrollments` + user.ID + `">` + strMaxEnroll + `</div>`
		html += `  <div class="dropdownContent" id="dropdownSetMaxEnrollments` + user.ID + `">`
		html += `    <a href="javascript:void(0);" onclick="enableEnrollment('` +  user.ID + `')">Enable</a>`
		html += `    <a href="javascript:void(0);" onclick="disableEnrollment('` + user.ID + `')">Disable</a>`
		html += `  </div>`
		html += `</div>`
		html += "</td>"
		
		html += `<td onmousedown="dismiss()">`
		for _, attr := range user.Attributes {
			html += attr.Name + ":" + attr.Value + " enroll_cert:" + strconv.FormatBool(attr.ECert) + "<br>"
		}
		html += "</td>"

		html += `<td onmousedown="dismiss()">` + user.Affiliation + "</td>" // Affiliation
		html += "</tr>"
	}
	
	html += "</table>"
	tabContent.Set("innerHTML", html)
}

func switchUser(this js.Value, in []js.Value) interface{} {
	target := in[0].Get("target")
	username := target.Get("value").String()

	
	if target.Get("checked").Bool() == false {
		return nil
	}

	caIDs.execUser = ""
	websto.SetCurrentUsername(username)
	id, err := websto.GetCurrentID()
	if err != nil && err.Error() != websto.ERR_ENCRYPTED_KEY {
		return nil
	}
	go makeUserTab(username, id)

	return nil
}

var switchUserContentLock = int32(0)
func updateSwitchUserContent(tabContent *js.Value) {
	if atomic.CompareAndSwapInt32(&switchUserContentLock, 0, 1) == false {
		return
	}
	defer func() { switchUserContentLock = 0 }()

	id, err := websto.GetCurrentID()
	curUsername := ""
	if err == nil {
		curUsername = id.Name
	}

	html := "<h3>Switch User</h3>\n"
	items := wu.InitItems()
	items.AppendRow("<p>Select a user:</p>")
	for _, username := range websto.ListUsername() {
		checked := ""
		if username == curUsername {
			checked = "checked"
		}

		passRequired := ""
		if websto.IsPasswordRequired(username) {
			passRequired = ":  password required"
		}
		items.AppendRadioButton("clientUser",  username + passRequired, username, `onchange="switchUser(event)" `+checked)
	}
	html += items.MakeHTML()

	tabContent.Set("innerHTML", html)
}

func makeUserTab(username string, id *immclient.UserID) {
	caURL := wu.GetImmsrvURL()

	userTab := wu.Tabs["user"]
	tabBtn := userTab.GetButton()
	tabBtn.Set("hidden", false)
	tabBtn.Set("innerHTML", username)

	registerTabF := false
	listUserTabF := false
	hasStorAdminF := false
	hasStorGrpAdminF := false
	if id != nil {
		regRoles := id.GetRegRoles(caURL)
		if len(regRoles) > 0 {
			registerTabF = true
			listUserTabF = true
		}
		
		hasStorAdminF = id.HasStorageAdmin()
		hasStorGrpAdminF = id.HasStorageGrpAdmin()
	}

	userContent := userTab.GetContent()
	html := "<h3>" + username + "</h3>\n"

	tabHTML := &wu.TabHTML{}
	
	if registerTabF {
		tabHTML.AppendTab(wu.Tabs["register"].MakeHTML("Register", "2"))
	}
	if listUserTabF {
		tabHTML.AppendTab(wu.Tabs["listUser"].MakeHTML("List User", "2"))		
	}
	tabHTML.AppendTab(wu.Tabs["keyManage"].MakeHTML("Key Management", "2"))
	if hasStorAdminF || hasStorGrpAdminF {
		tabHTML.AppendTab(wu.Tabs["action"].MakeHTML("Storage Service", "2"))
	} else {
		tabHTML.AppendTab(wu.Tabs["listApps"].MakeHTML("Application", "2"))
	}
	
	html += tabHTML.MakeHTML()
	userContent.Set("innerHTML", html)
}

func updateUserContent(tabC *js.Value) {
	encryptedIdF := isCurIdEncrypted()
	id, err := getCurrentIdWithDecryptingKey()
	if err != nil {
		tabBtn := wu.Tabs["user"].GetButton()
		tabBtn.Set("hidden", true)
		
		tabC.Set("innerHTML", "")
		return
	}
		
	if encryptedIdF {
		makeUserTab(id.Name, id)
	}
}

func makeRegisterTab() string {
	uType := []wu.SelectOptList{
		{"AppUser", "Application user"},
		{"StorageAdmin", "Storage service administrator"},
		{"StorageGrpAdmin", "Storage group administrator"},
	}

	items := wu.InitItems()
	items.AppendSelectListWithFunc("userType", "User type", "selectedUserType", uType)
	items.AppendHTML(`<div id="userAttributeArea"></div>`)
	items.AppendButton("Register", "register")
	items.AppendRow(`<p id="registerResult"></p>`)
	return items.MakeHTML()
}

func updateRegisterContent(tabC *js.Value) {
	html := makeRegisterTab()
	tabC.Set("innerHTML", html)

	doc := js.Global().Get("document")
	
	userTypeSel := doc.Call("getElementById", "userType")
	if userTypeSel.IsNull() {
		return
	}
	userTypeSel.Call("onchange")
}

func updateKeyManageContent(tabC *js.Value) {
	privItems := wu.InitItems()
	privItems.AppendHTML(`<button onclick="exportKey(event, 'private')" id="exportPrivKeyBtn">Export</button>`)
	privItems.AppendHTML(`<a id="exportPrivKeyData"></a>`)
	privItems.AppendHTML(`<button onclick="encryptKey(event)" id="encryptKeyBtn" style="margin-left: 5px;">Encrypt</button>`)
	privItems.PackDiv(privItems.BtnC)
	
	certItems := wu.InitItems()
	certItems.AppendHTML(`<button onclick="exportKey(event, 'certificate')" id="exportCertKeyBtn">Export</button>`)
	certItems.AppendHTML(`<a id="exportCertKeyData"></a>`)
	certItems.PackDiv(certItems.BtnC)

	items := wu.InitItems()
	items.AppendLabelAndInput("Private key", privItems.GetHTML())
	items.AppendLabelAndInput("Certificate", certItems.GetHTML())

	tabC.Set("innerHTML", items.MakeHTML())
	return
}


func selectedUserType(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	userTypeSel := doc.Call("getElementById", "userType")
	userType := userTypeSel.Get("value").String()
	userAttributeArea := doc.Call("getElementById", "userAttributeArea")
	
	registerName := ""
	hostName := ""
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}
	org, err := id.GetIssuerOrg()
	if err != nil {
		return nil
	}
	
	if userType == "StorageGrpAdmin" {
		registerName += "storage-grp"
		hostName += registerName + "." + org
	}
	if userType == "StorageAdmin" {
		registerName += "storage"
		hostName += registerName + "." + org
	}

	go func(){
		items := wu.InitItems()
		items.AppendLabelAndInputWithID("registerNameArea", "User name",
            `<input type="text" id="registerName" oninput="inputtedRegisterName()" value="`+registerName+`">`)

		if hostName == "" { // application user
			authType := []wu.SelectOptList{
				{"CA", "Certificate authority"},
				{"LDAP", "LDAP"},
				{"OAUTH_GRAPH", "MS Graph (OAuth2)"},
				{"JPKI", "JPKI"},
			}
			items.AppendSelectListWithFunc("authType", "Authentication type", "selectedAuthType", authType)
			items.AppendLabelAndInputWithAttr(` id="registerSecretArea" hidden`, "Secret",
				`<input type="text" id="registerSecret">`)
			items.AppendHTML(`<div id="authAttrArea" hidden></div>`)
		} else { // storage or storage group administrator
			items.AppendLabelAndInputWithID("registerHostnameArea", "Administration host",
                `<input type="text" id="registerHost" readonly="readonly" value="`+hostName+`">`)
			items.AppendLabelAndInputWithAttr(` id="registerSecretArea"`, "Secret",
				`<input type="text" id="registerSecret">`)
		}

		userAttributeArea.Set("innerHTML", items.GetHTML())

		authTypeSel := doc.Call("getElementById", "authType")
		if ! authTypeSel.IsNull() {
			authTypeSel.Call("onchange")
		}
	}()

	return nil
}

func inputtedRegisterName(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	userTypeSel := doc.Call("getElementById", "userType")
	userType := userTypeSel.Get("value").String()

	if userType != "StorageAdmin" && userType != "StorageGrpAdmin" {
		return nil
	}

	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}
	org, err := id.GetIssuerOrg()

	registerName := doc.Call("getElementById", "registerName").Get("value").String()
	hostnameInput := doc.Call("getElementById", "registerHost")
	hostnameInput.Set("value", registerName + "." + org)
	return nil
}

func selectedAuthType(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	authTypeSel := doc.Call("getElementById", "authType").Get("value").String()
	regSecretArea := doc.Call("getElementById", "registerSecretArea")
	regSecretAreaHiddenF := false
	authAttrArea := doc.Call("getElementById", "authAttrArea")
	authAttrAreaHiddenF := false
	registerNameArea := doc.Call("getElementById", "registerNameArea")
	registerNameHiddenF := false

	switch authTypeSel {
	case "CA":
		authAttrAreaHiddenF = true
	case "LDAP":
		items := wu.InitItems()
		items.AppendTextInput("bindLDAPServer", "Bind LDAP server", "localhost:389", "")
		items.AppendTextInput("bindDN", "Bind DN format", `"uid=%s,ou=PEOPLE,o=,c=",sn`, "")
		items.AppendTextInput("queryLDAPServer", "Query LDAP server", "localhost:389", "")
		items.AppendTextInput("queryBaseDN", "Query base DN", "ou=PEOPLE,o=,c=", "")
		items.AppendTextInput("queryLDAP", "Query format", `"(&(objectClass=organizationalPerson)(|(department=de1)(department=de2))(mail=%s))",username`, "")
		authAttrArea.Set("innerHTML", items.GetHTML())
		regSecretAreaHiddenF = true
	case "JPKI":
		items := wu.InitItems()
		items.AppendRow(`<p>Please select privacy information importing from the JPKI card:</p>`)
		items.AppendRadioButton("privacyInfoType", "publicKey", "Only public keys", "checked")
		items.AppendRadioButton("privacyInfoType", "authCert", "The authentication certificate, and a public key in the signature certificate", "")
		items.AppendRadioButton("privacyInfoType", "signCert", "The authentication certificate and the signature certificate contained residential address, full name, etc.", "")
		authAttrArea.Set("innerHTML", items.GetHTML())
		regSecretAreaHiddenF = true
		registerNameHiddenF = true
	case "OAUTH_GRAPH":
		id, err := websto.GetCurrentID()
		org := ""
		if err == nil {
			org, _ = id.GetIssuerOrg()
		}

		items := wu.InitItems()
		items.AppendTextInput("groupName", "Group name", "group1", "")
		items.AppendTextInput("clientID", "Client ID", "", "")
		items.AppendTextInput("secretValue", "Client secret value", "", "")
		items.AppendTextInput("allowPrincipalDomains", "Allow principal domains", "", "")
		items.AppendTextInput("redirectURL", "Redirect URL", "https://www."+org+"/graphcallback", "readonly")
		items.AppendTextInput("loginURL", "Login URL", "https://www."+org+"/graphcallback/login/group1", "readonly")
		authAttrArea.Set("innerHTML", items.GetHTML())
		regSecretAreaHiddenF = true
		registerNameHiddenF = true
	default:
		print("unknown authentication type: " + authTypeSel + "\n")
		return nil
	}

	regSecretArea.Set("hidden", regSecretAreaHiddenF)
	authAttrArea.Set("hidden", authAttrAreaHiddenF)
	registerNameArea.Set("hidden", registerNameHiddenF)
	return nil
}

func register(this js.Value, in []js.Value) interface{}{
	doc := js.Global().Get("document")
	
	userType := doc.Call("getElementById", "userType").Get("value").String()
	regList := map[string] func() (error){
		"AppUser": registerGeneralAppUser,
		"StorageAdmin": registerStorage,
		"StorageGrpAdmin": registerStorageGrp,		
	}

	go func() {
		result := doc.Call("getElementById", "registerResult")
		reg, ok := regList[userType]
		if ! ok {
			result.Set("innerHTML", "unexpected user type: " + userType)
			return
		}
		
		err := reg()
		if err != nil {
			result.Set("innerHTML", err.Error())
			return
		}
		result.Set("innerHTML", "Success")
	}()

	return nil
}

func registerGeneralAppUser() error {
	appendReq := &immclient.RegistrationRequest{
		Type: "client",
	}
	return registerAppUser(appendReq)
}

func registerAppUser(appendReq *immclient.RegistrationRequest) error {
	url := wu.GetImmsrvURL()
	doc := js.Global().Get("document")

	authType := doc.Call("getElementById", "authType").Get("value").String()
	id, err := websto.GetCurrentID()
	if err != nil {
		return err
	}

	err = id.CheckAndAddAffiliation(url, appendReq.Affiliation)
	if err != nil {
		return err
	}
	
	var authParam proto.Message
	var authParamRaw []byte
	switch authType {
	case "CA":
		usernameObj := doc.Call("getElementById", "registerName")
		secretObj := doc.Call("getElementById", "registerSecret")
		return webcli.RegisterAppUserCA(id, appendReq, &usernameObj, &secretObj)
	case "LDAP":
		authParam = &immop.AuthParamLDAP{
			BindServer: doc.Call("getElementById", "bindLDAPServer").Get("value").String(),
			BindDN: doc.Call("getElementById", "bindDN").Get("value").String(),
			QueryServer: doc.Call("getElementById", "queryLDAPServer").Get("value").String(),
			BaseDN: doc.Call("getElementById", "queryBaseDN").Get("value").String(),
			Query: doc.Call("getElementById", "queryLDAP").Get("value").String(),
			UserNameOnCA: doc.Call("getElementById", "registerName").Get("value").String(),
		}
	case "JPKI":
		authParam = &immop.AuthParamJPKI{
			ImportItems: doc.Call("querySelector", "input[name=\"privacyInfoType\"]:checked").Get("value").String(),
		}
	case "OAUTH_GRAPH":
		authParamS := &struct{
			GroupName string
			ClientID string
			SecretValue string
			AllowDomains string
		}{
			GroupName: doc.Call("getElementById", "groupName").Get("value").String(),
			ClientID: doc.Call("getElementById", "clientID").Get("value").String(),
			SecretValue: doc.Call("getElementById", "secretValue").Get("value").String(),
			AllowDomains: doc.Call("getElementById", "allowPrincipalDomains").Get("value").String(),
		}
		authParamRaw, err = json.Marshal(authParamS)
		if err != nil {
			return errors.New("failed to get authentication parameters: " + err.Error())
		}
		org, _ := id.GetIssuerOrg()
		loginURL := "https://www."+org+"/graphcallback/login/"+authParamS.GroupName
		doc.Call("getElementById", "loginURL").Set("value", loginURL)
	default:
		return errors.New("unknown authentication type: " + authType)
	}

	if authParamRaw == nil {
		authParamRaw, err = proto.Marshal(authParam)
		if err != nil {
			return errors.New("failed to marshal authentication parameter: " + err.Error())
		}
	}

	regReq := &immop.RegisterUserRequest{
		AuthType: authType,
		AuthParam: authParamRaw,
	}

	if appendReq != nil {
		regReq.AppendAttr, err = json.Marshal(appendReq)
		if err != nil {
			return errors.New("failed to parse appending attributes: " + err.Error())
		}
	}
	
	_, err = id.RegisterUser(regReq, url)
	return err
}

func registerStorage() error {
	doc := js.Global().Get("document")
	hostname := doc.Call("getElementById", "registerHost").Get("value").String()
	
	privilege := &immclient.UserPrivilege{
		StorageAdmin: hostname,
	}
	return registerHost(hostname, "peer", privilege)
}

func registerStorageGrp() error {
	doc := js.Global().Get("document")
	hostname := doc.Call("getElementById", "registerHost").Get("value").String()
	
	privilege := &immclient.UserPrivilege{
		StorageGrpAdmin: hostname,
	}
	return registerHost(hostname, "orderer", privilege)
}

func registerHost(hostname, ou string, privilege *immclient.UserPrivilege) error {
	doc := js.Global().Get("document")
	caURL := wu.GetImmsrvURL()
	
	username := doc.Call("getElementById", "registerName").Get("value").String()
	secret := doc.Call("getElementById", "registerSecret").Get("value").String()

	id, err := websto.GetCurrentID()
	if err != nil {
		return err
	}
	
	retSecret, err := id.RegisterObj(username, secret, "client", privilege, caURL)
	if err != nil {
		return errors.New("Register username: " + err.Error())
	}

	retHostSecret, err := id.RegisterObj(hostname, retSecret, ou, nil, caURL)
	if err != nil {
		id.RemoveIdentity(caURL, username)
		return errors.New("unexpected response from the CA: " + err.Error())
	}
	if retHostSecret != retSecret {
		id.RemoveIdentity(caURL, username)
		id.RemoveIdentity(caURL, hostname)
		return errors.New("unexpected secret")
	}

	doc.Call("getElementById", "registerSecret").Set("value", retSecret)
	return nil // success
}

func updateActionContent(tabC *js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	var tab *wu.TabBtn
	if id.HasStorageAdmin() {
		tab = wu.Tabs["storageSvc"]
	}
	if id.HasStorageGrpAdmin() {
		tab = wu.Tabs["storageGrp"]
	}

	if tab == nil {
		return
	}
	
	html := `<div class="space"></div>`
	tabHTML := tab.MakeHTML("Administration", "3")
	html += tabHTML.MakeHTML()
	tabC.Set("innerHTML", html)

	tab.GetButton().Call("click")
}

func updateListAppsContent(tabC *js.Value) {
	items := wu.InitItems()
	items.AppendRow(`<a href="readWriteLog.html">Read and Write Log</a>`)
	items.AppendRow(`<a href="secretBallot.html">Secret Ballot</a>`)
	items.AppendRow(`<a href="anonymousSurvey.html">Anonymous Survey</a>`)
	items.AppendRow(`<a href="rsyslogConfig.html">Rsyslog Configuration</a>`)
	items.AppendRow(`<a href="st2web/index.html">Workflow</a>`)
	items.PackDiv("listAppsArea")
	tabC.Set("innerHTML", items.MakeHTML())
}

var storageSvcContentLock = int32(0)
func updateStorageSvcContent(tabC *js.Value) {
	if atomic.CompareAndSwapInt32(&storageSvcContentLock, 0, 1) == false {
		return
	}
	defer func() { storageSvcContentLock = 0 }()

	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}
		
	storageHost := id.GetStorageAdminHost()
	if storageHost == "" {
		return
	}
	hostname := storageHost

	storageSvcI:= wu.InitItems()
	storageSvcI.AppendHTML(`<button onclick="exportService(event)" name="`+hostname+`">Export</button>`)
	storageSvcI.AppendHTML(`<label for="joinChannelFile" style="margin-left: 5px;">Join</label>`)
	storageSvcI.AppendHTML(`<input type="file" id="joinChannelFile" accept=".block" onchange=joinChannel(event) hidden name="`+hostname+`">`)
	storageSvcI.AppendHTML(`<a id="exportServiceConf`+hostname+`"></a>`)
	storageSvcI.PackDiv(storageSvcI.BtnC)
	storageSvcI.PackDiv("serviceCreateBtn")
	
	items := wu.InitItems()
	items.LabelC = "serviceName"
	items.InputC = "serviceState"
	items.AppendLabelAndInput(hostname, storageSvcI.GetHTML())
	items.AppendHTML(`<div id="storageGrpState"></div>`)
	tabC.Set("innerHTML", items.MakeHTML())
	updateStorageGrpState()	
}

var exportServiceLock = int32(0)
func exportService(this js.Value, in []js.Value) interface{} {
	target := in[0].Get("target")
	hostname := target.Get("name").String()

	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}

	go func() {
		if atomic.CompareAndSwapInt32(&exportServiceLock, 0, 1) == false {
			return
		}
		defer func() { exportServiceLock = 0 }()
		

		url := wu.GetImmsrvURL()
		serviceData, err := id.ExportService(hostname, url)
		if err != nil {
			print("log: " + err.Error() + "\n")
			return
		}

		saveFileName := hostname + "_service.dat"
		wu.SaveFile(saveFileName, serviceData, "exportServiceConf"+hostname)
	}()

	return nil
}

var storageGrpContentLock = int32(0)
func updateStorageGrpContent(tabC *js.Value) {
	url := wu.GetImmsrvURL()

	print("log: updateStorageGrpContent\n")
	if atomic.CompareAndSwapInt32(&storageGrpContentLock, 0, 1) == false {
		return
	}
	defer func() { storageGrpContentLock = 0 }()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}
		
	grpAdminHost := id.GetGrpAdminHost()
	if grpAdminHost == "" {
		return
	}
	
	services, err := id.ListService(url)
	if err != nil {
		print("log: " + err.Error() + "\n")
		return
	}
	grpAdminHostF := false
	for _, service := range services {
		if service.Hostname == grpAdminHost {
			grpAdminHostF = true
			break
		}
	}
	if grpAdminHostF == false {
		print("log: There is no service for storage group in this organization\n")
		return
	}

	org, _ := id.GetIssuerOrg()

	accessPerm, err := immadmin.GetStorageGrpPerm(id, url)
	if err != nil {
		print("log: " + err.Error() + "\n")
		return
	}

	permChecked := ""
	if accessPerm == immadmin.AccessPermGrpMember {
		permChecked = " checked"
	}
		
	items := wu.InitItems()
	items.AppendLabelAndInputWithAttr("", `<b>Storage group name: </b>`, `<label><b>` + strings.TrimSuffix(grpAdminHost, "."+org) + `</b></label>`)
	items.AppendHTML("<hr>")
	items.AppendCheckbox("Set access rights to group members only", `id="accessPerm" onchange=setPermGrpMember(event)`+permChecked)
	items.AppendHTML(`<div id="anchorPeers"></div>`)
	items.AppendReadFileButton("serviceConfFile", "Add storage service",
		"Import", `accept=".dat" onchange=addAnchorPeer(event) hidden`)
	items.AppendSaveFileButton("exportChannelData", "Export", "exportChannel", "hidden")
	
	html := items.MakeHTML()
	tabC.Set("innerHTML", html)

	updateAnchorPeers()
}

func setPermGrpMember(this js.Value, in []js.Value) interface{} {
	target := in[0].Get("target")

	perm := immadmin.AccessPermAll
	if target.Get("checked").Bool() == true {
		perm = immadmin.AccessPermGrpMember
	}

	url := wu.GetImmsrvURL()
	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}
	
	go immadmin.SetStorageGrpPerm(id, url, perm)
	return nil
}

func updateAnchorPeers() {
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	url := wu.GetImmsrvURL()
	doc := js.Global().Get("document")

	exportChBtn := doc.Call("getElementById", "exportChannelBtn")
	anchorArea := doc.Call("getElementById", "anchorPeers")
	
	listAnchor, err := id.ListImportedService(url)
	if err != nil {
		print("log: " + err.Error() + "\n")
		return
	}
		
	if len(listAnchor) > 0 {
		exportChBtn.Set("hidden", false)
	} else {
		exportChBtn.Set("hidden", true)
	}

	items := wu.InitItems()
	for _, anchor := range listAnchor {
		hostname := anchor.Hostname + ":" + anchor.Port
		items.AppendButtonWithDsc(hostname, hostname, "Remove", "removeService")
	}

	anchorArea.Set("innerHTML", items.GetHTML())
}

func addAnchorPeer(this js.Value, in []js.Value) interface{} {
	go func() {
		fileList := in[0].Get("target")
		peerDataFile := fileList.Get("files").Index(0)
		peerData := wu.ReadFile(peerDataFile)

		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		url := wu.GetImmsrvURL()
		id.ImportService(peerData, url)
		updateAnchorPeers()
	}()

	return nil
}

func removeService(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()
	removeBtn := in[0].Get("target")
	hostPortName := strings.Split(removeBtn.Get("name").String(), ":")

	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}
		
		id.RemoveServiceFromCh(hostPortName[0], hostPortName[1], url)
		updateAnchorPeers()
	}()

	return nil
}

func joinChannel(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()

	go func() {
		fileList := in[0].Get("target")
		dataFile := fileList.Get("files").Index(0)
		block := wu.ReadFile(dataFile)

		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}
		if ! id.HasStorageAdmin() {
			return
		}

		wu.VisibleSimpleMsgBox("Join task is in progress")
		err = id.JoinChannel(block, url)
		
		msg := "Success"
		if err != nil {
			print("JoinChannel error: " + err.Error() + "\n")
			msg = "Failed to join: " + err.Error()
		}
		wu.VisibleMsgBox(msg)
		
		updateStorageGrpState()
	}()

	return nil
}

func updateStorageGrpState() {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpState := doc.Call("getElementById", "storageGrpState")
	if storageGrpState.IsNull() {
		return
	}

	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}
	if ! id.HasStorageAdmin() {
		return
	}

	chNames, err := id.ListChannelInPeer(url)
	if (err != nil) || (len(chNames) == 0) {
		return // no channel
	}
	
	html := "Loading..."
	storageGrpState.Set("innerHTML", html)

	items := wu.InitItems()
	items.LabelC = "serviceName"
	items.InputC = "serviceState"
	
	html = "<hr>"
	items.AppendRow("Group")
	for _, chName := range chNames {
		var chainCodeF bool
		chainCodes, err := id.ListChainCode(url, chName)
		if err == nil && len(chainCodes) > 0 {
			chainCodeF = true
		}
		
		grpHost := strings.TrimSuffix(chName, "-ch")
		grpHostDsc := "- " + grpHost
		if chainCodeF {
			items.AppendLabelAndInput(grpHostDsc, `<label style="margin-left: 12px;">Available</label>`)
		} else {
			items.AppendButtonWithDsc(chName, grpHostDsc, "Enable", "enableChannel")
		}
	}
	html += items.GetHTML()
	storageGrpState.Set("innerHTML", html)	
}

var exportChannelLock = int32(0)
func exportChannel(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()

	go func() {
		if atomic.CompareAndSwapInt32(&exportChannelLock, 0, 1) == false {
			return
		}
		defer func() { exportChannelLock = 0 }()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		hostname := id.GetGrpAdminHost()
		if hostname == "" {
			return
		}

		chName := hostname + "-ch"
		err = id.CreateChannel(chName, url)
		if err != nil {
			print("log: " + err.Error() + "\n")
			return
		}

		block, err := id.GetConfigBlock(chName, url)
		if err != nil {
			return
		}

		saveFileName := chName + ".block"
		wu.SaveFile(saveFileName, block, "exportChannelData")
	}()

	return nil
}

var enableChannelLock = int32(0)
func enableChannel(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()
	
	target := in[0].Get("target")
	chName := target.Get("name").String()

	go func() {
		if atomic.CompareAndSwapInt32(&enableChannelLock, 0, 1) == false {
			return
		}
		defer func() { enableChannelLock = 0 }()

		wu.VisibleSimpleMsgBox("Enabling storage is in progress")
		
		resultMsg := "Success"
		defer func() {
			wu.VisibleMsgBox(resultMsg)
			updateStorageGrpState()
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			resultMsg= "Failed to enable storage: " + err.Error()
			return
		}
		if ! id.HasStorageAdmin() {
			resultMsg = "Permission denied"
			return
		}

		err = id.ActivateChannel(url, chName)
		if err != nil {
			resultMsg = "Failed to activate storage: " + err.Error()
			print("log: error: " + err.Error())
			return
		}
		
		chainCode, err := id.ListChainCodeInPeer(url)
		if err != nil {
			resultMsg = "Internal error: avaliable plugin is not found: " + err.Error()
			print("log: " + err.Error() + "\n")
			return
		}
		
		if len(chainCode) <= 0 {
			err = id.InstallChainCode(url)
			if err != nil {
				resultMsg = "Could not load a plugin: " + err.Error()
				print("log: " + err.Error() + "\n")
				return
			}
		}

		err = id.InstantiateChainCode(url, chName)
		if err != nil {
			resultMsg = "Failed to instantiate a plugin: " + err.Error()
			print("log: " + err.Error() + "\n")
			return
		}

		for i := 0; i < 3; i++ {
			chainCodes, err := id.ListChainCode(url, chName)
			if err == nil && len(chainCodes) > 0 {
				break
			}
			if err != nil {
				print("log: listChaincode: error=" + err.Error() + "\n")
			}
			time.Sleep(time.Second)
		}
	}()

	return nil
}

func dropdownIDFunc(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

//	target := in[0].Get("target")
	userID := in[1].String()

	//	print("dropdown: " + userID + "\n")

	closeDropdownContents()


	buttonNum := in[0].Get("button").Int()
	if buttonNum != 0 {
		return nil
	}
	
	activateContent := doc.Call("getElementById", "dropdown" + userID)
	if activateContent.IsNull() {
		return nil
	}

	activateContent.Get("style").Set("display", "block")

	return nil
}

func closeDropdownContents(){
	gl := js.Global()
	doc := gl.Get("document")
	
	dropdownContents := doc.Call("getElementsByClassName", "dropdownContent")
	len := dropdownContents.Length()
	for i := 0; i < len; i++ {
		dropdownContents.Index(i).Get("style").Set("display", "none")
	}
}

func enableEnrollment(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	
	userID := in[0].String()
	caURL := wu.GetImmsrvURL()

	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}

	
	go func() {
		err = id.EnableEnrollment(caURL, userID)
		if err != nil {
			return
		}
		
		doc := js.Global().Get("document")
		state := doc.Call("getElementById", "setMaxEnrollments" + userID)
		if state.IsNull() {
			return
		}
		state.Set("innerHTML", "unlimited")
	}()
	
	return nil
}

func disableEnrollment(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	
	userID := in[0].String()
	caURL := wu.GetImmsrvURL()

	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}

	go func() {
		err = id.DisableEnrollment(caURL, userID)
		if err != nil {
			return
		}

		doc := js.Global().Get("document")
		state := doc.Call("getElementById", "setMaxEnrollments" + userID)
		if state.IsNull() {
			return
		}
		state.Set("innerHTML", "disabled")
	}()
	return nil
}

func onOffEnrollment(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	
	gl := js.Global()
	doc := gl.Get("document")

	userID := in[1].String()

	activateContent := doc.Call("getElementById", "dropdownSetMaxEnrollments" + userID)
	if activateContent.IsNull() {
		return nil
	}
	activateContent.Get("style").Set("display", "block")

	return nil
}


func makeRemoveIdBoxContent(userName string) {
	header := `  <label>Are you sure you want to remove ` + userName + `?</label>`
	footer := `  <input id="removeIdName" type="hidden" value="` + userName + `">`
	wu.MakeReqBox("removeId", header, footer, true, true)
}

func getReqBoxUsername(in []js.Value) string {
	if len(in) != 2 {
		return "" // failure
	}

	idName := in[1].String() + "Name"
	
	gl := js.Global()
	doc := gl.Get("document")
	idObj := doc.Call("getElementById", idName)
	if idObj.IsNull() {
		return "" // failure
	}
	
	return idObj.Get("value").String()
}

func removeIdOk(in []js.Value) {
	caURL := wu.GetImmsrvURL()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}
	
	userName := getReqBoxUsername(in)
	if userName == "" {
		return
	}
	
	print("log: remove userName=" + userName + "\n")
	err = id.RemoveIdentity(caURL, userName)

	if err != nil {
		wu.VisibleMsgBox("failed to remove ID: " + err.Error())
		return
	}
	
	caIDs.execUser = ""
	updateListUserContent(nil)

	wu.CloseReqBox(in)
}

func removeID(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	userID := in[0].String()
	//	print("removeID: " + userID + "\n")
	makeRemoveIdBoxContent(userID)
	return nil
}

func makeRevokeIdBoxContent(userName string) {
	header := `  <label>Are you sure you want to revoke ` + userName + `?</label>`
	footer := `  <input id="revokeIdName" type="hidden" value="` + userName + `">`
	wu.MakeReqBox("revokeId", header, footer, true, true)
}

func revokeIdOk(in []js.Value) {
	caURL := wu.GetImmsrvURL()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	userName := getReqBoxUsername(in)
	if userName == "" {
		return
	}
	
	print("log: revoke userName=" + userName + "\n")
	err = id.RevokeIdentity(caURL, userName)
	if err != nil {
		wu.VisibleMsgBox("failed to revoke ID: " + err.Error())
		return
	}
	
	caIDs.execUser = ""
	updateListUserContent(nil)

	wu.CloseReqBox(in)
}

func revokeID(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	
	userName := in[0].String()
	print("revokeID: " + userName + "\n")
	makeRevokeIdBoxContent(userName)
	return nil
}

func dismiss(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	return nil
}

func makeChangeSecretBoxContent(userName string) {
	newSecret := immclient.RandStr(8)
	header := `  <label>Please enter new secret:</label>`
	header += `  <input type="text" id="changeSecretText" value="` + newSecret + `">`
	footer := `  <input id="changeSecretName" type="hidden" value="` + userName + `">`
	wu.MakeReqBox("changeSecret", header, footer, true, true)
}

func changeSecretOk(in []js.Value) {
	caURL := wu.GetImmsrvURL()

	userName := getReqBoxUsername(in)
	if userName == "" {
		return
	}

	gl := js.Global()
	doc := gl.Get("document")
	newSecret := doc.Call("getElementById", "changeSecretText").Get("value").String()
	if newSecret == "" {
		return // ignore
	}
	
	id, err := websto.GetCurrentID()
	if err != nil {
		wu.VisibleMsgBox("failed to change the secret: " + err.Error())
		return
	}
	
	_, err = id.ChangeSecret(caURL, userName, newSecret)
	if err != nil {
		wu.VisibleMsgBox("failed to change the secret: " + err.Error())
		return
	}
	wu.CloseReqBox(in)
}

func changeSecret(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	userName := in[0].String()
	makeChangeSecretBoxContent(userName)
	return nil
}

var exportKeyLock = int32(0)
func exportKey(this js.Value, in []js.Value) interface{} {
	if len(in) !=  2 {
		return nil // unexpected argument
	}
	keyType := in[1].String()
		
	go func(){
		if atomic.CompareAndSwapInt32(&exportKeyLock, 0, 1) == false {
			return
		}
		defer func() { exportKeyLock = 0 }()

		userName, err := websto.GetCurrentUsername()
		if err != nil {
			return
		}
		id, err := websto.GetIDFromStorage(userName)
		if err != nil {
			return
		}

		if keyType == "private" {
			wu.SaveFile(id.Name+"_sk", id.Priv, "exportPrivKeyData")
			return
		}

		if keyType == "certificate" {
			wu.SaveFile(id.Name+"-cert.pem", id.Cert, "exportCertKeyData")
			return
		}

		// unexpected key type
		return
	}()
	return nil
}

func encryptKey(this js.Value, in []js.Value) interface{} {
	makeEncryptionReqBoxContent()
	return nil
}

func makeReqBoxContent(reqStr string) {
	userName, err := websto.GetCurrentUsername()
	if err != nil {
		return
	}

	header := `  <label>Please enter ` + userName + `'s password</label>`
	header += `  <input type="password" id="keyPassword">`
	wu.MakeReqBox(reqStr, header, "", true, true)
}

func makeEncryptionReqBoxContent() {
	makeReqBoxContent("encrypt")
}

var decryptKeyCh chan error
func makeDecryptionReqBoxContent(err chan error) {
	decryptKeyCh = err
	makeReqBoxContent("decrypt")
}

func encryptOk(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	keyPass := doc.Call("getElementById", "keyPassword").Get("value").String()
	if keyPass == "" {
		return // ignore
	}
	websto.EncryptKey(keyPass)

	wu.CloseReqBox(in)
}
	
func decryptOk(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	keyPass := doc.Call("getElementById", "keyPassword").Get("value").String()
	if keyPass == "" {
		return // ignore
	}
	
	err := websto.DecryptKey(keyPass)
	if err != nil {
		result := doc.Call("getElementById", "cryptResult")
		result.Set("innerHTML", "incorrect password")
		return
	}
	decryptKeyCh <- err

	wu.CloseReqBox(in)
}

func decryptCancel(in []js.Value) {
	decryptKeyCh <- errors.New("cancel")
	wu.CloseReqBox(in)
}
