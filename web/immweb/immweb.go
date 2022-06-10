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
	"github.com/golang/protobuf/proto"
	
	"immclient"
	"immop"
	"websto"
	wu "webutil"
	"webcli"
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
	html := `
      <h3>Enroll user</h3>

      <div class="cert-area">
        <div class="row">
          <div class="cert-item">
          <label for="username">Username</label>
          </div>
          <div class="cert-input">
            <input type="text" id="username">
          </div>
        </div>
        
        <div class="row">
          <div class="cert-item">
            <label for="secret">Secret</label>
          </div>
          <div class="cert-input">
            <input type="password" id="secret">
          </div>
        </div>
        
        <div class="row">
          <br>
          <div class="immDSBtn">
            <button onClick="enroll();" id="enrollButtion">Enroll user</button>
          </div>
        </div>
        
      </div>
      <div class="row">
        <p id="result"></p>
      </div>
`
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
	html += `<div class="cert-area" id="switchUserArea">`
	html += "<p>Select a user:</p>"
	for _, username := range websto.ListUsername() {
		checked := ""
		if username == curUsername {
			checked = "checked"
		}

		passRequired := ""
		if websto.IsPasswordRequired(username) {
			passRequired = ":  password required"
		}
		
		html += `<label class="radioArea">` + username + passRequired
		html += `  <input type="radio" onchange="switchUser(event)" name="clientUser" value="` +username +`" ` +checked +">"
		html += `  <span class="radioBox"></span>`
		html += "</label>"
	}
	html += "</div>"

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
	uType := []struct{
		Name string
		Title string
	}{
		{"AppUser", "Application user"},
		{"StorageAdmin", "Storage service administrator"},
		{"StorageGrpAdmin", "Storage group administrator"},
	}

	options := ""
	for _, userT := range uType{
		options += `<option value="`+userT.Name+`">`+userT.Title+`</option>`
	}

	html := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-item"><label for="type">User type</label></div>
          <div class="cert-input">
            <select id="userType" onchange="selectedUserType()">` + options + `
	        </select>
          </div>
        </div>
        <div id="userAttributeArea"></div>
        <div class="row">
          <div class="immDSBtn">
            <button onClick="register()" id="registerButton">Register</button>
          </div>
        </div>
        <div class="row">
          <p id="registerResult"></p>
        </div>
      </div>`

	return html
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
	html := `  <div class="cert-area">`
	
	html += `    <div class="row">`
	html += `      <div class="cert-item"><label>Private key</label></div>`
	html += `      <div class="cert-input">`	
	html += `        <div class="immDSBtn">`
	html += `          <button onclick="exportKey(event, 'private')" id="exportPrivKeyBtn">Export</button>`
	html += `          <a id="exportPrivKeyData"></a>`
	html += `          <button onclick="encryptKey(event)" id="encryptKeyBtn">Encrypt</button>`
	html += `        </div>`
	html += `      </div>`
	html += `    </div>`
	

	html += `    <div class="row">`
	html += `      <div class="cert-item"><label>Certificate</label></div>`
	html += `      <div class="cert-input">`	
	html += `        <div class="immDSBtn">`
	html += `          <button onclick="exportKey(event, 'certificate')" id="exportCertKeyBtn">Export</button>`
	html += `          <a id="exportCertKeyData"></a>`
	html += `        </div>`
	html += `      </div>`
	html += `    </div>`

	html += `  </div>`

	tabC.Set("innerHTML", html)
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
		html := `
        <div class="row" id="registerNameArea">
          <div class="cert-item"><label for="registerName" id="registerNameLabel">User name</label></div>
          <div class="cert-input">
            <input type="text" id="registerName" oninput="inputtedRegisterName()" value="`+registerName+`">
          </div>
        </div>`

		if hostName == "" { // application user
			html += makeGeneralAppUserRegHtml()
		} else { // storage or storage group administrator
			html += `
            <div class="row" id="registerHostnameArea">
              <div class="cert-item"><label for="registerHost" id="registerHostLabel">Administration host</label></div>
              <div class="cert-input">
                <input type="text" id="registerHost" readonly="readonly" value="`+hostName+`">
              </div>
            </div>
            <div class="row" id="registerSecretArea">
              <div class="cert-item"><label for="registerSecret">Secret</label></div>
              <div class="cert-input"><input type="text" id="registerSecret"></div>
            </div>`
		}

		userAttributeArea.Set("innerHTML", html)

		authTypeSel := doc.Call("getElementById", "authType")
		if ! authTypeSel.IsNull() {
			authTypeSel.Call("onchange")
		}
	}()

	return nil
}

func makeGeneralAppUserRegHtml() string {
	html := `
<div class="row" id="authTypeArea">
  <div class="cert-item"><label for="authType" id="authTypeLable">Authentication type</lable></div>
  <div class="cert-input">
    <select id="authType" onchange="selectedAuthType()">
      <option value="CA">Certificate authority</option>
      <option value="LDAP">LDAP</option>
      <option value="OAUTH_GRAPH">MS Graph (OAuth2)</option>
      <option value="JPKI">JPKI</option>
    </select>
  </div>
</div>
<div class="row" id="registerSecretArea" hidden>
  <div class="cert-item"><label for="registerSecret">Secret</label></div>
  <div class="cert-input"><input type="text" id="registerSecret"></div>
</div>
<div id="authAttrArea" hidden></div>`
	return html
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
		html := `
          <div class="row" id="bindLDAPServerArea">
            <div class="cert-item"><label for="bindLDAPServer" id="bindLDAPServerLabel">Bind LDAP server</label></div>
            <div class="cert-input"><input type="text" id="bindLDAPServer" value="localhost:389"></div>
          </div>
          <div class="row" id="bindDNArea">
            <div class="cert-item"><label for="bindDN" id="bindDNLabel">Bind DN format</label></div>
            <div class="cert-input"><input type="text" id="bindDN" value='"uid=%s,ou=PEOPLE,o=,c=",sn'></div>
          </div>

          <div class="row" id="queryLDAPServerArea">
            <div class="cert-item"><label for="queryLDAPServer" id="queryLDAPServerLabel">Query LDAP server</label></div>
            <div class="cert-input"><input type="text" id="queryLDAPServer" value="localhost:389"></div>            
          </div>
          <div class="row" id="queryBaseDNArea">
            <div class="cert-item"><label for="queryBaseDN" id="queryBaseDNLabel">Query base DN</label></div>
            <div class="cert-input"><input type="text" id="queryBaseDN" value="ou=PEOPLE,o=,c="></div>            
          </div>
          <div class="row" id="queryLDAPArea">
            <div class="cert-item"><label for="queryLDAP" id="queryLDAPLabel">Query format</label></div>
            <div class="cert-input"><input type="text" id="queryLDAP" value='"(&(objectClass=organizationalPerson)(|(department=de1)(department=de2))(mail=%s))",username'></div>
          </div>`
		authAttrArea.Set("innerHTML", html)
		regSecretAreaHiddenF = true
	case "JPKI":
		html := `
          <div class="row">
            <p>Please select privacy information importing from the JPKI card:</p>
          </div>
          <div class="row">
            <label class="radioArea">
              <input type="radio" name="privacyInfoType" value="publicKey" checked>
              <span class="radioBox"></span>
              Only public keys
            </label>
          </div>
          <div class="row">
            <label class="radioArea">
              <input type="radio" name="privacyInfoType" value="authCert">
              <span class="radioBox"></span>
              The authentication certificate, and a public key in the signature certificate
            </label>
          </div>
          <div class="row">
            <label class="radioArea">
              <input type="radio" name="privacyInfoType" value="signCert">
              <span class="radioBox"></span>
              The authentication certificate and the signature certificate contained residential address, full name, etc.
            </label>
          </div>`
		authAttrArea.Set("innerHTML", html)
		regSecretAreaHiddenF = true
		registerNameHiddenF = true
	case "OAUTH_GRAPH":
		id, err := websto.GetCurrentID()
		org := ""
		if err == nil {
			org, _ = id.GetIssuerOrg()
		}
		html := `
          <div class="row">
            <div class="cert-item"><label for="groupName">Group name</label></div>
            <div class="cert-input"><input type="text" id="groupName" value="group1"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="clientID">Client ID</label></div>
            <div class="cert-input"><input type="text" id="clientID"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="secretValue">Client secret value</label></div>
            <div class="cert-input"><input type="text" id="secretValue"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="allowPrincipalDomains">Allow principal domains</label></div>
            <div class="cert-input"><input type="text" id="allowPrincipalDomains" value="example.com"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="redirectURL">Redirect URL</label></div>
            <div class="cert-input"><input type="text" id="redirectURL" value="https://www.`+org+`/graphcallback" readonly></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="Login URL">Login URL</label></div>
            <div class="cert-input"><input type="text" id="loginURL" value="https://www.`+org+`/graphcallback/login/group1" readonly></div>
		  </div>`
		
		authAttrArea.Set("innerHTML", html)
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
	html := `<div class="cert-area">`
	html += `<div class="listAppsArea">`
		
	html += `<div class="row">`
	html += `  <div class="cert-item"><a href="readWriteLog.html">Read and Write Log</a></div>`
	html += `</div>`
	html += `<div class="row">`
	html += `  <div class="cert-item"><a href="secretBallot.html">Secret Ballot</a></div>`
	html += `</div>`
	html += `<div class="row">`		
	html += `  <div class="cert-item"><a href="anonymousSurvey.html">Anonymous Suvey</a></div>`
	html += `</div>`
		
	html += `</div>`		
	html += `</div>`
	tabC.Set("innerHTML", html)
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

	html := `<div class="cert-area">`
	html += `<div class="serviceRow">`
	html += `<p class="serviceName">`+hostname+`</p>`
	html += `<div class="serviceCreateBtn">`
	html += `  <div class="immDSBtn">`
	html += `  <button onclick="exportService(event)" name="`+hostname+`">Export</button>`
	html += `  <label for="joinChannelFile">Join</label>`
	html += `  <input type="file" id="joinChannelFile" accept=".block" onchange=joinChannel(event) hidden name="`+hostname+`">`
	html += `  </div>`
	html += `  <a id="exportServiceConf`+hostname+`"></a>`
	html += `</div>`
	html += "</div>"
	html += `<div id="storageGrpState">`
	html += `</div>`
	html += "</div>"

	tabC.Set("innerHTML", html)
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

	html := `<div class="cert-area">`
	html += `<div class="row">`
	html += `<div id="storageGroupName">`
	html += `  <div class="row">`
	html += `    <div class="cert-item"><label><b>Storage group name: </b></label></div>`
	html += `    <div class="cert-input"><label><b>` + strings.TrimSuffix(grpAdminHost, "."+org) + `</b></label></div>`
	html += `  </div>`
	html += `</div>`
	html += "<hr>"
	html += `<div id="anchorPeers"></div>`
	html += `<div class="row">`
	html += `  <div class="cert-item"><label>Add storage service</label></div>`
	html += `  <div class="cert-input">`
	html += `    <div class="immDSBtn">`
	html += `      <label for="serviceConfFile">Import</lable>`
	html += `      <input type="file" id="serviceConfFile" accept=".dat" onchange=addAnchorPeer(event) hidden>`
	html += `    </div>`
	html += `  </div>`
	html += `</div>`
	html += `<div class="immDSBtn">`
	html += `  <button onclick="exportChannel(event)" id="exportChannelBtn" hidden>Export</button>`
	html += `  <a id="exportChannelData"></a>`
	html += `</div>`
	html += `</div>`
	
	tabC.Set("innerHTML", html)

	updateAnchorPeers()
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

	var html string
	for _, anchor := range listAnchor {
		html += `<div class="row">`
		html += `  <div class="cert-item"><label>` + anchor.Hostname + ":" + anchor.Port + "</label></div>"
		html += `  <div class="cert-input">`
		html += `    <div class="immDSBtn">`
		html += `      <button onclick="removeService(event)" name="`+anchor.Hostname+":"+anchor.Port+`">Remove</button>`
		html += "    </div>"
		html += "  </div>"
		html += "</div>"
	}

	anchorArea.Set("innerHTML", html)
}

func addAnchorPeer(this js.Value, in []js.Value) interface{} {
	go func() {
		gl := js.Global()
		fileList := in[0].Get("target")
		peerDataFile := fileList.Get("files").Index(0)
		peerDataCh := make(chan []byte, 1)
		
		fileReader := gl.Get("FileReader").New()
		fileReaderCompFunc := js.FuncOf(func(this js.Value, event []js.Value) interface{} {
			readData := gl.Get("Uint8Array").New(event[0].Get("target").Get("result"))
			readByte := make([]byte, readData.Get("byteLength").Int())
			js.CopyBytesToGo(readByte, readData)
			
			peerDataCh <- readByte
			return nil
		})
		defer fileReaderCompFunc.Release()

		fileReader.Set("onload", fileReaderCompFunc)
		fileReader.Call("readAsArrayBuffer", peerDataFile)

		var peerData []byte
		select {
		case peerData = <- peerDataCh:
		}

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
		gl := js.Global()
		fileList := in[0].Get("target")
		dataFile := fileList.Get("files").Index(0)
		dataCh := make(chan []byte, 1)

		fileReader := gl.Get("FileReader").New()
		fileReaderCompFunc := js.FuncOf(func(this js.Value, event []js.Value) interface{} {
			readData := gl.Get("Uint8Array").New(event[0].Get("target").Get("result"))
			readByte := make([]byte, readData.Get("byteLength").Int())
			js.CopyBytesToGo(readByte, readData)
			
			dataCh <- readByte
			return nil
		})
		defer fileReaderCompFunc.Release()

		fileReader.Set("onload", fileReaderCompFunc)
		fileReader.Call("readAsArrayBuffer", dataFile)

		block := <- dataCh

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
	
	html = `<hr><div class="serviceRow">Group</div>`
	for _, chName := range chNames {
		var chainCodeF bool
		chainCodes, err := id.ListChainCode(url, chName)
		if err == nil && len(chainCodes) > 0 {
			chainCodeF = true
		}
		
		grpHost := strings.TrimSuffix(chName, "-ch")
		html += `<div class="serviceRow">`
		html += `<p class="serviceName">- `+grpHost+`</p>`
		html += `<div class="serviceCreateBtn">`
		if chainCodeF {
			html += `  <label>Available</lable>`
		} else {
			html += `  <div class="immDSBtn">`
			html += `  <button onclick="enableChannel(event)" name="`+chName+`" id="enableChannelBtn">Enable</button>`
			html += `  </div>`
		}
		html += `</div>`
		html += `</div>`
	}

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
