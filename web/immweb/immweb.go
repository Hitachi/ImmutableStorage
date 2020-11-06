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
	//	"fmt"
	"strings"
	"strconv"
	"syscall/js"
	"immclient"
	"websto"
	"sync/atomic"
	"encoding/json"
	"time"

	"github.com/golang/protobuf/proto"
//	"encoding/hex"
	"github.com/hyperledger/fabric/protos/common"
	pp "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/msp"

	"encoding/pem"
	"crypto/x509"
	"errors"
)

const (
	immsrvPath = "/immsrv"
)

func RegisterCallback() {
	gl := js.Global()
	gl.Set("enroll", js.FuncOf(enroll))
	gl.Set("openTab", js.FuncOf(openTab))
	gl.Set("selectedUserType", js.FuncOf(selectedUserType))
	gl.Set("inputtedRegisterName", js.FuncOf(inputtedRegisterName))
	gl.Set("register", js.FuncOf(register))
	gl.Set("switchUser", js.FuncOf(switchUser))
	gl.Set("exportService", js.FuncOf(exportService))
	gl.Set("addAnchorPeer", js.FuncOf(addAnchorPeer))
	gl.Set("removeService", js.FuncOf(removeService))
	gl.Set("joinChannel", js.FuncOf(joinChannel))
	gl.Set("exportChannel", js.FuncOf(exportChannel))
	gl.Set("enableChannel", js.FuncOf(enableChannel))
	gl.Set("selectedStorageGrp", js.FuncOf(selectedStorageGrp))
	gl.Set("recordLedger", js.FuncOf(recordLedger))
	gl.Set("saveLedger", js.FuncOf(saveLedger))
	gl.Set("dropdownIDFunc", js.FuncOf(dropdownIDFunc))
	gl.Set("removeID", js.FuncOf(removeID))
	gl.Set("revokeID", js.FuncOf(revokeID))
	gl.Set("dismiss", js.FuncOf(dismiss))
	gl.Set("changeSecret", js.FuncOf(changeSecret))
	gl.Set("exportKey", js.FuncOf(exportKey))
	gl.Set("encryptKey", js.FuncOf(encryptKey))
	gl.Set("reqBoxOk", js.FuncOf(reqBoxOk))
	gl.Set("reqBoxCancel", js.FuncOf(reqBoxCancel))
}

func getCurrentIdWithDecryptingKey() (*immclient.UserID, error) {
	id, err := websto.GetCurrentID()
	if err == nil {
		return id, nil
	}

	if err.Error() != "encrypted key" {
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
	doc := js.Global().Get("document")

	makeSwitchUserContent()

	var defaultTab js.Value
	id, err := getCurrentIdWithDecryptingKey()
	if err == nil {
		makeUserTab(id)
		defaultTab = doc.Call("getElementById", "userTab")
	} else {
		defaultTab = doc.Call("getElementById", "enrollTab")
	}
	defaultTab.Call("click")
}

func enroll(this js.Value, i []js.Value) interface{} {
	doc := js.Global().Get("document")
	username := doc.Call("getElementById", "username").Get("value").String()
	enSecret := doc.Call("getElementById", "secret").Get("value").String()
	doc.Call("getElementById", "secret").Set("value", "") // clear

	go func() {
		doc := js.Global().Get("document")
		loc := js.Global().Get("location")
		localStorage := js.Global().Get("localStorage")

		url := loc.Get("protocol").String() + "//" + loc.Get("host").String() 

		resultPara := doc.Call("getElementById", "result")
		resultPara.Set("innerHTML", "enroll " + username)

		id, err := immclient.EnrollUser(username, immclient.OneYear, enSecret, url)
		if err != nil {
			resultPara.Set("innerHTML", err.Error())
			return
		}
		resultPara.Set("innerHTML", "Success")

		// save certificate
		storeKeyPair(username, id)
		localStorage.Call("setItem", "lastUser", id.Name)

		makeUserTab(id)

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
		storeKeyPair("host " + hostname, hostID)

		// create a service
		url += immsrvPath
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
	list []*immclient.IdentityResponse
}

var caIDs = &caIdentities{lock: 0}
func updateListUserContent(){
	go func() {
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

		loc := js.Global().Get("location")
		url := loc.Get("protocol").String() + "//" + loc.Get("host").String()
		users, err := id.GetAllIdentities(url)
		if err != nil {
			print("error: getAllIdentities: " +  err.Error() + "\n")
			return
		}
		caIDs.list = users

		makeListUserInternal()
	}()
}

func makeListUserInternal(){
	doc := js.Global().Get("document")
	tableContent := doc.Call("getElementById", "userListTable")

	html := "<tr>"
	html += `  <td>#</td><td>Name</td><td>Type</td><td>Max Enrollments</td><td>Attributes</td> <td>Affilication</td>`
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
		html += "<td>" + user.Type + "</td>" // Type

		strMaxEnroll := "unlimited"
		if user.MaxEnrollments == -1 {
			strMaxEnroll = strconv.Itoa(user.MaxEnrollments)
		}
		html += "<td>" + strMaxEnroll + "</td>" // Max Enrollments

		html += "<td>"
		for _, attr := range user.Attributes {
			html += attr.Name + ":" + attr.Value + " enroll_cert:" + strconv.FormatBool(attr.ECert) + "<br>"
		}
		html += "</td>"

		html += "<td>" + user.Affiliation + "</td>" // Affiliation
		html += "</tr>"
	}

	tableContent.Set("innerHTML", html)
}

var updateTab = map[string] func() {
	"listUserContent": updateListUserContent,
	"switchUserContent": updateSwitchUserContent,
	"actionContent": updateActionContent,
	"storageSvcContent": updateStorageSvcContent,
	"storageGrpContent": updateStorageGrpContent,
	"immRecordLedgerContent": updateRecordLedgerContent,
	"immReadLedgerContent": updateReadLedgerContent,
	"userContent": updateUserContent,
}

func openTab(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")

	tabLevel := "1"
	if len(in) >= 2 {
		tabLevel = strconv.Itoa(in[1].Int())
	}
	
	tabContent := doc.Call("getElementsByClassName", "tabcontent " + tabLevel)
	len := tabContent.Length()
	for i := 0; i < len; i++ {
		tabContent.Index(i).Get("style").Set("display", "none")
	}

	tablinks := doc.Call("getElementsByClassName", "tablinks " + tabLevel)
	len = tablinks.Length()
	for i := 0; i < len; i++ {
		oldStr := tablinks.Index(i).Get("className")
		if oldStr.IsNull() {
			continue
		}
		
		tablinks.Index(i).Set("className", strings.Replace(oldStr.String(), " active", "", 1) )
	}

	target := in[0].Get("target")
	className := target.Get("className").String()
	target.Set("className", className + " active")


	contentId := strings.Replace(target.Get("id").String(), "Tab", "Content", 1)
	content := doc.Call("getElementById", contentId)
	if content.IsNull() {
		return nil
	}

	content.Get("style").Set("display", "block")


	updateTabFunc, ok := updateTab[contentId]
	if ok {
		updateTabFunc()
	}

	return nil
}

func makeSwitchUserContent() {
	doc := js.Global().Get("document")
	tabCon := doc.Call("getElementById", "switchUserContent")
	html := "<h3>Switch User</h3>\n"
	html += `
      <div class="cert-area" id="switchUserArea">
      </div>`

	tabCon.Set("innerHTML", html)
}

func switchUser(this js.Value, in []js.Value) interface{} {
	storage := js.Global().Get("localStorage")
	
	target := in[0].Get("target")
	username := target.Get("value").String()

	
	if target.Get("checked").Bool() == false {
		return nil
	}

	storage.Call("setItem", "lastUser", username)
	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}
	go makeUserTab(id)

	return nil
}

var switchUserContentLock = int32(0)
func updateSwitchUserContent() {
	go func(){
		if atomic.CompareAndSwapInt32(&switchUserContentLock, 0, 1) == false {
			return
		}
		defer func() { switchUserContentLock = 0 }()

		id, err := websto.GetCurrentID()
		curUsername := ""
		if err == nil {
			curUsername = id.Name
		}

		doc := js.Global().Get("document")
		swList := doc.Call("getElementById", "switchUserArea")

		html := "<p>Select a user:</p>"
		storage := js.Global().Get("localStorage")
		storageLen := storage.Length()
		for i := 0; i < storageLen; i++ {
			key := storage.Call("key", i).String()
			userName := strings.TrimSuffix(key, "-cert.pem")

			if key == userName {
				continue
			}
			if strings.HasPrefix(key, "host ") {
				continue
			}

			checked := ""
			if userName == curUsername {
				checked = "checked"
			}

			passRequired := ""
			if websto.IsPasswordRequired(userName) {
				passRequired = ":  password required"
			}
			
			html += `<label class="radioArea">` + userName + passRequired
			html += `  <input type="radio" onchange="switchUser(event)" name="clientUser" value="` +userName +`" ` +checked +">"
			html += `  <span class="radioBox"></span>`
			html += "</label>"
		}

		swList.Set("innerHTML", html)
	}()
}

func makeUserTab(id *immclient.UserID) {
	username := id.Name
	
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()

	doc := js.Global().Get("document")
	tabBtn := doc.Call("getElementById", "userTab")
	tabBtn.Set("hidden", false)
	tabBtn.Set("innerHTML", username)

	_, err := id.GetIdentity(url, username)
	hasRegistrarRoleF := err == nil

	userContent := doc.Call("getElementById", "userContent")
	html := "<h3>" + username + "</h3>\n"
	html += `<div class="tab">`
	if hasRegistrarRoleF {	
		html += `  <button class="tablinks 2" onclick="openTab(event, 2)" id="registerTab">Register</button>`
		html += `  <button class="tablinks 2" onclick="openTab(event, 2)" id="listUserTab">List User</button>`
	}
	
	html += `  <button class="tablinks 2" onclick="openTab(event, 2)" id="keyManageTab">Key Management</button>`
	html += `  <button class="tablinks 2" onclick="openTab(event, 2)" id="actionTab">Storage Service</button>`
	html += "</div>"

	if hasRegistrarRoleF {
		html += makeRegisterTab()
		html += makeListUserTab()
	}

	html += makeKeyManageTab()
	html += makeActionTab()

	userContent.Set("innerHTML", html)
}

func updateUserContent() {
	go func() {
		_, err := getCurrentIdWithDecryptingKey()
		if err != nil {
			doc := js.Global().Get("document")
			tabBtn := doc.Call("getElementById", "userTab")
			tabBtn.Set("hidden", true)

			userContent := doc.Call("getElementById", "userContent")
			userContent.Set("innerHTML", "")
		}
	}()
}

func makeRegisterTab() string {
	html := `
    <div class="tabcontent 2" id="registerContent">
      <div class="cert-area">
        <div class="row">
          <div class="cert-item"><label for="type">User type</label></div>
          <div class="cert-input">
            <select id="userType" onchange="selectedUserType()">
              <option value="AppUser">Application user</option>
              <option value="StorageAdmin">Storage service administrator</option>
              <option value="StorageGrpAdmin">Storage group administrator</option>
            </select>
          </div>
        </div>
        <div class="row">
          <div class="cert-item"><label for="registerName" id="registerNameLabel">User name</label></div>
          <div class="cert-input"><input type="text" id="registerName" oninput="inputtedRegisterName()"></div>
        </div>
        <div class="row" id="registerHostnameArea" hidden>
          <div class="cert-item"><label for="registerHost" id="registerHostLabel">Administration host</label></div>
          <div class="cert-input"><input type="text" id="registerHost" readonly="readonly"></div>
        </div>
        <div class="row" id="registerSecretArea">
          <div class="cert-item"><label for="registerSecret">Secret</label></div>
          <div class="cert-input"><input type="text" id="registerSecret"></div>
        </div>
        <div class="row" id="gencrlBox">
          <div class="cert-item"><label>CRL</label></div>
          <div class="cert-input"><label class="checkbox">available<input type="checkbox" id="gencrl"><span class="checkmark"></span> </label></div>
        </div>
        <div class="row">
          <div class="immDSBtn">
            <button onClick="register()" id="registerButton">Register</button>
          </div>
        </div>
        <div class="row">
          <p id="registerResult"></p>
        </div>
      </div>
    </div>`

	return html
}

func makeKeyManageTab() string {
	html := `<div class="tabcontent 2" id="keyManageContent">`
	html += `  <div class="cert-area">`
	
	html += `    <div class="row">`
	html += `      <div class="cert-item">`
	html += `        <div class="immDSBtn">`
	html += `          <button onclick="encryptKey(event)" id="encryptKeyBtn">Encrypt</button>`
	html += `        </div>`
	html += `      </div>`
	html += `      <div class="cert-input"><label>Private key</label></div>`
	html += `    </div>`
	
	html += `    <div class="row">`
	html += `      <div class="cert-item">`
	html += `        <div class="immDSBtn">`
	html += `          <button onclick="exportKey(event, 'private')" id="exportPrivKeyBtn">Export</button>`
	html += `          <a id="exportPrivKeyData"></a>`
	html += `        </div>`
	html += `      </div>`
	html += `      <div class="cert-input"><label>Private key</label></div>`
	html += `    </div>`

	html += `    <div class="row">`
	html += `      <div class="cert-item">`
	html += `        <div class="immDSBtn">`
	html += `          <button onclick="exportKey(event, 'certificate')" id="exportCertKeyBtn">Export</button>`
	html += `          <a id="exportCertKeyData"></a>`
	html += `        </div>`
	html += `      </div>`
	html += `      <div class="cert-input"><label>Certificate</label></div>`
	html += `    </div>`

	
	html += `  </div>`
	html += `</div>`
	return html
}

func makeListUserTab() string {
	html := `<div class="tabcontent 2" id="listUserContent">`
	html += `  <table id="userListTable">`
    html += "  </table>"
	html += "</div>"
	return html
}

func selectedUserType(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	userTypeSel := doc.Call("getElementById", "userType")
	userType := userTypeSel.Get("value").String()
	registerName := doc.Call("getElementById", "registerName")
	hostnameArea := doc.Call("getElementById", "registerHostnameArea")
	hostnameInput := doc.Call("getElementById", "registerHost")
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return nil
	}
	org, err := id.GetIssuerOrg()
	if err != nil {
		return nil
	}
	
	hostnameAreaHiddenF := true
	var hostname string
	if userType == "StorageGrpAdmin" {
		hostname = "storage-grp"
		hostnameAreaHiddenF = false
	}
	if userType == "StorageAdmin" {
		hostname = "storage"
		hostnameAreaHiddenF = false
	}
	if ! hostnameAreaHiddenF {
		registerName.Set("value", hostname)
		hostnameInput.Set("value", hostname + "." + org)
	}

	hostnameArea.Set("hidden", hostnameAreaHiddenF)
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

func register(this js.Value, in []js.Value) interface{}{
	doc := js.Global().Get("document")
	username := doc.Call("getElementById", "registerName").Get("value").String()
	hostname := doc.Call("getElementById", "registerHost").Get("value").String()
	secret := doc.Call("getElementById", "registerSecret").Get("value").String()
	userType := doc.Call("getElementById", "userType").Get("value").String()
	genCRLF := doc.Call("getElementById", "gencrl").Get("checked").Bool()
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()

	attrList := map[string] *struct{ou string; privilege *immclient.UserPrivilege}{
		"AppUser": {
			ou: "client",
			privilege: &immclient.UserPrivilege{
				GenCRL: genCRLF,
			},
		},
		"StorageAdmin": {
			ou: "peer",
			privilege: &immclient.UserPrivilege{
				GenCRL: genCRLF,
				StorageAdmin: hostname,
			},
		},
		"StorageGrpAdmin": {
			ou: "orderer",
			privilege: &immclient.UserPrivilege{
				GenCRL: genCRLF,
				StorageGrpAdmin: hostname,
			},
		},
	}

	go func() {
		result := doc.Call("getElementById", "registerResult")

		id, err := websto.GetCurrentID()
		if err != nil {
			result.Set("innerHTML", err.Error())
			return
		}

		attr, ok := attrList[userType]
		if ! ok {
			result.Set("innerHTML", "unexpected user type: " + err.Error())
			return
		}
		retSecret, err := id.Register(username, secret, "client", attr.privilege, url)
		if err != nil {
			result.Set("innerHTML", "Register username: " + err.Error())
			return
		}

		org, _ := id.GetIssuerOrg()
		if hostname == (username + "." + org) {
			retHostSecret, err := id.Register(hostname, retSecret, attr.ou, nil, url)
			if err != nil {
				result.Set("innerHTML", "unexpected response from the CA: " + err.Error())
				id.RemoveIdentity(url, username)
				return
			}
			if retHostSecret != retSecret {
				result.Set("innerHTML", "unexpected secret")
				id.RemoveIdentity(url, username)
				id.RemoveIdentity(url, hostname)
				return
			}
		}
		
		doc.Call("getElementById", "registerSecret").Set("value", retSecret)
		result.Set("innerHTML", "Success")
	}()

	return nil
}

func storeKeyPair(prefix string, id *immclient.UserID) {
	localStorage := js.Global().Get("localStorage")
	uint8Array := js.Global().Get("Uint8Array")

	certStorage := prefix + "-cert.pem"
	privStorage := prefix + "_sk"
	skiStorage := prefix + "_ski"
	
	privArray := uint8Array.New(len(id.Priv))
	js.CopyBytesToJS(privArray, id.Priv)
	localStorage.Call("setItem", privStorage, privArray)

	certArray := uint8Array.New(len(id.Cert))
	js.CopyBytesToJS(certArray, id.Cert)
	localStorage.Call("setItem", certStorage, certArray)
	
	localStorage.Call("setItem", skiStorage, id.SKI)
}

func makeActionTab() string {
	html := `<div class="tabcontent 2" id="actionContent">`
	html += "</div>"
	return html
}

func updateActionContent() {
	doc := js.Global().Get("document")
	actionContent := doc.Call("getElementById", "actionContent")

	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		var html, tab string
		if id.HasStorageAdmin() {
			html, tab = makeStorageSvcTab()
		}
		if id.HasStorageGrpAdmin() {
			html, tab = makeStorageGrpTab()
		}
		if html == "" {
			html = makeChaincodeTabs()
		}
		actionContent.Set("innerHTML", html)

		if tab == "" {
			return
		}
		
		svcTab := doc.Call("getElementById", tab)
		svcTab.Call("click")
	}()
}

func makeStorageSvcTab() (html, tab string) {
	tab = "storageSvcTab"
	html  = `<div class="space"></div>`
	html += `<div class="tab">`
	html += `  <button class="tablinks 3" onclick="openTab(event, 3)" id="`+tab+`">Administration</button>`
	html += "</div>"
	
	html += `<div class="tabcontent 3" id="storageSvcContent">`
	html += "</div>"
	return
}

func makeStorageGrpTab() (html, tab string) {
	tab = "storageGrpTab"
	html  = `<div class="space"></div>`
	html += `<div class="tab">`
	html += `  <button class="tablinks 3" onclick="openTab(event, 3)" id="`+tab+`">Administration</button>`
	html += "</div>"
	
	html += `<div class="tabcontent 3" id="storageGrpContent">`
	html += "</div>"
	return
}

func makeChaincodeTabs() string {
	html := `<div class="space"></div>`
	html += `<div class="tab">`
	html += `  <button class="tablinks 3" onclick="openTab(event, 3)" id="immRecordLedgerTab">Record Ledger</button>`
	html += `  <button class="tablinks 3" onclick="openTab(event, 3)" id="immReadLedgerTab">Read Ledger</button>`
	html += "</div>"
	
	html += `<div class="tabcontent 3" id="immRecordLedgerContent">`
	html += "</div>"

	html += `<div class="tabcontent 3" id="immReadLedgerContent">`
	html += "</div>"
	return html
}

var storageSvcContentLock = int32(0)
func updateStorageSvcContent() {
	doc := js.Global().Get("document")
	
	go func() {
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

		storageSvcContent := doc.Call("getElementById", "storageSvcContent")
		
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

		storageSvcContent.Set("innerHTML", html)
		updateStorageGrpState()
	}()
}

var exportServiceLock = int32(0)
func exportService(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

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
		

		loc := gl.Get("location")
		url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
		serviceData, err := id.ExportService(hostname, url)
		if err != nil {
			print("log: " + err.Error() + "\n")
			return
		}
		
		serviceDataArray := gl.Get("Uint8Array").New(len(serviceData))
		js.CopyBytesToJS(serviceDataArray, serviceData)
		
		blobType := gl.Get("Object").New()
        blobType.Set("type","application/octet-stream")
        tmpArray := gl.Get("Array").New(serviceDataArray)
        saveFile := gl.Get("Blob").New(tmpArray, blobType)
		print("log: type=" + saveFile.Get("type").String() + " " + "size=" + saveFile.Get("size").String() + "\n")
        saveUrl := gl.Get("URL").Call("createObjectURL", saveFile)
		saveFileName := hostname + "_service.dat"

		exportFile := doc.Call("getElementById", "exportServiceConf"+hostname)
        exportFile.Set("download", saveFileName)
        exportFile.Set("href", saveUrl)
		exportFile.Call("click")
	}()

	return nil
}

var storageGrpContentLock = int32(0)
func updateStorageGrpContent() {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	doc := js.Global().Get("document")

	print("log: updateStorageGrpContent\n")
	go func() {
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

		storageGrpCont := doc.Call("getElementById", "storageGrpContent")
		storageGrpCont.Set("innerHTML", html)

		updateAnchorPeers()
	}()
}

func updateAnchorPeers() {
	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		loc := js.Global().Get("location")
		url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
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
	}()
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

		loc := js.Global().Get("location")
		url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
		id.ImportService(peerData, url)
		updateAnchorPeers()
	}()

	return nil
}

var recordLedgerContentLock = int32(0)
func updateRecordLedgerContent() {
	print("log: updateRecordLedgerContent\n")
	doc := js.Global().Get("document")
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

	go func() {
		if atomic.CompareAndSwapInt32(&recordLedgerContentLock, 0, 1) == false {
			return
		}
		defer func() { recordLedgerContentLock = 0 }()

		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		storageGrpList, err := id.ListAvailableStorageGroup(url)
		if err != nil {
			return
		}
		if len(storageGrpList) < 1 {
			return
		}
		
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

		recordLedger := doc.Call("getElementById", "immRecordLedgerContent")
		recordLedger.Set("innerHTML", html)
		return
	}()
}

func selectedStorageGrp(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	
	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		history, err := id.ReadLedger(storageGrp, "prog1", url)
		if err != nil {
			print("log: could not read ledger: " + err.Error() + "\n")
			return
		}
	
		html := `<div class="immDSBtn">`
		html += `  <button onclick="saveLedger(event)">Save</button>`
		html += `  <a id="saveLedgerData"></a>`
		html += `</div>`
	
		html += `<table id="historyTable">`
		html += "<thread>"
		html += "<tr>"
		html += `  <th scope="col">#</th>`
//		html += `  <th scope="col">TxID</th>`
		html += `  <th scope="col">Timestamp</th>`
		html += `  <th scope="col">Log</th>`
		html += `  <th scope="col">Recorded storage</th>`
		html += `  <th scope="col">Creator</th>`
		html += `</tr>`
		html += "</thread>"

		instVal := &immclient.InstanceValue{}

		html += "<tbody>"
		for i, item := range *history {

			bEnvelope := &common.Envelope{}
			payload := &common.Payload{}
			chHdr := &common.ChannelHeader{}
			signHdr := &common.SignatureHeader{}
			foundTxIdF := false

			block, err := id.QueryBlockByTxID(storageGrp, item.TxId, url)
			if err != nil {
				print("error: could not read ledger: " + err.Error() + "\n")
				return
			}
			for _, blockData := range block.Data.Data {
				err = proto.Unmarshal(blockData, bEnvelope)
				if err != nil {
					print("error: unexpected block data: " + err.Error() + "\n")
					return
				}

				err = proto.Unmarshal(bEnvelope.Payload, payload)
				if err != nil {
					print("error: unexpected block payload: " + err.Error() + "\n")
					return
				}
				err = proto.Unmarshal(payload.Header.ChannelHeader, chHdr)
				if err != nil {
					print("error: unexpected channel header: " + err.Error() + "\n")
					return
				}
				
				foundTxIdF = (chHdr.TxId == item.TxId)
				if foundTxIdF {
					break
				}
			}
			if !foundTxIdF {
				print("error: not found TxId: " + item.TxId + "\n")
				return
			}

			err = proto.Unmarshal(payload.Header.SignatureHeader, signHdr)
			if err != nil {
				print("error: unexpected signature header: " + err.Error() + "\n")
				return
			}
			creator := &msp.SerializedIdentity{}
			err = proto.Unmarshal(signHdr.Creator, creator)
			if err != nil {
				print("log: failed to unmarshal creator: " + err.Error() + "\n")
				return
			}
			creatorPem, _ := pem.Decode(creator.IdBytes)
			creatorCert, err := x509.ParseCertificate(creatorPem.Bytes)
			if err != nil {
				print(err.Error() + "\n")
				continue
			}

			chExt := &pp.ChaincodeHeaderExtension{}
			err = proto.Unmarshal(chHdr.Extension, chExt)
			if err != nil {
				print("error: chaincode header: " + err.Error() + "\n")
				return
			}
			
			trans := &pp.Transaction{}
			err = proto.Unmarshal(payload.Data, trans)
			if err != nil {
				print(err.Error()+"\n")
				return
			}
			ccAction := &pp.ChaincodeActionPayload{}
			err = proto.Unmarshal(trans.Actions[0].Payload, ccAction)
			if err != nil {
				print(err.Error()+"\n")
				return
			}

/*
			ccProposal := &pp.ChaincodeProposalPayload{}
			err = proto.Unmarshal(ccAction.ChaincodeProposalPayload, ccProposal)
			if err != nil {
				print(err.Error() + "\n")
				return
			}
			ccInvocationSpec := &pp.ChaincodeInvocationSpec{}
			err = proto.Unmarshal(ccProposal.Input, ccInvocationSpec)
			if err != nil {
				print(err.Error() + "\n")
				return
			}
*/
			proposalRsp := &pp.ProposalResponsePayload{}
			err = proto.Unmarshal(ccAction.Action.ProposalResponsePayload, proposalRsp)
			if err != nil {
				print(err.Error()+"\n")
				return
			}
			
			
//			print("log: block:\n%s\n", hex.Dump(blockRaw))

			html += "<tr>"
			html += `<td>` + strconv.Itoa(i+1) + "</td>"
//			html += "<td>" + item.TxId + "</td>" // transaction id
			t := time.Unix(item.Timestamp.GetSeconds(), int64(item.Timestamp.GetNanos()))
			html += `<td>` + t.Local().Format(time.UnixDate) + "</td>"
			json.Unmarshal(item.Value, instVal)
			html += "<td>" + string(instVal.Log) + "</td>" // Log

			html += "<td>"
			sId := &msp.SerializedIdentity{}
			for endorserN, endorser := range ccAction.Action.Endorsements {
				err = proto.Unmarshal(endorser.Endorser, sId)
				if err != nil {
					print(err.Error()+"\n")
					return
				}
				
				p, _ := pem.Decode(sId.IdBytes)
				if p.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(p.Bytes)
				if err != nil {
					print(err.Error()+"\n")
					continue
				}

				if endorserN != 0 {
					html += "<br>"
				}
				html += cert.Subject.CommonName
			}
			html += "</td>"
			html += "<td>" + creatorCert.Subject.CommonName + "</td>"

			html += "</tr>"
		}
		html += "</tbody>"
		html += "</table>"

		readLedgerList := doc.Call("getElementById", "readLedgerList")
		readLedgerList.Set("innerHTML", html)
	}()

	return nil
}

func recordLedger(this js.Value, in []js.Value) interface{} {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		recordLogText := doc.Call("getElementById", "recordLedgerText").Get("value").String()
		if recordLogText == "" {
			return
		}

		err = id.RecordLedger(storageGrp, "prog1", recordLogText, url)
		if err != nil {
			print("log: failed to record ledger")
			return
		}
	}()

	return nil
}

var readLedgerContentLock = int32(0)
func updateReadLedgerContent() {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	doc := js.Global().Get("document")

	go func() {
		if atomic.CompareAndSwapInt32(&readLedgerContentLock, 0, 1) == false {
			return
		}
		defer func() { readLedgerContentLock = 0 }()

		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		storageGrpList, err := id.ListAvailableStorageGroup(url)
		if err != nil {
			return
		}
		if len(storageGrpList) < 1 {
			return
		}
		
		html := `<div class="cert-area">`
		html += `<div class="row">`
		
		html += `  <div class="cert-item"><label for="storageGrp">Storage group</label></div>`
		html += `  <div class="cert-input">`
		html += `    <select id="readStorageGrp" onchange="selectedStorageGrp()">`
		html += `      <option disabled selected value> -- select storage group -- </option>`
		for _, storageGrp := range storageGrpList {
			html += `      <option value="`+storageGrp+`">`+storageGrp+`</option>`
		}
		html += `    </select>`
		html += `  </div>`
		html += `</div>`
		
		html += `<div class="row" id="readLedgerList">`
		html += `</div>`
		html += `</div>`
		
		recordLedger := doc.Call("getElementById", "immReadLedgerContent")
		recordLedger.Set("innerHTML", html)
	}()
}	

func removeService(this js.Value, in []js.Value) interface{} {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
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
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

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

		resultBox, okBtn := makeJoinChannelBoxContent()
		err = id.JoinChannel(block, url)
		
		resultHtml := "Success"
		if err != nil {
			print("JoinChannel error: " + err.Error() + "\n")
			resultHtml = "Failed to join: " + err.Error()
		}
		
		okBtn.Set("hidden", false)
		resultBox.Set("innerHTML", resultHtml)
		
		updateStorageGrpState()
	}()

	return nil
}

func updateStorageGrpState() {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	gl := js.Global()
	doc := gl.Get("document")

	go func() {
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
	}()
}

func makeJoinChannelBoxContent() (resultBox, okBtn js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	
	html := `<div class="passReqArea">`
	html += `  <div class="immDSBtn">`
	html += `    <p id="joinChannelResult">Join task is in progress</p>`
	html += `    <button onclick="reqBoxOk(event, 'confirmMsg')" id="reqBoxOkBtn" hidden>Ok</button>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")

	resultBox = doc.Call("getElementById", "joinChannelResult") 
	okBtn = doc.Call("getElementById", "reqBoxOkBtn")
	return
}


var exportChannelLock = int32(0)
func exportChannel(this js.Value, in []js.Value) interface{} {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	gl := js.Global()
	doc := gl.Get("document")

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

		blockDataArray := gl.Get("Uint8Array").New(len(block))
		js.CopyBytesToJS(blockDataArray, block)
		
		blobType := gl.Get("Object").New()
        blobType.Set("type","application/octet-stream")
        tmpArray := gl.Get("Array").New(blockDataArray)
        saveFile := gl.Get("Blob").New(tmpArray, blobType)
		print("log: type=" + saveFile.Get("type").String() + " " + "size=" + saveFile.Get("size").String() + "\n")
        saveUrl := gl.Get("URL").Call("createObjectURL", saveFile)
		saveFileName := chName + ".block"

		exportFile := doc.Call("getElementById", "exportChannelData")
        exportFile.Set("download", saveFileName)
        exportFile.Set("href", saveUrl)
		exportFile.Call("click")
	}()

	return nil
}

var enableChannelLock = int32(0)
func enableChannel(this js.Value, in []js.Value) interface{} {
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath
	
	target := in[0].Get("target")
	chName := target.Get("name").String()

	go func() {
		if atomic.CompareAndSwapInt32(&enableChannelLock, 0, 1) == false {
			return
		}
		defer func() { enableChannelLock = 0 }()

		resultBox, okBtn := makeEnableChannelBoxContent()
		resultHtml := "Success"
		defer func() {
			okBtn.Set("hidden", false)
			resultBox.Set("innerHTML", resultHtml)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			resultHtml = "Failed to enable storage: " + err.Error()
			return
		}
		if ! id.HasStorageAdmin() {
			resultHtml = "Permission denied"
			return
		}

		err = id.ActivateChannel(url, chName)
		if err != nil {
			resultHtml = "Failed to activate storage: " + err.Error()
			print("log: error: " + err.Error())
			return
		}
		
		chainCode, err := id.ListChainCodeInPeer(url)
		if err != nil {
			resultHtml = "Internal error: avaliable plugin is not found: " + err.Error()
			print("log: " + err.Error() + "\n")
			return
		}
		
		if len(chainCode) <= 0 {
			err = id.InstallChainCode(url)
			if err != nil {
				resultHtml = "Could not load a plugin: " + err.Error()
				print("log: " + err.Error() + "\n")
				return
			}
		}

		err = id.InstantiateChainCode(url, chName)
		if err != nil {
			resultHtml = "Failed to instantiate a plugin: " + err.Error()
			print("log: " + err.Error() + "\n")
			return
		}
	}()

	return nil
}

func makeEnableChannelBoxContent() (resultBox, okBtn js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	
	html := `<div class="passReqArea">`
	html += `  <div class="immDSBtn">`
	html += `    <p id="enableChannelResult">Enabling storage is in progress</p>`
	html += `    <button onclick="reqBoxOk(event, 'confirmEnChMsg')" id="reqBoxOkBtn" hidden>Ok</button>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")

	resultBox = doc.Call("getElementById", "enableChannelResult") 
	okBtn = doc.Call("getElementById", "reqBoxOkBtn")
	return
}

func confirmEnChMsgOk(in []js.Value){
	closeReqBox(in)
	updateStorageGrpState()
}


var saveLedgerLock = int32(0)
func saveLedger(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		if atomic.CompareAndSwapInt32(&saveLedgerLock, 0, 1) == false {
			return
		}
		defer func() { saveLedgerLock = 0 }()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}
		
		history, err := id.ReadLedger(storageGrp, "prog1", url)
		if err != nil {
			print("log: could not read ledger: " + err.Error() + "\n")
			return
		}
		
		var blocks []*common.Block
		for i, item := range *history {
			block, err := id.QueryBlockByTxID(storageGrp, item.TxId, url)
			if err != nil {
				print("log: could not read ledger: " + err.Error() + "\n")
				return
			}

			if i != 0 && (i % 2048) == 0 {
				ledgerFileName := "ledger_prog1_" + strconv.Itoa(i - 2048) + ".blocks"
				saveLedgerFile(ledgerFileName, blocks)
				blocks = blocks[:0]
			}
			blocks = append(blocks, block)
		}
		
		ledgerFileName := "ledger_prog1_" + strconv.Itoa( (len(*history)/2048)*2048 ) + ".blocks"
		saveLedgerFile(ledgerFileName, blocks)
	}()

	return nil
}

func saveFile(fileName string, fileData []byte, downloadUrlElem string) {
	gl := js.Global()
	doc := gl.Get("document")	
	
	fileDataArray :=  gl.Get("Uint8Array").New(len(fileData))
	js.CopyBytesToJS(fileDataArray, fileData)
	
	blobType := gl.Get("Object").New()
	blobType.Set("type","application/octet-stream")
	tmpArray := gl.Get("Array").New(fileDataArray)
	saveFile := gl.Get("Blob").New(tmpArray, blobType)
	print("log: type=" + saveFile.Get("type").String() + " " + "size=" + saveFile.Get("size").String() + "\n")
	saveUrl := gl.Get("URL").Call("createObjectURL", saveFile)

	exportFile := doc.Call("getElementById", downloadUrlElem)
	exportFile.Set("download", fileName)
	exportFile.Set("href", saveUrl)
	exportFile.Call("click")
}

func saveLedgerFile(fileName string, blocks []*common.Block) {
	var buf []byte

	for _, block := range blocks {
		blockRaw, err := proto.Marshal(block)
		if err != nil {
			print("log: failed to marshal blocks: " + err.Error() + "\n")
			return
		}
		
		blockLen := len(blockRaw)
		blockLenRaw := []byte{ byte(blockLen), byte(blockLen>>8), byte(blockLen>>16), byte(blockLen>>24) }

		buf = append(buf, blockLenRaw...)
		buf = append(buf, blockRaw...)
	}
	
	saveFile(fileName, buf, "saveLedgerData")
}

func dropdownIDFunc(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

//	target := in[0].Get("target")
	userID := in[1].String()

	//	print("dropdown: " + userID + "\n")

	dropdownContents := doc.Call("getElementsByClassName", "dropdownContent")
	len := dropdownContents.Length()
	for i := 0; i < len; i++ {
		dropdownContents.Index(i).Get("style").Set("display", "none")
	}

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


func makeRemoveIdBoxContent(userName string) {
	gl := js.Global()
	doc := gl.Get("document")
	
	html := `<div class="passReqArea">`
	html += `  <label>Are you sure you want to remove ` + userName + `?</label>`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'removeId')" id="reqBoxOkBtn" name="` + userName+ `">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'removeId')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="cryptResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")		
}

func removeIdOk(in []js.Value) {
	gl := js.Global()
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	target := in[0].Get("target")
	userName := target.Get("name").String()
	print("log: remove userName=" + userName + "\n")
	id.RemoveIdentity(url, userName)
	
	caIDs.execUser = ""
	updateListUserContent()

	closeReqBox(in)
}

func removeID(this js.Value, in []js.Value) interface{} {
	closeDropdownContents()
	userID := in[0].String()
	//	print("removeID: " + userID + "\n")
	makeRemoveIdBoxContent(userID)
	return nil
}

func makeRevokeIdBoxContent(userName string) {
	gl := js.Global()
	doc := gl.Get("document")
	
	html := `<div class="passReqArea">`
	html += `  <label>Are you sure you want to revoke ` + userName + `?</label>`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'revokeId')" id="reqBoxOkBtn" name="` + userName+ `">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'revokeId')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="cryptResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")		
}

func revokeIdOk(in []js.Value) {
	defer closeReqBox(in)
	
	gl := js.Global()
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	target := in[0].Get("target")
	userName := target.Get("name").String()
	print("log: revoke userName=" + userName + "\n")
	id.RevokeIdentity(url, userName)
	
	caIDs.execUser = ""
	updateListUserContent()
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
	gl := js.Global()
	doc := gl.Get("document")

	newSecret := immclient.RandStr(8)
	html := `<div class="passReqArea">`
	html += `  <label>Please enter new secret:</label>`
	html += `  <input type="text" id="changeSecretText" value="` + newSecret + `">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, 'changeSecret')" id="reqBoxOkBtn" name="` + userName + `">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, 'changeSecret')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="changeSecretResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")		
}

func changeSecretOk(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()	

	target := in[0].Get("target")
	userName := target.Get("name").String()
	
	newSecret := doc.Call("getElementById", "changeSecretText").Get("value").String()
	if newSecret == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "changeSecretResult")
	
	id, err := websto.GetCurrentID()
	if err != nil {
		result.Set("innerHTML", "failed to change the secret: " + err.Error())
		return
	}
	
	_, err = id.ChangeSecret(url, userName, newSecret)
	if err != nil {
		result.Set("innerHTML", "failed to change the secret: " + err.Error())
		return
	}
	closeReqBox(in)
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

		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		if keyType == "private" {
			saveFile(id.Name+"_sk", id.Priv, "exportPrivKeyData")
			return
		}

		if keyType == "certificate" {
			saveFile(id.Name+"-cert.pem", id.Cert, "exportCertKeyData")
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
	gl := js.Global()
	doc := gl.Get("document")

	userName, err := websto.GetCurrentUsername()
	if err != nil {
		return
	}

	html := `<div class="passReqArea">`
	html += `  <label>Please enter ` + userName + `'s password</label>`
	html += `  <input type="password" id="keyPassword">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOk(event, '` + reqStr + `')" id="reqBoxOkBtn">Ok</button>`
	html += `    <button onclick="reqBoxCancel(event, '` + reqStr + `')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="cryptResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")	
}

func makeEncryptionReqBoxContent() {
	makeReqBoxContent("encrypt")
}

var decryptKeyCh chan error
func makeDecryptionReqBoxContent(err chan error) {
	decryptKeyCh = err
	makeReqBoxContent("decrypt")
}

var reqBoxFunc = map[string] func([]js.Value) {
	"encryptOk": encryptOk,
	"encryptCancel": closeReqBox,
	"decryptOk": decryptOk,
	"decryptCancel": decryptCancel,
	"removeIdOk": removeIdOk,
	"removeIdCancel": closeReqBox,
	"revokeIdOk": revokeIdOk,
	"revokeIdCancel": closeReqBox,
	"changeSecretOk": changeSecretOk,
	"changeSecretCancel": closeReqBox,
	"confirmMsgOk": closeReqBox,
	"confirmEnChMsgOk": confirmEnChMsgOk,
}

func closeReqBox(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "none")	
}

func encryptOk(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	keyPass := doc.Call("getElementById", "keyPassword").Get("value").String()
	if keyPass == "" {
		return // ignore
	}
	websto.EncryptKey(keyPass)

	closeReqBox(in)
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

	closeReqBox(in)
}

func decryptCancel(in []js.Value) {
	decryptKeyCh <- errors.New("cancel")
	closeReqBox(in)
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

func reqBoxOk(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "Ok")
}

func reqBoxCancel(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "Cancel")
}
