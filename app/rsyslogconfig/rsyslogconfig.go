/*
Copyright Hitachi, Ltd. 2023 All Rights Reserved.

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
	"google.golang.org/protobuf/proto"
	
	"websto"
	wu "webutil"
	"immadmin"
	"rwlog"
	"immclient"
	"immblock"
)

const (
	saveLedgerDataID = "saveLedgerData"
)

func main() {
	ch := make(chan struct{}, 0)
	registerCallback()
	makeContent()
	<- ch
}

func registerCallback() {
	gl := js.Global()
	wu.InitTab("openTab")
	wu.RegisterTab("mainPage", gotoMainPageContent)
	wu.RegisterTab("appRsyslogConfig", updateRsyslogConfigContent)

	wu.RegisterTab("createRsyslogd", updateCreateRsyslogdContent)
	gl.Set("createRsyslogdEnv", js.FuncOf(createRsyslogdEnv))
	wu.RegisterTab("logViewer", updateLogViewerContent)
	gl.Set("selectedStorageGrp", js.FuncOf(selectedStorageGrp))
	gl.Set("selectedKeyInStorageGrp", js.FuncOf(selectedKeyInStorageGrp))
	gl.Set("saveLedger", js.FuncOf(saveLedger))
	wu.RegisterTab("verification", updateVerificationContent)
	
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
}

func makeContent() {
	doc := js.Global().Get("document")
	rsyslogConfigContent := doc.Call("getElementById", "rsyslogconfigContent")
	
	tabHTML := wu.Tabs["mainPage"].MakeHTML("<<", "1")
	defaultTab := wu.Tabs["appRsyslogConfig"]	
	tabHTML.AppendTab(defaultTab.MakeHTML("Rsyslogd", "1"))
	html := tabHTML.MakeHTML()
	rsyslogConfigContent.Set("innerHTML", html)

	defaultTab.GetButton().Call("click")
}

func gotoMainPageContent(tabC *js.Value) {
	gl := js.Global()
	loc := gl.Get("location")
	mainPageURL := loc.Get("protocol").String()+"//"+loc.Get("host").String()
	loc.Call("replace", mainPageURL)
}

func updateRsyslogConfigContent(tabC *js.Value) {
	var err error
	html := ""
	defaultTab := wu.Tabs["createRsyslogd"]

	defer func() {
		tabC.Set("innerHTML", html)
		if err != nil {
			return
		}
		
		defaultTab.GetButton().Call("click")
	}()

	id, err := websto.GetCurrentID()
	if err != nil {
		html += "<h3>You are invalid user</h3>"
		return
	}

	html += "<h3>" + id.Name + "</h3>"
	html += `<div class="space"></div>`

	tabHTML := &wu.TabHTML{}
	tabHTML.AppendTab(defaultTab.MakeHTML("Configuration", "2"))
	tabHTML.AppendTab(wu.Tabs["logViewer"].MakeHTML("Viewer", "2"))
	tabHTML.AppendTab(wu.Tabs["verification"].MakeHTML("Verification", "2"))
	html += tabHTML.MakeHTML()
	return
}

func updateCreateRsyslogdContent(tabC *js.Value) {
	html := ""
	errMsg := ""

	defer func() {
		if errMsg != "" {
			wu.VisibleMsgBox(errMsg)
			return
		}
		
		tabC.Set("innerHTML", html)
	}()

	id, err := websto.GetCurrentID()
	if err != nil {
		errMsg = "You are invalid user"
		return
	}

	url := wu.GetImmsrvURL()
	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil {
		errMsg = "There is no group in your storage: " + err.Error()
		return
	}
	if len(storageGrpList) < 1 {
		errMsg = "There is no group in your storage."
		return
	}

	items := wu.InitItems()
	items.AppendSelectList("storageGrp", "Select a storage group for the rsyslogd", storageGrpList)
	items.AppendTextInput("rsysloguser", "Rsyslog username", "rsysloguser1", "")
	items.AppendTextInput("loggingCond", "Logging Condition", `$syslogfacility-text == &quot;local7&quot;`, "")
	items.AppendTextInput("loggingKey",  "Logging Key", "logprogram1", "")
	items.AppendButton("Create an environment", "createRsyslogdEnv")
	html = items.MakeHTML()
	return	
}

func createRsyslogdEnv(this js.Value, in []js.Value) interface{} {
	wu.VisibleSimpleMsgBox("Creating...")
	
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	username := doc.Call("getElementById", "rsysloguser").Get("value").String()
	storageGrp := doc.Call("getElementById", "storageGrp").Get("value").String()

	loggingCond := doc.Call("getElementById", "loggingCond").Get("value").String()
	loggingKey := doc.Call("getElementById", "loggingKey").Get("value").String()

	go func() {
		msg := "Success"
		defer func() {
			wu.VisibleMsgBox(msg)
		}()

		id, err := websto.GetCurrentID()
		if err != nil {
			msg = "You are invalid user: " + err.Error()
			return
		}

		err = immadmin.CreateRsyslogEnv(id, url, storageGrp, username, loggingCond, loggingKey)
		if err != nil {
			msg = err.Error()
			return
		}
	}()

	return nil
}

func updateLogViewerOrVerificationContent(tabC *js.Value) {
	url := wu.GetImmsrvURL()

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

	storageGrpL := []wu.SelectOptList{
		{`" disabled selected="`, " -- select storage group -- "},
	}
	for _, storageGrp := range storageGrpList {
		storageGrpL = append(storageGrpL, wu.SelectOptList{storageGrp, storageGrp})
	}

	items := wu.InitItems()
	items.AppendSelectListWithFunc("readStorageGrp", "Storage group", "selectedStorageGrp", storageGrpL)
	items.AppendHTML(`<div id="keyList"></div>`)
	items.AppendHTML(`<div id="readLedgerList"></div>`)
	html := items.MakeHTML()
	tabC.Set("innerHTML", html)
}

func updateLogViewerContent(tabC *js.Value) {
	wu.Tabs["verification"].GetContent().Set("innerHTML", "") // clear
	updateLogViewerOrVerificationContent(tabC)
}


func selectedStorageGrp(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()
	keyListDiv := doc.Call("getElementById", "keyList")

	go func() {
		html := ""
		errMsg := ""
		defer func() {
			keyListDiv.Set("innerHTML", html)
			if errMsg == "" {
				return
			}

			readLedgerList := doc.Call("getElementById", "readLedgerList")
			readLedgerList.Set("innerHTML", html)
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			errMsg = "You are invalid user: " + err.Error()
			return
		}

		tmpID, err := immadmin.CreateTmpUserWithGrpPrivilege(id, url, storageGrp)
		if err != nil {
			errMsg = err.Error()
			return
		}
		defer func() {
			id.RemoveIdentity(url, tmpID.Name)
		}()
		
		keys, err := immadmin.ListKeyInStorageGrp(tmpID, url)
		if err != nil {
			errMsg = err.Error()
			return
		}
		if len(keys) < 1 {
			errMsg = "There is no key in this storage group"
			return
		}

		keyL := []wu.SelectOptList{
			{`" disabled selected="`, " -- select a key -- "},
		}
		for _, key := range keys {
			keyL = append(keyL, wu.SelectOptList{key, key})
		}
		items := wu.InitItems()
		items.AppendSelectListWithFunc("rkey", "Select a key", "selectedKeyInStorageGrp", keyL)
		html = items.GetHTML()
	}()

	return nil
}

func selectedKeyInStorageGrp(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()

	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()
	
	keySel := doc.Call("getElementById", "rkey")
	rkey := keySel.Get("value").String()

	readLedgerList := doc.Call("getElementById", "readLedgerList")
	
	go func() {
		html := ""
		errMsg := ""
		defer func() {
			readLedgerList.Set("innerHTML", html)
			if errMsg == "" {
				return
			}
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			errMsg = "You are invalid user: " + err.Error()
			return
		}

		tmpID, err := immadmin.CreateTmpUserWithGrpPrivilege(id, url, storageGrp)
		if err != nil {
			errMsg = err.Error()
			return
		}
		defer func() {
			id.RemoveIdentity(url, tmpID.Name)
		}()

		logViewerContentSt := wu.Tabs["logViewer"].GetContent().Get("style").Get("display").String()
		if logViewerContentSt == "block" {
			var ledgerHTML string
			ledgerHTML, errMsg = rwlog.PrintLedger(tmpID, url, storageGrp, rkey)
			if errMsg != "" {
				return
			}

			items := wu.InitItems()
			items.AppendSaveFileButton(saveLedgerDataID, "Save", "saveLedger", "")
			html += items.GetHTML()
			html += ledgerHTML
			return // success
		}

		// verification content
		html, errMsg = getVerifyBlockHTML(tmpID, url, storageGrp, rkey)
		return
	}()

	return nil
}

func saveLedger(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()

	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()
	
	keySel := doc.Call("getElementById", "rkey")
	rkey := keySel.Get("value").String()

	go func() {
		errMsg := ""
		defer func() {
			if errMsg == "" {
				return
			}
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			errMsg = "You are invalid user: " + err.Error()
			return
		}

		tmpID, err := immadmin.CreateTmpUserWithGrpPrivilege(id, url, storageGrp)
		if err != nil {
			errMsg = err.Error()
			return
		}
		defer func() {
			id.RemoveIdentity(url, tmpID.Name)
		}()

		errMsg = rwlog.SaveLedger(tmpID, url, storageGrp, rkey, saveLedgerDataID)
	}()

	return nil
}

func updateVerificationContent(tabC *js.Value) {
	wu.Tabs["logViewer"].GetContent().Set("innerHTML", "")//clear
	updateLogViewerOrVerificationContent(tabC)
}

func getVerifyBlockHTML(id *immclient.UserID, url, storageGrp, rkey string) (html, errMsg string) {
	history, err := id.ListTxId(storageGrp, rkey, url)
	if err != nil {
		errMsg = "error: could not read logs: " + err.Error()
		return
	}

	var blocks []byte
	for i, txid := range *history {
		if i >= 2048 {
			errMsg = "error: too long history"
			return
		}
		
		block, err := id.QueryBlockByTxID(storageGrp, txid, url)
		if err != nil {
			errMsg = "error: could not read a block for the " + txid + ": " + err.Error()
			return
		}

		blockRaw, err := proto.Marshal(block)
		if err != nil {
			errMsg = "error: failed to marshal a block: " + err.Error()
			return
		}

		blockLen := len(blockRaw)
		blockLenRaw := []byte{ byte(blockLen), byte(blockLen>>8), byte(blockLen>>16), byte(blockLen>>24) }
		blocks = append(blocks, blockLenRaw...)
		blocks = append(blocks, blockRaw...)
	}

	html = `<table id="blockTable">`
	html += "<thread>"
	html += "<tr>"
	html += `  <th scope="col">Blocks</th>`
	html += `</tr>`
	html += `</thread>`
	html += `<tbody>`
	
	immblock.BLOCK_PREFIX = "<tr><td>"
	immblock.LB = "<br>"
	immblock.BLOCK_SUFFIX = "</tr></td>"
	str, err := immblock.ReadBlocks(blocks)
	if err != nil {
		errMsg = err.Error()
		return
	}
	html += str
	
	html += "</tbody>"
	html += "</table>"
	return // success
}
