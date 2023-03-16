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

package main

import (
	"syscall/js"
	"sync/atomic"

	"websto"
	wu "webutil"
	"rwlog"
)

const (
	RKEY = "prog1"
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
	gl.Set("selectedStorageGrp", js.FuncOf(selectedStorageGrp))
	gl.Set("recordLedger", js.FuncOf(recordLedger))
	gl.Set("saveLedger", js.FuncOf(saveLedger))

	wu.InitTab("openTab")
	wu.RegisterTab("mainPage", gotoMainPageContent)
	wu.RegisterTab("appReadWriteLog", updateAppReadWriteLogContent)
	wu.RegisterTab("recordLedger", updateRecordLedgerContent)
	wu.RegisterTab("readLedger", updateReadLedgerContent)
	
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
}

func makeContent() {
	doc := js.Global().Get("document")
	rdwtLogContent := doc.Call("getElementById", "readWriteLogContent")

	tabHTML := wu.Tabs["mainPage"].MakeHTML("<<", "1")
	defaultTab := wu.Tabs["appReadWriteLog"]
	tabHTML.AppendTab(defaultTab.MakeHTML("Read and Write Log", "1"))
	html := tabHTML.MakeHTML()
	rdwtLogContent.Set("innerHTML", html)

	defaultTab.GetButton().Call("click")
}

func gotoMainPageContent(tabC *js.Value) {
	gl := js.Global()
	loc := gl.Get("location")
	mainPageURL := loc.Get("protocol").String()+"//"+loc.Get("host").String()
	loc.Call("replace", mainPageURL)
}

func updateAppReadWriteLogContent(tabC *js.Value) {
	html := ""
		
	defer func() {
		tabC.Set("innerHTML", html)
	}()
		
	id, err := websto.GetCurrentID()
	if err != nil {
		html += "<h3>You are invalid user</h3>"
		return
	}
		
	html += "<h3>" + id.Name + "</h3>"
	html += `<div class="space"></div>`

	tabHTML := &wu.TabHTML{}
	tabHTML.AppendTab(wu.Tabs["recordLedger"].MakeHTML("Write Log", "2"))
	tabHTML.AppendTab(wu.Tabs["readLedger"].MakeHTML("Read Log", "2"))
	html += tabHTML.MakeHTML()
	return
}

var recordLedgerContentLock = int32(0)
func updateRecordLedgerContent(tabC *js.Value) {
	url := wu.GetImmsrvURL()

	if atomic.CompareAndSwapInt32(&recordLedgerContentLock, 0, 1) == false {
		return
	}
	defer func() { recordLedgerContentLock = 0 }()

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
	items.AppendSelectList("recordStorageGrp", "Storage group", storageGrpList)
	items.AppendTextInput("recordLedgerText", "Ledger", "", "")
	items.AppendButton("Record", "recordLedger")
	tabC.Set("innerHTML", items.MakeHTML())
	return
}

func selectedStorageGrp(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

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


		items := wu.InitItems()
		items.AppendSaveFileButton(saveLedgerDataID, "Save", "saveLedger", "")
		html := items.GetHTML()
		
		var ledgerHTML string
		ledgerHTML, errMsg = rwlog.PrintLedger(id, url, storageGrp, RKEY)
		if errMsg != "" {
			return
		}
		html += ledgerHTML

		readLedgerList := doc.Call("getElementById", "readLedgerList")
		readLedgerList.Set("innerHTML", html)
	}()

	return nil
}


func recordLedger(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

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

		recordLogText := doc.Call("getElementById", "recordLedgerText").Get("value").String()
		if recordLogText == "" {
			errMsg = "empty log"
			return // ignore
		}

		wu.VisibleSimpleMsgBox("Writing...")
		err = id.RecordLedger(storageGrp, RKEY, recordLogText, url)
		if err != nil {
			errMsg = "error: failed to record a prog1 log: " + err.Error()
			return
		}

		errMsg = "Success" // success
	}()

	return nil
}

var readLedgerContentLock = int32(0)
func updateReadLedgerContent(tabC *js.Value) {
	url := wu.GetImmsrvURL()

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

	storageGrpL := []wu.SelectOptList{
		{`" disabled selected="`, " -- select storage group -- "},
	}
	for _, storageGrp := range storageGrpList {
		storageGrpL = append(storageGrpL, wu.SelectOptList{storageGrp, storageGrp})
	}

	items := wu.InitItems()
	items.AppendSelectListWithFunc("readStorageGrp", "Storage group", "selectedStorageGrp", storageGrpL)
	items.AppendHTML(`<div class="row" id="readLedgerList"></div>`)
	html := items.MakeHTML()
	tabC.Set("innerHTML", html)
}	


var saveLedgerLock = int32(0)
func saveLedger(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()

	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		if atomic.CompareAndSwapInt32(&saveLedgerLock, 0, 1) == false {
			return
		}
		defer func() { saveLedgerLock = 0 }()

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

		errMsg = rwlog.SaveLedger(id, url, storageGrp, RKEY, saveLedgerDataID)
	}()

	return nil
}
