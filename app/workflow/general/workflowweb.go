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
	"strconv"
	"strings"
	"syscall/js"
	"crypto/rand"
	
	"websto"
	wu "webutil"
	"st2loginweb"
	"st2do"
)

const (
	ST2DO_PATH = "/st2do"
)

func main() {
	ch := make(chan struct{}, 0)
	registerCallback()
	makeContent()
	<- ch
}

func registerCallback() {
	gl := js.Global()
	gl.Set("selectedFile", js.FuncOf(selectedFile))
	
	wu.InitTab("openTab")
	wu.RegisterTab("mainPage", gotoMainPageContent)
	wu.RegisterTab("appWorkflow", updateWorkflowContent)
	wu.RegisterTab("pendingTask", updatePendingTaskContent)
	wu.RegisterTab("approvalReq", updateApprovalReqContent)
	wu.RegisterTab("myMsgBox", updateMyMsgBoxContent)
	wu.RegisterTab("login", updateLoginContent)
	wu.RegisterTab("myAttr", updateMyAttrContent)	
	
	
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
	wu.AppendReqBox("approvalReq", approvalReqOK, nil)
}

func makeContent() {
	if st2loginweb.IsLoginContent() == true {
		errMsg := st2loginweb.LoginContent()
		if errMsg != "" {
			wu.VisibleMsgBox(errMsg)
		}
		return
	}

	doc := js.Global().Get("document")
	workflowContent := doc.Call("getElementById", "workflowContent")

	tabHTML := wu.Tabs["mainPage"].MakeHTML("<<", "1")
	defaultTab := wu.Tabs["appWorkflow"]
	tabHTML.AppendTab(defaultTab.MakeHTML("Workflow", "1"))
	html := tabHTML.MakeHTML()
	workflowContent.Set("innerHTML", html)

	defaultTab.GetButton().Call("click")
}

func gotoMainPageContent(tabC *js.Value) {
	gl := js.Global()
	loc := gl.Get("location")
	mainPageURL := loc.Get("protocol").String()+"//"+loc.Get("host").String()
	loc.Call("replace", mainPageURL)
}

func updateWorkflowContent(tabC *js.Value) {
	html := ""
	defer func() {
		tabC.Set("innerHTML", html)
	}()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		html += "<h3>You are invalid user</h3>"
		return
	}

	regRoles := id.GetRegRoles(wu.GetImmsrvURL())
	if len(regRoles) > 0 && regRoles[0] == "*" { // admin
		gl := js.Global()
		//loc := gl.Get("location")
		doc := gl.Get("document")

		adminHTML := `
function adminDo() {
    WebAssembly.instantiateStreaming(fetch("workflowadminweb.wasm"), go.importObject).then( async(result) => {
      mod = result.module;
      inst = result.instance;
      await go.run(inst);
    });
}
`
		appendScript := doc.Call("createElement", "script")
		appendScript.Set("type", "text/javascript")
		appendScript.Set("innerHTML",adminHTML)
		doc.Call("getElementsByTagName", "head").Index(0).Call("appendChild", appendScript)
		gl.Call("adminDo")
		return
	}
		
	html += "<h3>" + id.Name + "</h3>"
	html += `<div class="space"></div>`

	tabHTML := &wu.TabHTML{}
	//tabHTML.AppendTab(wu.Tabs["pendingTask"].MakeHTML("Pending Task", "2"))
	//tabHTML.AppendTab(wu.Tabs["approvalReq"].MakeHTML("Approval Request", "2"))
	//tabHTML.AppendTab(wu.Tabs["myMsgBox"].MakeHTML("My Message Box", "2"))
	tabHTML.AppendTab(wu.Tabs["login"].MakeHTML("Login", "2"))
	tabHTML.AppendTab(wu.Tabs["myAttr"].MakeHTML("My Attribution", "2"))
	html += tabHTML.MakeHTML()
	return
}

func genAesKey() (aesKey []byte) {
	aesKey = make([]byte, 32) // AES-256 key
	rand.Read(aesKey)
	return
}


func updatePendingTaskContent(tabC *js.Value) {
}

func updateApprovalReqContent(tabC *js.Value) {
	items := wu.InitItems()
	items.AppendHTML("<p>Please click <b>Select</b> to select files you want to get approval.</p>")
	items.AppendReadFileButton("approvalReqFile", "Document files", "Select", `onchange=selectedFile(event) multiple hidden`)
	items.PackDiv("approvalFileArea")
	tabC.Set("innerHTML", items.MakeHTML())
}

var approvalFiles []struct{
	val js.Value
	checked bool
}

func selectedFile(this js.Value, in []js.Value) interface{} {
	go func() {
		fileList := in[0].Get("target")
		fileList = fileList.Get("files")

		approvalFiles = nil
		for i := 0; i < fileList.Length(); i++ {
			file := fileList.Index(i)
			approvalFiles = append(approvalFiles,  struct{val js.Value; checked bool}{val: file, checked:true})
		}
		
		makeApprovalReqBox("", "")
	}()

	return nil
}

func makeApprovalReqBox(approverList, footer string) {
	if approvalFiles == nil {
		return
	}

	header := `<label>Please set approvers, and uncheck files you don't want to send to them.</label>`
	
	items := wu.InitItems()
	items.AppendTextInput("approvers", "Approvers", approverList, "")
	for i, file := range approvalFiles {
		filename := file.val.Get("name").String()
		checked := ""
		if file.checked {
			checked = "checked"
		}
		items.AppendCheckbox(filename, `name="filelist" `+checked+` id="filelist`+strconv.Itoa(i)+`"` )
	}
		
	header += items.GetHTML()
	wu.MakeReqBox("approvalReq", header, footer, true, true)
}

func approvalReqOK(in []js.Value) {
	errMsg := ""
	approverList := ""
	defer func() {
		if errMsg == "" {
			wu.VisibleMsgBox("Succcess")
			return
		}
		makeApprovalReqBox(approverList, "<b>"+errMsg+"</b>")
		return
	}()
	
	doc := js.Global().Get("document")
	unselFiles := doc.Call("querySelectorAll", `input[name="filelist"]:not(:checked)`)
	for i := 0; i < unselFiles.Length(); i++ {
		checkedID := unselFiles.Index(i).Get("id").String()
		idN, err := strconv.Atoi(strings.TrimPrefix(checkedID, "filelist"))
		if err != nil {
			continue
		}

		approvalFiles[idN].checked = false
	}
	
	approverList = doc.Call("getElementById", "approvers").Get("value").String()
	approver := strings.Split(approverList, ",")
	
	if approver[0] == "" {
		errMsg = "Please set at least one approver."
		return
	}

	selectedFiles := doc.Call("querySelectorAll", `input[name="filelist"]:checked`)
	if selectedFiles.Length() <= 0 {
		errMsg = "Please select at least one file."
		return
	}
	
	wu.VisibleSimpleMsgBox("Building approval request...")

	
}

func updateMyMsgBoxContent(tabC *js.Value) {
}

func updateLoginContent(tabC *js.Value) {
	gl := js.Global()
	loc := gl.Get("location")

	curOrigin := loc.Get("origin").String()
	loc.Call("replace", curOrigin + st2loginweb.LoginPath)
}

func updateMyAttrContent(tabC *js.Value) {
	json := js.Global().Get("JSON")
	loc := js.Global().Get("location")
	st2req := &st2do.ST2Request{BaseURL: loc.Get("origin").String()+ST2DO_PATH}
	errMsg := st2req.Login()
	if errMsg != "" {
		wu.VisibleMsgBox("failed to login: " + errMsg)
		return
	}
        
	rspJson, errMsg := st2req.Get("/api/v1/user", nil)
	if errMsg != "" {
		wu.VisibleMsgBox("error: [" + errMsg + "]")
		return
	}
	rspJson = json.Call("stringify", rspJson)
	wu.VisibleMsgBox(rspJson.String())
}
