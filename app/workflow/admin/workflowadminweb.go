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
	
	"websto"
	wu "webutil"

	"immadmin"
	"st2mng"
)

const (
	LoggingCond = `$syslogfacility-text == "local6"`
	LoggingKey = "st2actionrunner"
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
	wu.RegisterTab("appWorkflowAdmin", updateWorkflowAdminContent)
	wu.RegisterTab("configWorkflow", updateConfigWorkflowContent)
	
	wu.RegisterTab("configRsyslogdEnv", updateConfigRsyslogdEnvContent)
	gl.Set("createRsyslogdEnv", js.FuncOf(createRsyslogdEnv))
	wu.RegisterTab("configST2Env", updateConfigST2EnvContent)
	gl.Set("createST2Env", js.FuncOf(createST2Env))
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
}

func makeContent() {
	doc := js.Global().Get("document")
	workflowContent := doc.Call("getElementById", "workflowContent")
	
	tabHTML := wu.Tabs["mainPage"].MakeHTML("<<", "1")
	defaultTab := wu.Tabs["appWorkflowAdmin"]	
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

func updateWorkflowAdminContent(tabC *js.Value) {
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
	tabHTML.AppendTab(wu.Tabs["configWorkflow"].MakeHTML("Configuration", "2"))
	html += tabHTML.MakeHTML()
	return
}

func updateConfigWorkflowContent(tabC *js.Value) {
	html := `<div class="space"></div>`

	defer func() {
		tabC.Set("innerHTML", html)
	}()

	tabHTML := &wu.TabHTML{}
	tabHTML.AppendTab(wu.Tabs["configRsyslogdEnv"].MakeHTML("Rsyslogd", "3"))
	tabHTML.AppendTab(wu.Tabs["configST2Env"].MakeHTML("StackStorm", "3"))
	html += tabHTML.MakeHTML()

	return
}

func updateConfigRsyslogdEnvContent(tabC *js.Value) {
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
	items.AppendButton("Create an environment", "createRsyslogdEnv")
	html = items.MakeHTML()
	return
}

func createRsyslogdEnv(this js.Value, in []js.Value) any {
	wu.VisibleSimpleMsgBox("Creating...")
	
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	username := doc.Call("getElementById", "rsysloguser").Get("value").String()
	storageGrp := doc.Call("getElementById", "storageGrp").Get("value").String()

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

		err = immadmin.CreateRsyslogEnv(id, url, storageGrp, username, LoggingCond, LoggingKey)
		if err != nil {
			msg = err.Error()
			return
		}
	}()

	return nil
}

func updateConfigST2EnvContent(tabC *js.Value) {
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
		errMsg = "You are invalid user: " + err.Error()
		return
	}

	url := wu.GetImmsrvURL()
	rsyslogUserList, err := immadmin.ListRsyslogEnv(id, url)
	if err != nil {
		errMsg = "Failed to get the list of rsyslogd users: " + err.Error()
		return
	}
	if len(rsyslogUserList) < 1 {
		errMsg = "There is no rsyslogd users in the this system."
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
	items.AppendSelectList("rsysloguser", "Select a rsyslog user", rsyslogUserList)
	items.AppendSelectList("storageGrp", "Select a storage group for new workflow environment", storageGrpList)
	items.AppendButton("Create an environment", "createST2Env")
	html = items.MakeHTML()
	return
}

func createST2Env(this js.Value, in []js.Value) any {
	wu.VisibleSimpleMsgBox("Creating...")
	
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "storageGrp")
	storageGrp := storageGrpSel.Get("value").String()
	rsysUsername := doc.Call("getElementById", "rsysloguser").Get("value").String()

	go func() {
		msgBoxStr := "Success"
		defer func() {
			wu.VisibleMsgBox(msgBoxStr)
		}()

		id, err := websto.GetCurrentID()
		if err != nil {
			msgBoxStr = "Invalid user: " + err.Error()
			return
		}

		err = st2mng.CreateEnv(id, url, storageGrp, rsysUsername)
		if err != nil {
			msgBoxStr = "Failed to create an environment for the workflow: " + err.Error()
			return
		}
	}()

	return nil
}
