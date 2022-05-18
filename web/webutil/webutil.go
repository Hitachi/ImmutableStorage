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

package webutil

import (
	"syscall/js"
	"strconv"
	"strings"
)

const (
	immsrvPath = "/immsrv"
)

func GetImmsrvURL() string {
	loc := js.Global().Get("location")
	return loc.Get("protocol").String() + "//" + loc.Get("host").String()+immsrvPath
}


type TabHTML struct{
	btnHTML string
	contentHTML string
}

func (i *TabHTML) AppendTab(tabI *TabHTML) {
	i.btnHTML += tabI.btnHTML
	i.contentHTML += tabI.contentHTML
}

func (i *TabHTML) MakeHTML() string {
	html := `<div class="tab">`
	html += i.btnHTML
	html += `</div>`
    html += i.contentHTML
	return html
}

type TabBtn struct{
	ID string
	update func(*js.Value)
}

var Tabs map[string]*TabBtn
func InitTab(openTabFunc string) {
	js.Global().Set(openTabFunc, js.FuncOf(openTab))
	Tabs = make(map[string]*TabBtn)
}

func RegisterTab(name string, updateTab func(tabContent *js.Value)) {
	Tabs[name] = &TabBtn{
		ID: name,
		update: updateTab,
	}
}

func (i *TabBtn)MakeHTML(title, level string) (*TabHTML) {
	hiddenStr := ""
	if title == "" {
		hiddenStr = " hidden"
	}
	
	return &TabHTML{
		btnHTML: `  <button class="tablinks `+level+`" onclick="openTab(event, `+level+`)" id="`+i.ID+`Tab"`+hiddenStr+`>`+title+`</button>`,
		contentHTML: `<div class="tabcontent `+level+`" id="`+i.ID+`Content"></div>`,
	}
}

func (i *TabBtn)GetButton() (btn *js.Value) {
	doc := js.Global().Get("document")
	tabBtn := doc.Call("getElementById", i.ID+"Tab")
	btn = &tabBtn
	return
}

func (i *TabBtn)GetContent() (tContent *js.Value) {
	doc := js.Global().Get("document")
	tabContent := doc.Call("getElementById", i.ID+"Content")
	tContent = &tabContent
	return	
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

	tabId := strings.TrimSuffix(target.Get("id").String(), "Tab")
	contentId := tabId + "Content"
	content := doc.Call("getElementById", contentId)
	if content.IsNull() {
		return nil
	}

	content.Get("style").Set("display", "block")

	tab, ok := Tabs[tabId]
	if ok {
		go tab.update(&content)
	}

	return nil
}

type reqBoxActionSet struct{
	OK func([]js.Value)
	Cancel func([]js.Value)
}

var reqBoxFunc map[string]*reqBoxActionSet
var reqBoxOKFunc, reqBoxCancelFunc string
var reqBoxDefaultAction string

func InitReqBox(okFunc, cancelFunc, defaultAction string) {
	reqBoxOKFunc = okFunc
	reqBoxCancelFunc = cancelFunc
	
	gl := js.Global()
	gl.Set(okFunc, js.FuncOf(reqBoxOk))
	gl.Set(cancelFunc, js.FuncOf(reqBoxCancel))
	
	reqBoxFunc = make(map[string]*reqBoxActionSet)
	reqBoxDefaultAction = defaultAction
	AppendReqBox(reqBoxDefaultAction, nil, nil)
}

func AppendReqBox(reqBoxAction string, OKFunc, CancelFunc func([]js.Value) ) {
	reqBoxFunc[reqBoxAction] = &reqBoxActionSet{OK: OKFunc, Cancel: CancelFunc}
}

func getReqBoxHandler(in []js.Value) (handlers *reqBoxActionSet, ok bool) {
	if len(in) != 2 {
		return // failure
	}
	reqStr := in[1].String()
	print("log: reqStr=" + reqStr + "\n")

	handlers, ok = reqBoxFunc[reqStr]
	return
}

func reqBoxOk(this js.Value, in []js.Value) interface{} {
	handler, ok := getReqBoxHandler(in)
	if !ok {
		return nil
	}
	
	if handler.OK == nil {
		handler.OK = CloseReqBox
	}
	go handler.OK(in)
	return nil
}

func reqBoxCancel(this js.Value, in []js.Value) interface{} {
	handler, ok := getReqBoxHandler(in)
	if !ok {
		return nil
	}
	
	if handler.Cancel == nil {
		handler.Cancel = CloseReqBox
	}
	go handler.Cancel(in)
	return nil
}

func CloseReqBox(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "none")	
}

func MakeReqBox(reqBoxAction, header, footer string, okBtn, cancelBtn bool) {
	gl := js.Global()
	doc := gl.Get("document")
	
	html := `<div class="passReqArea">`
	html += header
	html += `  <div class="immDSBtn">`
	if okBtn {	
		html += `    <button onclick="`+reqBoxOKFunc+`(event, '`+reqBoxAction+`')" id="reqBoxOkBtn">OK</button>`
	}
	if cancelBtn {
		html += `    <button onclick="`+reqBoxCancelFunc+`(event, '`+reqBoxAction+`')" id="reqBoxCancelBtn">Cancel</button>`
	}
	html += `  </div>`
	html += footer
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)
	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")
}

func VisibleSimpleMsgBox(msg string) {
	header := `<label>` + msg + `</label>`
	MakeReqBox("", header, "", false, false)
}

func VisibleMsgBox(msg string) {
	header := `<label>` + msg + `</label>`
	MakeReqBox(reqBoxDefaultAction, header, "", true, false)
}


func SaveFile(fileName string, fileData []byte, downloadUrlElem string) {
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
