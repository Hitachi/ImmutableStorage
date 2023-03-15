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

package st2loginweb

import (
	"strings"
	"net/url"
	"syscall/js"
	
	"st2do"
)

const (
	st2authCallbackURL = "https://st2web/auth/v1/sso/callback"
	LoginPath = "/st2web/st2login.html"
)

func IsLoginContent() (bool) {
	gl := js.Global()
	loc := gl.Get("location")

	pathName := loc.Get("pathname").String()
	if ! strings.HasPrefix(pathName, LoginPath) {
		return false
		
	}

	return true
}

func LoginContent() (errMsg string) {
	gl := js.Global()
	loc := gl.Get("location")

	queryStr := loc.Get("search").String()
	queryStr = strings.TrimPrefix(queryStr, "?")

	if queryStr == "" {
		reqBase64, org, errStr := st2do.MakeLoginRequest()
		if errStr != "" {
			errMsg = errMsg
			return
		}
			
		switchST2URL := "https://st2web." + org + loc.Get("pathname").String() + "?"
		loc.Call("replace", switchST2URL + url.QueryEscape(reqBase64))
		return
	}

	reqBase64, err := url.QueryUnescape(queryStr)
	if err != nil {
		errMsg = "invalid request: " + err.Error()
		return
	}
	reqData := `{"response": "`+ reqBase64 + `"}`

	baseURL := loc.Get("origin").String()
	st2req := &st2do.ST2Request{BaseURL: baseURL}
	rsp, errMsg := st2req.Post(st2do.SSO_CALLBACK, nil, reqData)
	if errMsg != "" {
		errMsg = "faild to authenticate a user: " + errMsg
		return
	}

	//print("success\n")
	//print(rsp.String()+"\n")

	origin := loc.Get("origin").String()
	
	doc := gl.Get("document")
	html := string(rsp.String())
	html = strings.Replace(html, "<html>", "", 1)
	html = strings.Replace(html, "</html>", "", 1)
	html = strings.Replace(html, "<script>",
		`function setST2Token() {
               window.localStorage.setItem('st2Session', '{"token": "", "server": {"api": "`+origin+`/api", "auth": "`+origin+`/auth", "stream": "`+origin+`/stream"}}');
            `, 1)
	html = strings.Replace(html, "</script>", "}\n", 1)
	//print("log: \n" + html + "\n")
	
	appendScript := doc.Call("createElement", "script")
	appendScript.Set("type", "text/javascript")
	appendScript.Set("innerHTML", html)
	doc.Call("getElementsByTagName", "head").Index(0).Call("appendChild", appendScript)
	
	gl.Call("setST2Token")

	return
}
