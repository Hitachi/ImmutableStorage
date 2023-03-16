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

package st2do

import (
	"syscall/js"
	"encoding/base64"
	"google.golang.org/protobuf/proto"
	
	"websto"
	"immop"
	"immcommon"
	wu "webutil"
)

const (
	SSO_CALLBACK = "/auth/v1/sso/callback"
)

type ST2Request struct {
	BaseURL string
	x_auth_token string
}

type st2ReqParam struct {
	path string
	method string
	headers map[string]string
	jsonText string
}

func (req *ST2Request) doRequest(param *st2ReqParam) (rsp js.Value, err string) {
	gl := js.Global()
	//json := js.Global().Get("JSON")

	errCh := make(chan string, 1)
	resolve := js.FuncOf(func(this js.Value, in []js.Value) interface{} {
		val := in[0]
		contentType := val.Get("headers").Call("get", "Content-Type").String()

		var getDataJS js.Func
		getFaultStr := func(result js.Value) string {
			return ""
		}
		
		getDataJS = js.FuncOf(func(this js.Value, result []js.Value) any {
			getDataJS.Release()

			rsp = result[0]
			errCh <- getFaultStr(rsp)
			return nil
		})

		if contentType == "application/json" {
			getFaultStr = func(result js.Value) string {
				faultStr := result.Get("faultstring")
				if ! faultStr.IsUndefined() {
					return faultStr.String()
				}
				return ""
			}
			
			val.Call("json").Call("then", getDataJS)
			return nil
		}

		val.Call("text").Call("then", getDataJS)
		return nil
	})
	reject := js.FuncOf(func(this js.Value, in []js.Value) interface{} {
		errObj := in[0]
		errCh <- "error name: " + errObj.Get("name").String() + " msg: " + errObj.Get("message").String()
		return nil
	})

	headers := map[string]any{
		"Content-Type": "application/json",		
	}
	for h_name, header := range param.headers{
		headers[h_name] = header
	}
	if req.x_auth_token != "" {
		headers["x-auth-token"] = req.x_auth_token
	}
	
	reqData := map[string]any{
		"method": param.method,
		"headers": js.ValueOf(headers),
	}
	if param.jsonText != "" {
		reqData["body"] = param.jsonText
	}
		
	gl.Call("fetch", req.BaseURL + param.path, js.ValueOf(reqData)).Call("then", resolve, reject)
	err = <- errCh
	resolve.Release()
	reject.Release()
	
	return
}

func (req *ST2Request) Get(api_path string, headers *map[string]string) (rsp js.Value, err string) {
	req_headers := &map[string]string{}
	if headers != nil {
		req_headers = headers
	}
	return req.doRequest(&st2ReqParam{
		method: "GET",
		path: api_path,
		headers: *req_headers,
	})
}


func (req *ST2Request) getJsonTxt(json_text any) (text string, err string) {
	gl := js.Global()
	json := gl.Get("JSON")
	
	switch json_text.(type) {
	case string:
		text = json_text.(string)
	case map[string]any:
		jsonObj := js.ValueOf(json_text)
		text = json.Call("stringify", jsonObj).String()
	default:
		err = "the specified parameter is unexpected type"
	}
	
	return 
}

func (req *ST2Request) doPostOrPut(method, api_path string, headers *map[string]string, json_text any) (rsp js.Value, err string) {
	text, err := req.getJsonTxt(json_text)
	if err != "" {
		return
	}
	
	reqParam := &st2ReqParam{
		method: method,
		path: api_path,
		jsonText: text,
	}
	if headers != nil {
		reqParam.headers = *headers
	}
	
	return req.doRequest(reqParam)
}

func (req *ST2Request) Post(api_path string, headers *map[string]string, json_text any) (rsp js.Value, err string) {
	return req.doPostOrPut("POST", api_path, headers, json_text)
}

func (req *ST2Request) Put(api_path string, json_text any) (rsp js.Value, err string) {
	return req.doPostOrPut("PUT", api_path, nil, json_text)
}

func (req *ST2Request) Delete(api_path string) (err string) {
	_, err = req.doRequest(&st2ReqParam{
		method: "DELETE",
		path: api_path,
	})
	return
}

func MakeLoginRequest() (reqBase64, org, errStr string){
	id, err := websto.GetCurrentID()
	if err != nil {
		errStr = err.Error()
		return
	}

	org, err = id.GetIssuerOrg()
	if err != nil {
		errStr= "invaid certificate: " + err.Error()
		return
	}

	immsrvURL := wu.GetImmsrvURL()
	
	reply := &immcommon.WhoamIReply{}
	_, err = immcommon.ImmstFunc(id, immsrvURL, immcommon.MCommon, immcommon.FWhoamI, nil, reply)
	if err != nil {
		errStr = err.Error()
		return
	}

	reqGrpc := &immop.ImmstFuncRequest{
		Mod: immcommon.MCommon,
		Func: immcommon.FWhoamI,
		Time: reply.Time,
	}
	reqGrpc.Cred, err = id.SignMsg("ImmstFunc", reqGrpc)
	if err != nil {
		errStr = "failed to sign a message: " + err.Error()
		return
	}

	rawReq, err := proto.Marshal(reqGrpc)
	if err != nil {
		errStr = "failed to marshal a request: " + err.Error()
		return
	}

	req := &immop.PropReq{}
	req.Msg = rawReq
	req.Cred, err = id.SignMsg("st2authReq", req)
	if err != nil {
		errStr = err.Error()
		return
	}
	rawReq, err = proto.Marshal(req)
	if err != nil {
		errStr = "failed to marshal a request to authenticate a user: " + err.Error()
		return
	}
	reqBase64 = base64.StdEncoding.EncodeToString(rawReq)
	return // success
}

func (st2req *ST2Request) Login() (errStr string) {
	reqBase64, _, errStr := MakeLoginRequest()
	if errStr != "" {
		return
	}

	reqData := `{"response": "`+ reqBase64 + `"}`
	_, errStr = st2req.Post(SSO_CALLBACK, nil, reqData)
	if errStr != "" {
		return
	}

	gl := js.Global()
	json := gl.Get("JSON")
	doc := gl.Get("document")

	curCookie := doc.Get("cookie")
	curCookie = gl.Get("String").New(curCookie)
	curCookie = curCookie.Call("match", `(^|;) ?` + "st2-auth-token" + `=([^;]*)(;|$)`)
	if curCookie.IsNull() {
		errStr = "failed to get a token"
		return
	}
	curCookie = gl.Call("decodeURIComponent", curCookie.Index(2))
	token := json.Call("parse", curCookie)
	token = token.Get("token")
	if token.IsUndefined() {
		errStr = "unexpected cookie"
		return
	}
	st2req.x_auth_token = token.String()

	return // success
}
