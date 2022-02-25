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
	
	"websto"
	"immclient"
)

const (
	immsrvPath = "/immsrv"
)

func main() {
	ch := make(chan struct{}, 0)
	enrollOAuthUser()
	<- ch
}

func enrollOAuthUser() {
	doc := js.Global().Get("document")
	loc := js.Global().Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String()+immsrvPath
	
	usernameObj := doc.Call("getElementById", "username")
	if usernameObj.IsNull() {
		return
	}
	username := usernameObj.Get("value").String()
	
	secretObj := doc.Call("getElementById", "secret")
	if secretObj.IsNull() {
		return
	}
	secret := secretObj.Get("value").String()

	go func() {
		id, err := immclient.EnrollUser(username, immclient.OneYear, secret, url)
		if err != nil {
			return
		}

		websto.StoreKeyPair(id.Name, id)
		websto.SetCurrentUsername(id.Name)

		mainUrl := loc.Get("protocol").String() + "//" + loc.Get("host").String()
		loc.Set("href", mainUrl)
	}()
}
