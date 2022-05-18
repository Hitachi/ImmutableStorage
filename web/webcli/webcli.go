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

package webcli

import (
	"syscall/js"
	"strings"
	
	"immclient"
	wu "webutil"
)

func RegisterAppUserCA(id *immclient.UserID, regUserReq *immclient.RegistrationRequest, usernameObj, secretObj *js.Value) error {
	url := wu.GetImmsrvURL()

	username := usernameObj.Get("value").String()	
	secret := secretObj.Get("value").String()
	if secret == "" {
		secret = immclient.RandStr(16)
	}

	if regUserReq.Name != "" {
		username = strings.TrimSuffix(username, regUserReq.Name)
		username += regUserReq.Name
	}
	usernameObj.Set("value", username)
	
	regUserReq.Name = username
	regUserReq.Secret = secret
	regUserReq.MaxEnrollments = -1 // unlimited
			
	_, err := id.Register(regUserReq, url)
	if err != nil {
		return err
	}

	// success			
	secretObj.Set("value", secret)
	return nil
}
