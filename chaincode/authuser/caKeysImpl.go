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

package authuser

import (
	"io/ioutil"
)

type CAKeysImpl struct {
}
func (ca *CAKeysImpl) name() string {
	return ""
}

func (ca *CAKeysImpl) cert() *[]byte {
	fileName := permConfDir + "/ca.pem"
	data, err:= ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}

func (ca *CAKeysImpl) uCert() *[]byte {
	fileName := permConfDir + "/ucert.pem"
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}

func (ca *CAKeysImpl) uPriv() *[]byte {
	fileName := permConfDir + "/upriv.pem"
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}
func NewAuthUser() *CAAuthUser {
	au := new(CAAuthUser)
	au.setKeys(new(CAKeysImpl))
	return au
}
