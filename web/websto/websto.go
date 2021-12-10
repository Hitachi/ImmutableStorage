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

package websto

import (
	"immclient"
	"syscall/js"
	"strings"
	"strconv"
	"errors"
	"sync/atomic"
	"encoding/pem"
	"crypto/rand"
	"crypto/x509"
)

const (
	ERR_ENCRYPTED_KEY = "encrypted key"
	
	USER_PRIV_SUFFIX =  "_sk"
	USER_CERT_SUFFIX = "-cert.pem"
	HOST_PREFIX = "host "
)

func ConvToArray(src string) []byte {
	srcArray := strings.Split(src, ",")
	dst := make([]byte, len(srcArray))
	for i, str := range srcArray {
		v, _ := strconv.Atoi(str)
		dst[i] = byte(v)
	}

	return dst
}

func GetIDFromStorage(username string) (*immclient.UserID, error) {
	gl := js.Global()
	storage := gl.Get("localStorage")

	privStorage := storage.Call("getItem", username + USER_PRIV_SUFFIX)
	certStorage := storage.Call("getItem", username + USER_CERT_SUFFIX)
	if privStorage.IsNull() || certStorage.IsNull() {
		return nil, errors.New("not found user")
	}

	priv := ConvToArray(privStorage.String())
	cert := ConvToArray(certStorage.String())

	return &immclient.UserID{Name: username, Priv: priv, Cert: cert}, nil
}

func SetCurrentUsername(username string) {
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("setItem", "lastUser", username)
}

func GetCurrentUsername() (string, error) {
	gl := js.Global()
	storage := gl.Get("localStorage")

	userName := storage.Call("getItem", "lastUser")
	if userName.IsNull() {
		return "", errors.New("There is not last user in localStorage")
	}
	return userName.String(), nil
}


var cachedUser *immclient.UserID
var cachedUserLock = int32(0)

func GetCurrentID() (*immclient.UserID, error) {
	userName, err := GetCurrentUsername()
	if err != nil {
		return nil, err
	}

	if atomic.CompareAndSwapInt32(&cachedUserLock, 0, 1) == false {
		return nil, errors.New("another task is in progress")
	}
	defer func() { cachedUserLock = 0 }()
	
	if (cachedUser != nil) && (cachedUser.Name == userName) {
		return cachedUser, nil
	}

	userOnSto, err := GetIDFromStorage(userName)
	if err != nil {
		return nil, err
	}

	privPem, _ := pem.Decode(userOnSto.Priv)
	if x509.IsEncryptedPEMBlock(privPem) {
		return nil, errors.New(ERR_ENCRYPTED_KEY)
	}
	
	cachedUser = userOnSto
	return cachedUser, nil
}

func EncryptKey(keyPass string) error {
	userName, err := GetCurrentUsername()
	if err != nil {
		return err
	}

	if cachedUser == nil {
		return errors.New("you have not selected a user")
	}

	if cachedUser.Name != userName {
		return errors.New("unexpected status")
	}

	privData, _ := pem.Decode(cachedUser.Priv)
	encryptedPem, err := x509.EncryptPEMBlock(rand.Reader, privData.Type, privData.Bytes, []byte(keyPass), x509.PEMCipherAES256)
	if err != nil {
		return errors.New("failed to encrypt key")
	}
	encryptedKeyData := pem.EncodeToMemory(encryptedPem)

	localStorage := js.Global().Get("localStorage")
	uint8Array := js.Global().Get("Uint8Array")
	privStorage := userName + USER_PRIV_SUFFIX
	privArray := uint8Array.New(len(encryptedKeyData))
	js.CopyBytesToJS(privArray, encryptedKeyData)
	localStorage.Call("setItem", privStorage, privArray)

	return nil
}

func DecryptKey(keyPass string) error {
	userName, err := GetCurrentUsername()
	if err != nil {
		return err
	}

	userOnSto, err := GetIDFromStorage(userName)
	if err != nil {
		return err
	}

	privPem, _ := pem.Decode(userOnSto.Priv)
	if ! x509.IsEncryptedPEMBlock(privPem) {
		return errors.New("not encrypted key")
	}

	privAsn1, err := x509.DecryptPEMBlock(privPem, []byte(keyPass))
	if err != nil {
		return errors.New("failed to decrypt a key: " + err.Error())
	}

	userOnSto.Priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1})
	cachedUser = userOnSto
	return nil
}

func IsPasswordRequired(username string) bool {
	id, err := GetIDFromStorage(username)
	if err != nil {
		return false
	}

	privPem, _ := pem.Decode(id.Priv)
	return x509.IsEncryptedPEMBlock(privPem)
}

func StoreKeyPair(prefix string, id *immclient.UserID) {
	localStorage := js.Global().Get("localStorage")
	uint8Array := js.Global().Get("Uint8Array")

	certStorage := prefix + USER_CERT_SUFFIX
	privStorage := prefix + USER_PRIV_SUFFIX
	
	privArray := uint8Array.New(len(id.Priv))
	js.CopyBytesToJS(privArray, id.Priv)
	localStorage.Call("setItem", privStorage, privArray)

	certArray := uint8Array.New(len(id.Cert))
	js.CopyBytesToJS(certArray, id.Cert)
	localStorage.Call("setItem", certStorage, certArray)
}

func ListUsername() (list []string) {
	list = []string{}
	
	storage := js.Global().Get("localStorage")
	storageLen := storage.Length()
	for i := 0; i < storageLen; i++ {
		key := storage.Call("key", i).String()
		username := strings.TrimSuffix(key, USER_CERT_SUFFIX)
		
		if key == username {
			continue
		}
		if strings.HasPrefix(key, HOST_PREFIX) {
			continue
		}

		list = append(list, username)
	}

	return
}
