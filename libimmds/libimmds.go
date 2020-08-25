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

package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lprotobuf
#include <stdlib.h>
#include <stdio.h>
*/
import "C"

import (
	"immclient"
	"libimmds"
	"strings"
	"fmt"
	"io/ioutil"
	//	"encoding/hex"
	"github.com/golang/protobuf/proto"
	"encoding/pem"
	"crypto/x509"
)

var ids map[string]*immclient.UserID = make(map[string]*immclient.UserID)

//export OpenKey
func OpenKey(c_userAndOrg, c_path, c_password *C.char) (userID, retErr *C.char) {
	userAndOrg := C.GoString(c_userAndOrg)
	userAndOrgStr := strings.SplitN(userAndOrg, "@", 2)
	username := userAndOrgStr[0]
	org := ""
	if len(userAndOrgStr) >= 2 {
		org = userAndOrgStr[1]
	}
	path := C.GoString(c_path)
	password := C.GoString(c_password)
	
	//	print("username: " + username + ", path: " + path + "\n")
	priv, err := ioutil.ReadFile(path+"/"+username+"_sk")
	if err != nil {
		retErr = C.CString("OpenKey: " + err.Error())
		return
	}

	privPem, _ := pem.Decode(priv)
	if x509.IsEncryptedPEMBlock(privPem) {
		privAsn1, err := x509.DecryptPEMBlock(privPem, []byte(password))
		if err != nil {
			retErr = C.CString("failed to decrypt a key: " + err.Error())
			return
		}

		priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1})
	}		

	cert, err := ioutil.ReadFile(path+"/"+username+"-cert.pem")
	if err != nil {
		retErr = C.CString("OpenKey: " + err.Error())
		return
	}

	id := &immclient.UserID{Name: username, Priv: priv, Cert: cert}
	issuerOrg, err := id.GetIssuerOrg()
	if err != nil {
		retErr = C.CString("invalid key: " + err.Error())
		return
	}
	
	if (org != "") && (org == issuerOrg) {
		retErr = C.CString("private key was not found")
		return
	}
	org = issuerOrg
	
	userIDStr := username + "@" + org
	ids[userIDStr] = id
	
	userID = C.CString(userIDStr)
	return
}

func CloseKey(c_userID *C.char) (*C.char) {
	userID := C.GoString(c_userID)
	_, ok := ids[userID]
	if !ok {
		return C.CString("invalid user")
	}

	delete(ids, userID)
	return nil
}

func getIdAndUrl(userID string) (retID immclient.UserID, url string, retErr error) {
	id, ok := ids[userID]
	if !ok {
		retErr = fmt.Errorf("invalid user")
		return
	}
	
	issuerOrg, _ := id.GetIssuerOrg()
	url = "immsrv." + issuerOrg + ":8080"
	retID = *id
	return
}

//export RecordLedger
func RecordLedger(c_userID, c_storageGrp, c_logName, c_msgLog *C.char) *C.char {
	userID := C.GoString(c_userID)
	storageGrp := C.GoString(c_storageGrp)
	
	id, url, err := getIdAndUrl(userID)
	if err != nil {
		return C.CString(err.Error())
	}

	org := strings.SplitN(userID, "@", 2)[1]
	if ! strings.Contains(storageGrp, ".") {
		storageGrp += "." + org
	}
	
	logName := C.GoString(c_logName)
	msgLog := C.GoString(c_msgLog)
	err = id.RecordLedger(storageGrp, logName, msgLog, url)
	if err != nil {
		return C.CString(err.Error())
	}
	
	return nil
}

//export GetTxIDOnLedger
func GetTxIDOnLedger(c_userID, c_storageGrp, c_logName *C.char) (response, retErr *C.char) {
	userID := C.GoString(c_userID)
	storageGrp := C.GoString(c_storageGrp)
	
	id, url, err := getIdAndUrl(userID)
	if err != nil {
		retErr = C.CString(err.Error())
		return
	}

	org := strings.SplitN(userID, "@", 2)[1]
	if ! strings.Contains(storageGrp, ".") {
		storageGrp += "." + org
	}

	logName := C.GoString(c_logName)
	history, err := id.ReadLedger(storageGrp, logName, url)
	if err != nil {
		retErr = C.CString("could not read ledger: " + err.Error())
		return
	}

	txIdArray := &libimmds.TxIdList{}
	txIdArray.TxID = make([]string, len(*history))
	for i, item := range *history {
		txIdArray.TxID[i] = item.TxId
		//		print("TxID: " + item.TxId + "\n")
	}
	txIdBuf, err := proto.Marshal(txIdArray)
	if err != nil {
		retErr = C.CString("failed to marshal TxIDs: " + err.Error())
		return
	}
	//	fmt.Printf("txIdBuf:\n%s", hex.Dump(txIdBuf))

	responseTmp := (C.malloc(C.size_t(len(txIdBuf))))
	if len(txIdBuf) > (1<<26)/*64MB*/ {
		retErr = C.CString("It is too many IDs on the ledger to response")
		return
	}
	copy((*[1<<26]byte)(responseTmp)[0:len(txIdBuf)], txIdBuf)
	response = (*C.char)(responseTmp)
	
	return
}

//export QueryBlockByTxID
func QueryBlockByTxID(c_userID, c_storageGrp, c_txID *C.char) (response *C.char, rspLen C.ulong, retErr *C.char) {
	userID := C.GoString(c_userID)
	storageGrp := C.GoString(c_storageGrp)
	
	id, url, err := getIdAndUrl(userID)
	if err != nil {
		retErr = C.CString(err.Error())
		return
	}

	org := strings.SplitN(userID, "@", 2)[1]
	if ! strings.Contains(storageGrp, ".") {
		storageGrp += "." + org
	}

	block, err := id.QueryBlockByTxID(storageGrp, C.GoString(c_txID), url)
	if err != nil {
		retErr = C.CString("could not read block: " + err.Error())
		return
	}

	blockByte, err := proto.Marshal(block)
	if err != nil {
		retErr = C.CString("failed to marshal block: " + err.Error())
		return
	}
	//	fmt.Printf("block:\n%s\n", hex.Dump(blockByte))

	responseTmp := (C.malloc(C.size_t(len(blockByte))))
	if len(blockByte) > (1<<27)/*128MB*/ {
		retErr = C.CString("It is too big block to reponse")
		return
	}
	copy((*[1<<27]byte)(responseTmp)[0:len(blockByte)], blockByte)
	response = (*C.char)(responseTmp)
	rspLen = C.ulong(len(blockByte))

	return
}

func main(){
}

