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
	"libimmds"
	"immledger"
	//	"fmt"
	//	"encoding/hex"
	"google.golang.org/protobuf/proto"
	"encoding/hex"
	"crypto/rand"
	"crypto/sha256"
)

var handler map[string]*immledger.ImmLedger = make(map[string]*immledger.ImmLedger)

func generateHandlerID(username string) (id string) {
	randNum := make([]byte, 16)
	rand.Read(randNum)

	buf := append(randNum, []byte(username)...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8])
}

//export OpenKey
func OpenKey(c_userAndOrg, c_path, c_password *C.char) (retID, retErr *C.char) {
	userAndOrg := C.GoString(c_userAndOrg)
	path := C.GoString(c_path)
	password := C.GoString(c_password)

	ledger, err := immledger.OpenKey(userAndOrg, path, password)
	if err != nil {
		retErr = C.CString(err.Error())
		return
	}

	id := generateHandlerID(userAndOrg)
	handler[id] = ledger
	retID = C.CString(id)
	return
}

//export CloseKey
func CloseKey(c_ID *C.char) (*C.char) {
	id := C.GoString(c_ID)
	
	_, ok := handler[id]
	if !ok {
		return C.CString("invalid id")
	}

	delete(handler, id)
	return nil
}

//export RecordImmData
func RecordImmData(c_ID, c_storageGrp, c_key, c_msg *C.char) *C.char {
	id := C.GoString(c_ID)
	storageGrp := C.GoString(c_storageGrp)
	keyName := C.GoString(c_key)
	msg:= C.GoString(c_msg)

	hdl, ok := handler[id]
	if !ok {
		return C.CString("invalid id")
	}
	
	err := hdl.Write(storageGrp, keyName, msg)
	if err != nil {
		return C.CString(err.Error())
	}
	
	return nil
}

//export GetTxID
func GetTxID(c_ID, c_storageGrp, c_key *C.char) (response, retErr *C.char) {
	id := C.GoString(c_ID)
	storageGrp := C.GoString(c_storageGrp)
	keyName := C.GoString(c_key)

	hdl, ok := handler[id]
	if !ok {
		retErr = C.CString("invalid id")
		return
	}
	
	txIDs, err := hdl.GetTxID(storageGrp, keyName)
	if err != nil {
		retErr = C.CString(err.Error())
		return
	}

	txIdArray := &libimmds.TxIdList{}
	txIdArray.TxID = txIDs
	txIdBuf, err := proto.Marshal(txIdArray)
	if err != nil {
		retErr = C.CString("failed to marshal TxIDs: " + err.Error())
		return
	}

	responseTmp := (C.malloc(C.size_t(len(txIdBuf))))
	if len(txIdBuf) > (1<<26)/*64MB*/ {
		retErr = C.CString("It is too many IDs on the ledger to response")
		return
	}
	copy((*[1<<26]byte)(responseTmp)[0:len(txIdBuf)], txIdBuf)
	response = (*C.char)(responseTmp)
	
	return
}

//export GetBlockByTxID
func GetBlockByTxID(c_ID, c_storageGrp, c_txID *C.char) (response *C.char, rspLen C.ulong, retErr *C.char) {
	id := C.GoString(c_ID)
	storageGrp := C.GoString(c_storageGrp)
	txID := C.GoString(c_txID)
	
	hdl, ok := handler[id]
	if !ok {
		retErr = C.CString("invalid id")
		return
	}
	

	block, err := hdl.GetBlockByTxID(storageGrp,txID)
	if err != nil {
		retErr = C.CString(err.Error())
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

