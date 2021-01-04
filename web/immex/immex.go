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

import (
	"websto"
	"syscall/js"
	"sync/atomic"
	"github.com/golang/protobuf/proto"
	"strings"
	"fmt"
)

const (
	immsrvPath = "/immsrv"
)


func registerJsFunc() {
	gl := js.Global()
	gl.Set("recordImmData", js.FuncOf(recordImmData))
	gl.Set("getTxID", js.FuncOf(getTxID))
	gl.Set("getTxIDComp", js.FuncOf(getTxIDComp))
	gl.Set("getBlockByTxID", js.FuncOf(getBlockByTxID))
	gl.Set("getBlockByTxIDComp", js.FuncOf(getBlockByTxIDComp))
}

func recordImmData(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

	if len(in) != 3 {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New("unexpected argument"))
	}

	storageGrp := in[0].String()
	progName := in[1].String()
	recordLogText := in[2].String()

	id, err := websto.GetCurrentID()
	if err != nil {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New(err.Error()))
	}

	if ! strings.Contains(storageGrp, ".") {
		org, _ := id.GetIssuerOrg()
		storageGrp += "." + org
	}

	print("log: " + progName + ": " + recordLogText + "\n")
	go func() {
		err = id.RecordLedger(storageGrp, progName, recordLogText, url)
		if err != nil {
			print("log: failed to record ledger: " + err.Error() + "\n")
			return
		}
	}()

	return gl.Get("Promise").Call("resolve")
}

var getTxIdLock = int32(0)
var txIdArray []string

func getTxID(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

	if len(in) != 2 {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New("unexpected argument"))
	}
	storageGrp := in[0].String()
	progName := in[1].String()

	id, err := websto.GetCurrentID()
	if err != nil {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New(err.Error()))
	}

	if ! strings.Contains(storageGrp, ".") {
		org, _ := id.GetIssuerOrg()
		storageGrp += "." + org
	}

	if atomic.CompareAndSwapInt32(&getTxIdLock, 0, 1) == false {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New("another task is in progress"))
	}


	go func(){
		defer func() { getTxIdLock = 0 }()

		history, err := id.ReadLedger(storageGrp, progName, url)
		if err != nil {
			print("log: could not read ledger: " + err.Error() + "\n")
			return
		}

		txIdArray = make([]string, len(*history))
		for i, item := range *history {
			txIdArray[i] = item.TxId
		}
	}()

	return gl.Get("Promise").Call("resolve")
}

func getTxIDComp(this js.Value, in []js.Value) interface{} {
	gl := js.Global()

	print("log: getTxIdOnLedgerComp")
	if atomic.CompareAndSwapInt32(&getTxIdLock, 0, 1) == false {
		return gl.Get("Promise").Call("reject")
	}
	defer func() { getTxIdLock = 0 }()
	
	fmt.Printf("log: getTxIdOnLedgerComp: length=%d\n", len(txIdArray))

	txIdList := gl.Get("Array").New()
	for i, txId := range txIdArray {
		txIdList.SetIndex(i, txId)
	}
	txIdArray = make([]string, 0)

	return gl.Get("Promise").Call("resolve", txIdList)
}

var getBlockByTxIDLock = int32(0)
var blockArray []byte

func getBlockByTxID(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	loc := gl.Get("location")
	url := loc.Get("protocol").String() + "//" + loc.Get("host").String() + immsrvPath

	if len(in) != 2 {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New("unexpected argument"))
	}
	storageGrp := in[0].String()
	txId := in[1].String()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New(err.Error()))
	}

	if ! strings.Contains(storageGrp, ".") {
		org, _ := id.GetIssuerOrg()
		storageGrp += "." + org
	}
	
	if atomic.CompareAndSwapInt32(&getBlockByTxIDLock, 0, 1) == false {
		return gl.Get("Promise").Call("reject", gl.Get("Error").New("another task is in progress"))
	}
	
	go func(){
		defer func() { getBlockByTxIDLock = 0 }()

		block, err := id.QueryBlockByTxID(storageGrp, txId, url)
		if err != nil {
			print("log: could not read block: " + err.Error() + "\n")
			return
		}

		blockArray, err = proto.Marshal(block)
		if err != nil {
			print("log: failed to marshal block: " + err.Error() + "\n")
			return
		}
	}()
		
	return gl.Get("Promise").Call("resolve")
}

func getBlockByTxIDComp(this js.Value, in []js.Value) interface{} {
	gl := js.Global()

	if atomic.CompareAndSwapInt32(&getBlockByTxIDLock, 0, 1) == false {
		return gl.Get("Promise").Call("reject")
	}
	defer func() { getBlockByTxIDLock = 0 }()

	blockDataArray := gl.Get("Uint8Array").New(len(blockArray))
	js.CopyBytesToJS(blockDataArray, blockArray)
	blockArray = make([]byte, 0)

	return gl.Get("Promise").Call("resolve", blockDataArray)
}


func main() {
	print("log: before registerJsFunc\n")
	registerJsFunc()
	print("log: after registerJsFunc\n")
	ch := make(chan struct{}, 0)
	<- ch
}
