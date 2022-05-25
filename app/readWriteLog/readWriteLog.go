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
	"encoding/pem"
	"encoding/json"
	"crypto/x509"
	"syscall/js"
	"sync/atomic"
	"time"
	"strconv"
	
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	pp "github.com/hyperledger/fabric/protos/peer"

	"websto"
	"immclient"
	wu "webutil"
)

func main() {
	ch := make(chan struct{}, 0)
	registerCallback()
	makeContent()
	<- ch
}

func registerCallback() {
	gl := js.Global()
	gl.Set("selectedStorageGrp", js.FuncOf(selectedStorageGrp))
	gl.Set("recordLedger", js.FuncOf(recordLedger))
	gl.Set("saveLedger", js.FuncOf(saveLedger))

	wu.InitTab("openTab")
	wu.RegisterTab("appReadWriteLog", updateAppReadWriteLogContent)
	wu.RegisterTab("recordLedger", updateRecordLedgerContent)
	wu.RegisterTab("readLedger", updateReadLedgerContent)
	
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
}

func makeContent() {
	doc := js.Global().Get("document")
	rdwtLogContent := doc.Call("getElementById", "readWriteLogContent")

	defaultTab := wu.Tabs["appReadWriteLog"]
	tabHTML := defaultTab.MakeHTML("Read and Write Log", "1")
	html := tabHTML.MakeHTML()
	rdwtLogContent.Set("innerHTML", html)

	defaultTab.GetButton().Call("click")
}

func updateAppReadWriteLogContent(tabC *js.Value) {
	html := ""
		
	defer func() {
		tabC.Set("innerHTML", html)
	}()
		
	id, err := websto.GetCurrentID()
	if err != nil {
		html += "<h3>You are invalid user</h3>"
		return
	}
		
	html += "<h3>" + id.Name + "</h3>"
	html += `<div class="space"></div>`

	tabHTML := &wu.TabHTML{}
	tabHTML.AppendTab(wu.Tabs["recordLedger"].MakeHTML("Write Log", "2"))
	tabHTML.AppendTab(wu.Tabs["readLedger"].MakeHTML("Read Log", "2"))
	html += tabHTML.MakeHTML()
	return
}

var recordLedgerContentLock = int32(0)
func updateRecordLedgerContent(tabC *js.Value) {
	print("log: updateRecordLedgerContent\n")
	url := wu.GetImmsrvURL()

	if atomic.CompareAndSwapInt32(&recordLedgerContentLock, 0, 1) == false {
		return
	}
	defer func() { recordLedgerContentLock = 0 }()

	errMsg := ""
	defer func() {
		if errMsg == "" {
			return
		}
		wu.VisibleMsgBox(errMsg)
	}()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		errMsg = "You are invalid user: " + err.Error()
		return
	}

	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil {
		errMsg = "There is no group in your storage: " + err.Error()
		return
	}
	if len(storageGrpList) < 1 {
		errMsg = "There is no group in your storage."
		return
	}
		
	html := `<div class="cert-area">`
	html += `<div class="row">`
	
	html += `  <div class="cert-item"><label for="storageGrp">Storage group</label></div>`
	html += `  <div class="cert-input">`
	html += `    <select id="recordStorageGrp">`
	for _, storageGrp := range storageGrpList {
		html += `      <option value="`+storageGrp+`">`+storageGrp+`</option>`
	}
	html += `    </select>`
	html += `  </div>`
	html += `</div>`
	
	html += `<div class="row">`
	html += `  <div class="cert-item"><label>Ledger</label></div>`
	html += `  <div class="cert-input"><input type="text" id="recordLedgerText"></div>`
	html += `    <div class="immDSBtn">`
	html += `      <button onclick="recordLedger(event)" id="recordLedgerBtn">Record</button>`
	html += "    </div>"
	html += `</div>`
	
	html += `</div>`

	tabC.Set("innerHTML", html)
	return
}

func selectedStorageGrp(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		errMsg := ""
		defer func() {
			if errMsg == "" {
				return
			}
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			errMsg = "You are invalid user: " + err.Error()
			return
		}

		history, err := id.ReadLedger(storageGrp, "prog1", url)
		if err != nil {
			//print("log: could not read ledger: " + err.Error() + "\n")
			errMsg = "error: could not read prog1 log: " + err.Error()
			return
		}
	
		html := `<div class="immDSBtn">`
		html += `  <button onclick="saveLedger(event)">Save</button>`
		html += `  <a id="saveLedgerData"></a>`
		html += `</div>`
	
		html += `<table id="historyTable">`
		html += "<thread>"
		html += "<tr>"
		html += `  <th scope="col">#</th>`
//		html += `  <th scope="col">TxID</th>`
		html += `  <th scope="col">Timestamp</th>`
		html += `  <th scope="col">Log</th>`
		html += `  <th scope="col">Recorded storage</th>`
		html += `  <th scope="col">Creator</th>`
		html += `</tr>`
		html += "</thread>"

		instVal := &immclient.InstanceValue{}

		html += "<tbody>"
		for i, item := range *history {

			bEnvelope := &common.Envelope{}
			payload := &common.Payload{}
			chHdr := &common.ChannelHeader{}
			signHdr := &common.SignatureHeader{}
			foundTxIdF := false

			block, err := id.QueryBlockByTxID(storageGrp, item.TxId, url)
			if err != nil {
				errMsg = "error: failed to get a block: " + err.Error()
				return
			}
			for _, blockData := range block.Data.Data {
				err = proto.Unmarshal(blockData, bEnvelope)
				if err != nil {
					errMsg = "error: unexpected block data: " + err.Error()
					return
				}

				err = proto.Unmarshal(bEnvelope.Payload, payload)
				if err != nil {
					errMsg =  "error: unexpected block payload: " + err.Error()
					return
				}
				err = proto.Unmarshal(payload.Header.ChannelHeader, chHdr)
				if err != nil {
					errMsg = "error: unexpected channel header: " + err.Error()
					return
				}
				
				foundTxIdF = (chHdr.TxId == item.TxId)
				if foundTxIdF {
					break
				}
			}
			if !foundTxIdF {
				errMsg = "error: not found TxId: " + item.TxId
				return
			}

			err = proto.Unmarshal(payload.Header.SignatureHeader, signHdr)
			if err != nil {
				errMsg = "error: unexpected signature header: " + err.Error()
				return
			}
			creator := &msp.SerializedIdentity{}
			err = proto.Unmarshal(signHdr.Creator, creator)
			if err != nil {
				errMsg = "error: failed to unmarshal creator: " + err.Error()
				return
			}
			creatorPem, _ := pem.Decode(creator.IdBytes)
			creatorCert, err := x509.ParseCertificate(creatorPem.Bytes)
			if err != nil {
				errMsg = "error: unexpected certificate for a creator: " + err.Error()
				continue
			}

			chExt := &pp.ChaincodeHeaderExtension{}
			err = proto.Unmarshal(chHdr.Extension, chExt)
			if err != nil {
				errMsg = "error: unexpected chaincode header: " + err.Error()
				return
			}
			
			trans := &pp.Transaction{}
			err = proto.Unmarshal(payload.Data, trans)
			if err != nil {
				errMsg = "error: unexpected data: " + err.Error()
				return
			}
			ccAction := &pp.ChaincodeActionPayload{}
			err = proto.Unmarshal(trans.Actions[0].Payload, ccAction)
			if err != nil {
				errMsg = "error: unexpected chaincode action payload: " + err.Error()
				return
			}

			proposalRsp := &pp.ProposalResponsePayload{}
			err = proto.Unmarshal(ccAction.Action.ProposalResponsePayload, proposalRsp)
			if err != nil {
				errMsg = "error: unexpected proposal response payload: " + err.Error()
				return
			}

			html += "<tr>"
			html += `<td>` + strconv.Itoa(i+1) + "</td>"
//			html += "<td>" + item.TxId + "</td>" // transaction id
			t := time.Unix(item.Timestamp.GetSeconds(), int64(item.Timestamp.GetNanos()))
			html += `<td>` + t.Local().Format(time.UnixDate) + "</td>"
			json.Unmarshal(item.Value, instVal)
			html += "<td>" + string(instVal.Log) + "</td>" // Log

			html += "<td>"
			sId := &msp.SerializedIdentity{}
			for endorserN, endorser := range ccAction.Action.Endorsements {
				err = proto.Unmarshal(endorser.Endorser, sId)
				if err != nil {
					print(err.Error()+"\n")
					return
				}
				
				p, _ := pem.Decode(sId.IdBytes)
				if p.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(p.Bytes)
				if err != nil {
					print(err.Error()+"\n")
					continue
				}

				if endorserN != 0 {
					html += "<br>"
				}
				html += cert.Subject.CommonName
			}
			html += "</td>"
			html += "<td>" + creatorCert.Subject.CommonName + "</td>"

			html += "</tr>"
		}
		html += "</tbody>"
		html += "</table>"

		readLedgerList := doc.Call("getElementById", "readLedgerList")
		readLedgerList.Set("innerHTML", html)
	}()

	return nil
}


func recordLedger(this js.Value, in []js.Value) interface{} {
	url := wu.GetImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		errMsg := ""
		defer func() {
			if errMsg == "" {
				return
			}
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			return
		}

		recordLogText := doc.Call("getElementById", "recordLedgerText").Get("value").String()
		if recordLogText == "" {
			errMsg = "You are invalid user: " + err.Error()
			return // ignore
		}

		wu.VisibleSimpleMsgBox("Writing...")
		err = id.RecordLedger(storageGrp, "prog1", recordLogText, url)
		if err != nil {
			errMsg = "error: failed to record a prog1 log: " + err.Error()
			return
		}

		errMsg = "Success" // success
	}()

	return nil
}

var readLedgerContentLock = int32(0)
func updateReadLedgerContent(tabC *js.Value) {
	url := wu.GetImmsrvURL()

	if atomic.CompareAndSwapInt32(&readLedgerContentLock, 0, 1) == false {
		return
	}
	defer func() { readLedgerContentLock = 0 }()

	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil {
		return
	}
	if len(storageGrpList) < 1 {
		return
	}
		
	html := `<div class="cert-area">`
		
	html += `<div class="row">`
	html += `  <div class="cert-item"><label for="storageGrp">Storage group</label></div>`
	html += `  <div class="cert-input">`
	html += `    <select id="readStorageGrp" onchange="selectedStorageGrp()">`
	html += `      <option disabled selected value> -- select storage group -- </option>`
	for _, storageGrp := range storageGrpList {
		html += `      <option value="`+storageGrp+`">`+storageGrp+`</option>`
	}
	html += `    </select>`
	html += `  </div>`
	html += `</div>`
		
	html += `<div class="row" id="readLedgerList">`
	html += `</div>`
		
	html += `</div>`
		
	tabC.Set("innerHTML", html)
}	


var saveLedgerLock = int32(0)
func saveLedger(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()

	storageGrpSel := doc.Call("getElementById", "readStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()

	go func() {
		if atomic.CompareAndSwapInt32(&saveLedgerLock, 0, 1) == false {
			return
		}
		defer func() { saveLedgerLock = 0 }()

		errMsg := ""
		defer func() {
			if errMsg == "" {
				return
			}
			wu.VisibleMsgBox(errMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			errMsg = "You are invalid user: " + err.Error()
			return
		}
		
		history, err := id.ReadLedger(storageGrp, "prog1", url)
		if err != nil {
			errMsg = "error: could not read prog1 logs: " + err.Error()
			return
		}
		
		var blocks []*common.Block
		for i, item := range *history {
			block, err := id.QueryBlockByTxID(storageGrp, item.TxId, url)
			if err != nil {
				errMsg = "error: could not read ledger: " + err.Error()
				return
			}

			if i != 0 && (i % 2048) == 0 {
				ledgerFileName := "ledger_prog1_" + strconv.Itoa(i - 2048) + ".blocks"
				saveLedgerFile(ledgerFileName, blocks)
				blocks = blocks[:0]
			}
			blocks = append(blocks, block)
		}
		
		ledgerFileName := "ledger_prog1_" + strconv.Itoa( (len(*history)/2048)*2048 ) + ".blocks"
		saveLedgerFile(ledgerFileName, blocks)
	}()

	return nil
}

func saveLedgerFile(fileName string, blocks []*common.Block) {
	var buf []byte

	for _, block := range blocks {
		blockRaw, err := proto.Marshal(block)
		if err != nil {
			print("log: failed to marshal blocks: " + err.Error() + "\n")
			return
		}
		
		blockLen := len(blockRaw)
		blockLenRaw := []byte{ byte(blockLen), byte(blockLen>>8), byte(blockLen>>16), byte(blockLen>>24) }

		buf = append(buf, blockLenRaw...)
		buf = append(buf, blockRaw...)
	}
	
	wu.SaveFile(fileName, buf, "saveLedgerData")
}
