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

package rwlog

import (
	"strconv"
	"time"
	"crypto/x509"
	"encoding/pem"
	"google.golang.org/protobuf/proto"
	"fabric/protos/common"
	"fabric/protos/msp"
	pp "fabric/protos/peer"
	
	"immclient"
	wu "webutil"
)	

func PrintLedger(id *immclient.UserID, url, storageGrp, rkey string) (html, errMsg string) {
	history, err := id.ReadLedger(storageGrp, rkey, url)
	if err != nil {
		//print("log: could not read ledger: " + err.Error() + "\n")
		errMsg = "error: could not read " + rkey +" log: " + err.Error()
		return
	}
	
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

		/*
			proposalRsp := &pp.ProposalResponsePayload{}
			err = proto.Unmarshal(ccAction.Action.ProposalResponsePayload, proposalRsp)
			if err != nil {
				errMsg = "error: unexpected proposal response payload: " + err.Error()
				return
			}*/
		ccActionPayload := &pp.ChaincodeProposalPayload{}
		err = proto.Unmarshal(ccAction.ChaincodeProposalPayload, ccActionPayload)
		if err != nil {
			errMsg = "error: unexpected chaincode proposal payload: " + err.Error()
			return
		}

		ccActionInput := &pp.ChaincodeInvocationSpec{}
		err = proto.Unmarshal(ccActionPayload.Input, ccActionInput)
		if err != nil {
			errMsg = "error: failed to read chaincode inputs in a block: " + err.Error()
			return
		}
		inputArgs := ccActionInput.ChaincodeSpec.Input.Args
		if len(inputArgs) < 4 {
			errMsg = "error: unexpected block: number of arguments " + strconv.Itoa(len(inputArgs))
			return
		}
			
		funcName := string(inputArgs[0])
		progKeyName := string(inputArgs[1])
		// logFormat := string(inputArgs[2])
		prog1Log  := string(inputArgs[3])
		
		if funcName != "addLog" {
			errMsg = "error: unexpected function: " + funcName + "\n"
			return
		}
		if progKeyName != rkey {
			errMsg = "error: unexpected key: " + prog1Log + "\n"
			return
		}
		

		html += "<tr>"
		html += `<td>` + strconv.Itoa(i+1) + "</td>"
		//			html += "<td>" + item.TxId + "</td>" // transaction id
		t := time.Unix(item.Timestamp.GetSeconds(), int64(item.Timestamp.GetNanos()))
		html += `<td>` + t.Local().Format(time.UnixDate) + "</td>"
		html += "<td>" + prog1Log + "</td>" // Log
		
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
	return // success
}


func SaveLedger(id *immclient.UserID, url, storageGrp, rkey, htmlDataID string) (errMsg string) {
	history, err := id.ListTxId(storageGrp, rkey, url)
	if err != nil {
		errMsg = "error: could not read logs: " + err.Error()
		return
	}
	
	var blocks []*common.Block
	for i, txid := range *history {
		block, err := id.QueryBlockByTxID(storageGrp, txid, url)
		if err != nil {
			errMsg = "error: could not read ledger: " + err.Error()
			return
		}
		
		if i != 0 && (i % 2048) == 0 {
			ledgerFileName := "ledger_"+rkey+"_" + strconv.Itoa(i - 2048) + ".blocks"
			errMsg = saveLedgerFile(ledgerFileName, blocks, htmlDataID)
			if errMsg != "" {
				return
			}
			blocks = blocks[:0]
		}
		blocks = append(blocks, block)
	}
		
	ledgerFileName := "ledger_"+rkey+"_" + strconv.Itoa( (len(*history)/2048)*2048 ) + ".blocks"
	errMsg = saveLedgerFile(ledgerFileName, blocks, htmlDataID)
	return
}

func saveLedgerFile(fileName string, blocks []*common.Block, htmlDataID string) (errMsg string) {
	var buf []byte

	for _, block := range blocks {
		blockRaw, err := proto.Marshal(block)
		if err != nil {
			errMsg = "log: failed to marshal blocks: " + err.Error()
			return
		}
		
		blockLen := len(blockRaw)
		blockLenRaw := []byte{ byte(blockLen), byte(blockLen>>8), byte(blockLen>>16), byte(blockLen>>24) }

		buf = append(buf, blockLenRaw...)
		buf = append(buf, blockRaw...)
	}
	
	wu.SaveFile(fileName, buf, htmlDataID)
	return // success
}

