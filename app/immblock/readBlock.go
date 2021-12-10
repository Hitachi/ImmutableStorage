/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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

package immblock

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	pp "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/ledger/rwset"
	"github.com/hyperledger/fabric/protos/ledger/rwset/kvrwset"
	
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"math/big"
	"time"
	"errors"
	"strconv"
	"immsign"
	//	"fmt"
)

type InstanceValue struct {
        Format  string
        Log  string
}

type ECDSASignature struct {
	R, S *big.Int
}

//var LB = "\n"
var LB = "<br>\n"
var BLOCK_PREFIX = ""
var BLOCK_SUFFIX = "\n"

func ReadBlocks(blocks []byte) (retStr string, retErr error) {
	if len(blocks) < 4 {
		retErr = errors.New("unexpected block data")
		return
	}
	
	block := &common.Block{}

	blockSize := uint32(0)
	blockSpacing := uint32(0)
	needSize := uint32(0)
	for readP := uint32(0); len(blocks) > int(readP+blockSpacing); readP += blockSize {
		blockSize = uint32(blocks[readP])|uint32(blocks[readP+1])<<8|uint32(blocks[readP+2])<<16|uint32(blocks[readP+3])<<24
		blockSize &= needSize
		blockSize |= uint32(len(blocks)) & ^needSize

		readP += blockSpacing
		err := proto.Unmarshal(blocks[readP:readP+blockSize], block)
		if err != nil {
			if blockSpacing == 0 {
				blockSpacing += 4
				needSize = ^needSize
				blockSize = 0
				continue
			}
			retErr = errors.New("failed to unmarshal: " + err.Error())
			return
		}

		retStr += BLOCK_PREFIX
		var str string
		str, retErr = ReadBlock(block)
		if retErr != nil {
			return
		}
		retStr += str
		retStr += BLOCK_SUFFIX
	}

	return
}

func ReadBlock(block *common.Block) (retStr string, retErr error) {
	bEnvelope := &common.Envelope{}
	payload := &common.Payload{}
	chHdr := &common.ChannelHeader{}
	signHdr := &common.SignatureHeader{}	

	retStr += "Number: " + strconv.Itoa(int(block.Header.Number))
	retStr += ", block size: " + strconv.Itoa(proto.Size(block)) + LB
	retStr += "previous header sum: " + hex.EncodeToString(block.Header.PreviousHash) + LB
	retStr += "calculated header sum: " + hex.EncodeToString(block.Header.Hash()) + LB
	

	//	fmt.Printf("%s\n", proto.MarshalTextString(block))

	if len(block.Metadata.Metadata) < 4 {
		retErr = errors.New("unexpected number of metadata: "+ strconv.Itoa(len(block.Metadata.Metadata)))
		return
	}
	
	metaRaw := block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES]
	meta := &common.Metadata{}
	err := proto.Unmarshal(metaRaw, meta)
	if err != nil {
		retErr = errors.New("invalid signautre: " + err.Error())
		return
	}
	for _, metaSign := range meta.Signatures {
		err = proto.Unmarshal(metaSign.SignatureHeader, signHdr)
		if err != nil {
			retErr =  errors.New("invalid signer: " + err.Error())
			return
		}
		
		verifiedData := append(meta.Value, metaSign.SignatureHeader...)
		verifiedData = append(verifiedData, block.Header.Bytes()...)
		strGrpCert, err := immsign.VerifySignatureCreator(signHdr.Creator, metaSign.Signature, verifiedData)
		verifyS := "verification failure"
		strGrpName := "unknown"
		if err == nil {
			verifyS = "verified"
		}
		if strGrpCert != nil {
			strGrpName = strGrpCert.Subject.CommonName
		}

		retStr += "storage group: " + strGrpName + LB
		retStr += "signature for header: " + hex.EncodeToString(metaSign.Signature)
		retStr += ": " + verifyS + LB
	}

	/*
	metaRaw = block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES]
	lastConfig := &common.LastConfig{}
	err = proto.Unmarshal(metaRaw, lastConfig)
	if err != nil {
		return errors.New("invalid last configuration: " + err.Error())
	}
	fmt.Printf("last configuration index: %d\n", lastConfig.Index)
	*/

	dataHash := hex.EncodeToString(block.Header.DataHash)
	retStr += "contained data sum: " + dataHash + LB
	verifyHash := sha256.New()
	for _, blockData := range block.Data.Data {
		verifyHash.Write(blockData)
	}
	calcSum := hex.EncodeToString(verifyHash.Sum(nil))
	retStr += "calculated data sum: " +  calcSum + ": "
	verifyResult := "OK"
	if calcSum != dataHash {
		verifyResult = "NG"
	}
	retStr += verifyResult + LB
	
	
	for _, blockData := range block.Data.Data {
		err = proto.Unmarshal(blockData, bEnvelope)
		if err != nil {
			retErr = errors.New("error: unexpected block data: " + err.Error())
			return
		}
		
		err = proto.Unmarshal(bEnvelope.Payload, payload)
		if err != nil {
			retErr = errors.New("error: unexpected block payload: " + err.Error())
			return
		}
		
		err = proto.Unmarshal(payload.Header.ChannelHeader, chHdr)
		if err != nil {
			retErr = errors.New("error: unexpected channel header: " + err.Error())
			return
		}
		err = proto.Unmarshal(payload.Header.SignatureHeader, signHdr)
		if err != nil {
			retErr = errors.New("error: unexpected signature header: " + err.Error())
			return
		}
		
		retStr += "type: " + common.HeaderType(chHdr.Type).String() + LB
		t := time.Unix(chHdr.Timestamp.Seconds, int64(chHdr.Timestamp.Nanos))
		retStr += "timestamp: " + t.Local().Format(time.UnixDate) + LB
		
		if common.HeaderType(chHdr.Type) != common.HeaderType_ENDORSER_TRANSACTION {
			continue
		}
		
		// endorser transaction
		
		creatorCert, err := immsign.VerifySignatureCreator(signHdr.Creator, bEnvelope.Signature, bEnvelope.Payload)
		verifyS := "verification failure"
		creatorName := "unknown"
		if err == nil {
			verifyS = "verified"
		}
		if creatorCert != nil {
			creatorName = creatorCert.Subject.CommonName
		}
		retStr += "Creator: " + creatorName + LB
		retStr += "signature for payload: "+ hex.EncodeToString(bEnvelope.Signature) + ": "+verifyS + LB
		
		chExt := &pp.ChaincodeHeaderExtension{}
		err = proto.Unmarshal(chHdr.Extension, chExt)
		if err != nil {
			retErr = errors.New("invalid chaincode header: " + err.Error())
			return
		}
		
		trans := &pp.Transaction{}
		err = proto.Unmarshal(payload.Data, trans)
		if err != nil {
			retErr = errors.New("invalid payload: " + err.Error())
			return
		}
		ccAction := &pp.ChaincodeActionPayload{}
		err = proto.Unmarshal(trans.Actions[0].Payload, ccAction)
		if err != nil {
			retErr = errors.New("invalid chaincode action payload: " + err.Error())
			return
		}
		
		//fmt.Printf("ccAction:\n%s\n", proto.MarshalTextString(ccAction))
		ccPropPayload := &pp.ChaincodeProposalPayload{}
		err = proto.Unmarshal(ccAction.ChaincodeProposalPayload, ccPropPayload)
		if err != nil {
			retErr = errors.New("invalid chaincode proposal payload: " + err.Error())
			return
		}
		//fmt.Printf("ccPropPayload:\n%s\n", proto.MarshalTextString(ccPropPayload))
		
		proposalRsp := &pp.ProposalResponsePayload{}
		err = proto.Unmarshal(ccAction.Action.ProposalResponsePayload, proposalRsp)
		if err != nil {
			retErr = errors.New("invalid proposal response payload: " + err.Error())
			return
		}
		
		for _, endorser := range ccAction.Action.Endorsements{
			msg := append(ccAction.Action.ProposalResponsePayload, endorser.Endorser...)				
			cert, err := immsign.VerifySignatureCreator(endorser.Endorser, endorser.Signature, msg)
			
			verifyS := "verification failure"
			storageName := "unknown"
			if err == nil {
				verifyS = "verified"
			}
			if cert != nil {
				storageName = cert.Subject.CommonName
			}
			retStr += "stored storage: " + storageName + LB
			retStr += "signature for action: "+hex.EncodeToString(endorser.Signature)
			retStr += ": " + verifyS + LB
		}
		
		ccAct := &pp.ChaincodeAction{}
		err = proto.Unmarshal(proposalRsp.Extension, ccAct)
		if err != nil {
			retErr = errors.New("invalid extension: " + err.Error())
			return
		}
		
		//fmt.Printf("rspPayload:\n%s\n", proto.MarshalTextString(proposalRsp))
		//fmt.Printf(" ccAct: \n%s\n", proto.MarshalTextString(ccAct))
		
		txRwset := &rwset.TxReadWriteSet{}
		err = proto.Unmarshal(ccAct.Results, txRwset)
		if err != nil {
			retErr = errors.New("invalid results: " + err.Error())
			return
		}
		
		// fmt.Printf("  rwset: \n%s\n", proto.MarshalTextString(txRwset))
		for _, nsRwset := range txRwset.NsRwset {
			if nsRwset.Namespace != "hlRsyslog" {
				continue
			}
				
			kvRwset := &kvrwset.KVRWSet{}
			err = proto.Unmarshal(nsRwset.Rwset, kvRwset)
			if err != nil {
				retErr = errors.New("invalid read write set: " + err.Error())
				return
			}
			
			if kvRwset.Writes == nil {
				continue
			}
			
			value := &InstanceValue{}
			err := json.Unmarshal(kvRwset.Writes[0].Value, value)
			if err != nil {
				retErr = errors.New("unexpected key-value format: " + err.Error())
				return
			}
			retStr += "ledger: " +  value.Log + LB
			//fmt.Printf("key value rwset:\n%s\n",  proto.MarshalTextString(kvRwset))
		}
	}

	return
}
