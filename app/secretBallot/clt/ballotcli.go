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

package ballotcli

import (
	"crypto/x509"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"encoding/json"
	"encoding/base64"
	"strconv"
	"errors"
	"time"
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	pp "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/ledger/rwset"
	"github.com/hyperledger/fabric/protos/ledger/rwset/kvrwset"
	
	"immclient"
	"immop"
	"immconf"
	"immsign"
)

const (
	FCreateBox = "CreateBox"
	FSelectVoter = "SelectVoter"
	FGetPaper = "GetPaper"
	FGetSealKey = "GetSealKey"
	FVote = "Vote"
	FGetResultVote = "GetResultVote"
	FGetVoterState = "GetVoterState"

	RKEY_BoxPub = "boxPub"
	RKEY_SealPub1 = "sealPub1"
	RKEY_SealPub2 = "sealPub2"
	RKEY_Paper = "paper"
	RKEY_PollTimes = "pollTimes"
	RKEY_BallotBox = "ballotBox"
	RKEY_OpenedBox = "openedBox"
	RKEY_OpenedBoxName = "openedBoxName"
	RKEY_Result = "resultVote"

	ROLE_Prefix = "imm.Role."
	ROLE_AdminOfficial = "AdminOfficial"
	ROLE_ElectionOfficial = "ElectionOfficial"
	ROLE_AdminVoterReg = "AdminVoterReg"
	ROLE_VoterReg = "VoterReg"
	ROLE_Voter = "Voter"
	ROLE_BallotBoxAgent = "BallotBox"

	VoterGrp = "@voter"
	VoterGrpForJPKI = "@JPKI@voter"

	VOTER_STA = "imm.VoterState"
	VOTER_STA_registered = "registered"
	VOTER_STA_voted = "voted"
)

func ballotFunc(id *immclient.UserID, url, funcName string, req, reply interface{}) (retJson []byte, retErr error) {
	var reqJson []byte
	var err error
	if req != nil {
		reqJson, err = json.Marshal(req)
		if err != nil {
			retErr = errors.New(funcName + ": unexpected request: " + err.Error())
			return
		}
	}
	
	conn, err := grpc.Dial(url, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true,})))
	if err != nil {
		retErr = errors.New(funcName + ": " + err.Error())
		return
	}
	defer conn.Close()
	
	cli := immop.NewImmOperationClient(conn)
	reqGrpc := &immop.BallotFuncRequest{
		Func: funcName,
		Req: reqJson,
	}

	var reqFunc = func(reqTime string) (retRspRaw []byte, retryTime string, retErr error) {
		reqGrpc.Time = reqTime
		reqGrpc.Cred = nil
		reqGrpc.Cred, err = id.SignMsg("BallotFunc", reqGrpc)
		if err != nil {
			retErr = errors.New("failed to add a signature for this request: " + err.Error())
			return
		}
		
		rsp, err := cli.BallotFunc(context.Background(), reqGrpc)
		if err != nil {
			retErr = errors.New(funcName + ": " + err.Error())
			return // error
		}

		retryTime = rsp.Time
		retRspRaw = rsp.Rsp
		return
	}
	
	rspRaw, retryTime, err := reqFunc(time.Now().Format(time.RFC3339))
	if retryTime != "" {
		rspRaw, retryTime, err = reqFunc(retryTime)
	}	
	if err != nil {
		retErr = err
		return
	}
	if retryTime != "" {
		retErr = errors.New("Your computer time is incorrect.")
		return
	}

	if reply == nil {
		retJson = rspRaw
		return // success
	}
	
	err = json.Unmarshal(rspRaw, reply)
	if err != nil {
		retErr = errors.New(funcName + ": unexpected response: " + err.Error())
		return
	}

	return // success
}

type CreateBoxRequest struct {
	Pub []byte `json:"Pub"`
}

type CreateBoxReply struct {
	BoxPub []byte `json:"BoxPub"`
}

func CreateBox(id *immclient.UserID, url, storageGrp string) (retErr error) {
	req := CreateBoxRequest{
		Pub: id.Cert,
	}
	boxPubKey, err := ballotFunc(id, url, FCreateBox, req, nil)
	if err != nil {
		retErr = err
		return
	}

	err = id.RecordLedger(storageGrp, RKEY_BoxPub, string(boxPubKey), url)
	if err != nil {
		retErr = errors.New("failed to record a public key for the ballot box: " + err.Error())
		return
	}

	err = id.RecordLedger(storageGrp, RKEY_SealPub2, id.Name, url)
	if err != nil {
		retErr = errors.New("failed to record a public key: " + err.Error())
	}
	return // success
}

func SetSealPubKey(id *immclient.UserID, url string) (retErr error) {
	storageGrp, err := GetStorageForBallotBox(id, url)
	if err != nil {
		retErr = err
		return
	}
	
	err = id.RecordLedger(storageGrp, RKEY_SealPub1, id.Name, url)
	if err != nil {
		retErr = errors.New("failed to record a public key: " + err.Error())
		return
	}
	return // success
}

func GetBallotBoxPubKey(id *immclient.UserID, url, storageGrp string) (boxCertPem []byte, retErr error) {
	recorder, signature, message, err := GetLastRecord(id, url, storageGrp, RKEY_BoxPub)
	if err != nil {
		retErr = err
		return
	}
	
	boxCertJson, cert, err := GetRecordValue(recorder, signature, message)
	if err != nil {
		retErr = err
		return
	}

	role := immclient.GetCertRole(cert)
	if role != ROLE_AdminOfficial {
		retErr = errors.New("unexpected recorder: " + role)
		return
	}
	
	boxCertRaw := &CreateBoxReply{}
	err = json.Unmarshal([]byte(boxCertJson), boxCertRaw)
	if err != nil {
		retErr = errors.New("not found : " + err.Error())
		return
	}
	boxCertPem = boxCertRaw.BoxPub	

	return // success
}

func GetStorageAndBoxCert(id *immclient.UserID, url string) (storageGrp string, boxCertPem []byte, retErr error) {
	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil || len(storageGrpList) <= 0 {
		retErr = errors.New("Not found storage: " + err.Error())
		return
	}

	errMsg := ""
	for _, storageGrp = range storageGrpList {
		boxCertPem, err = GetBallotBoxPubKey(id, url, storageGrp)
		if err == nil {
			return // success
		}

		errMsg += ", " + storageGrp + ": " + err.Error()
	}

	retErr = errors.New("not found bollot box" + errMsg)
	return	
}

func GetStorageForBallotBox(id *immclient.UserID, url string) (storageGrp string, retErr error) {
	storageGrp, _, retErr = GetStorageAndBoxCert(id, url)
	return
}

type PollTimes struct {
	OpeningTime string
	ClosingTime string
}

func SetPollTimes(id *immclient.UserID, url string, pollTimes *PollTimes) (retErr error) {
	storageGrp, err := GetStorageForBallotBox(id, url)
	if err != nil {
		retErr = err
		return
	}
	
	jsonPollTimes, _ := json.Marshal(pollTimes)
	err = id.RecordLedger(storageGrp, RKEY_PollTimes, string(jsonPollTimes), url)
	if err != nil {
		retErr = err
		return
	}
	return // success
}

type OpenedBoxName struct {
	Time string
	Name string
}

func SetOpenedBoxName(id *immclient.UserID, url, storageGrp string) (rkeyName string, retErr error) {
	boxName := &OpenedBoxName{
		Time: time.Now().Format(time.RFC3339),
		Name: RKEY_OpenedBox + immclient.RandStr(16),
	}
	jsonBoxName, _ := json.Marshal(boxName)
	retErr = id.RecordLedger(storageGrp, RKEY_OpenedBoxName, string(jsonBoxName), url)
	if retErr != nil {
		return
	}

	rkeyName = boxName.Name
	return
}

func GetOpenedBoxName(id *immclient.UserID, url, storageGrp string) (rKeyName string, retErr error) {
	recorder, signature, message, retErr := GetLastRecord(id, url, storageGrp, RKEY_OpenedBoxName)
	if retErr != nil {
		return
	}

	boxNameJson, cert, retErr := GetRecordValue(recorder, signature, message)
	if retErr != nil {
		return
	}

	role := immclient.GetCertRole(cert)
	if role != ROLE_AdminOfficial {
		retErr = errors.New("unexpected recorder: " + role)
		return
	}

	boxName := &OpenedBoxName{}
	err := json.Unmarshal([]byte(boxNameJson), boxName)
	if err != nil {
		retErr = errors.New("unexpected name format: " + err.Error())
		return
	}

	rKeyName = boxName.Name
	return // success
}

func OpenBallotBox(id *immclient.UserID, url string) (retErr error) {
	storageGrp, boxCertPem, err := GetStorageAndBoxCert(id, url)
	if err != nil {
		retErr = err
		return
	}

	openBoxKey, err := immconf.GetConfidentialTool(id.Priv, boxCertPem, "")
	if err != nil {
		retErr = errors.New("failed to get a key for the ballot box")
		return
	}

	txIDs, err := id.ListTxId(storageGrp, RKEY_BallotBox, url)
	if err != nil {
		retErr = errors.New("failed to read voted papers: " + err.Error())
		return
	}

	rKeyBoxName, retErr := SetOpenedBoxName(id, url, storageGrp)
	if retErr != nil {
		return
	}

	print("rKeyBoxName: " + rKeyBoxName + "\n")

	openedNames := make(map[string] bool)
	for _, txId := range *txIDs {
		recorder, signature, message, err := GetRecord(id, url, storageGrp, txId)
		if err != nil {
			retErr = errors.New("unexpected papers: " + err.Error())
			return
		}
		
		base64Val, recorderCert, err := GetRecordValue(recorder, signature, message)
		if err != nil {
			retErr = errors.New("unexpected papers: " + err.Error())
			return
		}

		role := immclient.GetCertRole(recorderCert)
		if role != ROLE_BallotBoxAgent {
			continue // invalid record
		}
		
		sealedReq, err := base64.StdEncoding.DecodeString(base64Val)
		if err != nil {
			retErr = errors.New("unexpected papers: " + err.Error())
			return
		}

		plainReq, err := openBoxKey.Decrypt(sealedReq)
		if err != nil {
			retErr = errors.New("failed to decrypt papers: " + err.Error())
			return
		}

		voteReq := &immop.BallotFuncRequest{}
		err = proto.Unmarshal(plainReq, voteReq)
		if err != nil {
			continue // invalid paper
		}

		certData, _ := pem.Decode(voteReq.Cred.Cert)
        cert, err := x509.ParseCertificate(certData.Bytes)
		if err != nil {
			continue // invalid voter
		}
		signature = voteReq.Cred.Signature

		voteReq.Cred = nil
		rawReq, _ := proto.Marshal(voteReq)

		msg := []byte("BallotFunc")
		msg = append(msg, rawReq...)
		err = immsign.VerifySignatureCert(cert, signature, msg)
		if err != nil {
			continue // invalid papers
		}

		voterName := cert.Subject.CommonName
		_, validUserF := openedNames[voterName]
		if validUserF {
			print("multiple voting\n")
			continue // multiple voting
		}

		voterState, err := GetVoterState(id, url, voterName)
		if err != nil {
			continue // invalid voter
		}
		if voterState != VOTER_STA_registered && voterState != VOTER_STA_voted {
			continue // invalid voter
		}

		openedNames[voterName] = true
		sealedPapersBase64 := base64.StdEncoding.EncodeToString(voteReq.Req)
		err = id.RecordLedger(storageGrp, rKeyBoxName, sealedPapersBase64, url)
		if err != nil {
			retErr = errors.New("failed to record ballot papers in Immutable Storage")
			return
		}
	}

	return // success
}

func CountVotes(id *immclient.UserID, url string) (retErr error) {
	storageGrp, err := GetStorageForBallotBox(id, url)
	if err != nil {
		retErr = err
		return
	}

	temps, err := GetPaper(id, url)
	if err != nil {
		retErr = err
		return
	}
	candidateScore := make([][]int, len(*temps))
	for i, templ := range *temps {
		candidateScore[i] = make([]int, len(templ.Candidates))
	}

	boxName, err := GetOpenedBoxName(id, url, storageGrp)
	if err != nil {
		retErr = err
		return
	}
	
	txIDs, err := id.ListTxId(storageGrp, boxName, url)
	if err != nil {
		retErr = errors.New("failed to read papers: " + err.Error())
		return
	}

	for _, txId := range *txIDs {
		recorder, signature, message, err := GetRecord(id, url, storageGrp, txId)
		if err != nil {
			continue // invaild papers
		}

		base64Val, cert, err := GetRecordValue(recorder, signature, message)
		if err != nil {
			continue // invalid papers
		}

		role := immclient.GetCertRole(cert)
		if role != ROLE_AdminOfficial {
			continue // invaild recorder
		}

		jsonVal, err := base64.StdEncoding.DecodeString(base64Val)
		if err != nil {
			continue // invalid papers
		}
		voteReq := &VoteRequest{}
		err = json.Unmarshal([]byte(jsonVal), voteReq)
		if err != nil {
			continue // unexpected record
		}

		unsealKey, err := immconf.GetConfidentialTool(id.Priv, voteReq.PubKey, "")
		if err != nil {
			continue // failed to get an unseal key
		}

		jsonPapers, err := unsealKey.Decrypt(voteReq.Paper)
		if err != nil {
			continue // failed to decrypt papers
		}

		papers := &[]Paper{}
		err = json.Unmarshal(jsonPapers, papers)
		if err != nil {
			continue // unexpected papers
		}

		for i, paper := range *papers {
			switch paper.Method {
			case PAPER_METHOD_RADIO:
				for j, candidate := range paper.Candidates {
					if candidate.VoterInput == "selected" {
						candidateScore[i][j] += 1
					}
				}
			case PAPER_METHOD_DISAPPROVAL:
				for j, candidate := range paper.Candidates {
					if candidate.VoterInput == "disapproval" {
						candidateScore[i][j] += 1
					}
				}
			case PAPER_METHOD_RANK:
				for j, candidate := range paper.Candidates {
					tmpScore, _ := strconv.Atoi(candidate.VoterInput)
					candidateScore[i][j] += tmpScore
				}
			}
		}
	}

	for i := 0; i < len(*temps); i++ {
		for j := 0; j < len((*temps)[i].Candidates); j++ {
			(*temps)[i].Candidates[j].VoterInput = strconv.Itoa(candidateScore[i][j])
		}
	}
	
	resultVoteJson, err := json.Marshal(temps)
	if err != nil {
		retErr = errors.New("failed to count papers")
		return
	}

	err = id.RecordLedger(storageGrp, RKEY_Result, string(resultVoteJson), url)
	if err != nil {
		retErr = errors.New("failed to record the results of vote: " + err.Error())
		return
	}

	return // succcess
}

type SelectVoterRequest struct {
	AuthType string `json:"AuthType"`
	AuthParam []byte `json:"AuthParam"`
}

type VoterAuthParamLDAP struct {
	GroupName string `json:GroupName"`
	BindServer string `json:"BindServer"`
	BindDN string `json:"BindDN"`
	QueryServer string `json:"QueryServer"`
	BaseDN string `json:"BaseDN"`
	Query string `json: "Query"`
}

type VoterAuthParamJPKI struct {
	GroupName string `json:GroupName"`
	AddressFilter string `json:"AddressFilter"`
	BirthdayFilter string `json:"BrithdayFilter"`
}

func SelectVoter(id *immclient.UserID, url string, req *SelectVoterRequest) (retErr error) {
	_, retErr = ballotFunc(id, url, FSelectVoter, req, nil)
	return
}

type Candidate struct {
	Name string
	VoterInput string
}

const (
	PAPER_METHOD_RADIO = "radio" // select one candidate
	PAPER_METHOD_DISAPPROVAL = "disapproval" // mark disapproval candidates
	PAPER_METHOD_RANK = "rank" // rank candidates in numerical order
)

type Paper struct {
	Description string
	Method string
	Candidates []Candidate
}

func SetPaper(id *immclient.UserID, url string, papers *[]Paper) (retErr error) {
	storageGrp, err := GetStorageForBallotBox(id, url)
	if err != nil {
		retErr = err
		return
	}

	papersJson, err := json.Marshal(papers)
	if err != nil {
		retErr = errors.New("failed to marshal ballot papers: " + err.Error())
		return
	}

	err = id.RecordLedger(storageGrp, RKEY_Paper, string(papersJson), url)
	if err != nil {
		retErr = errors.New("failed to record ballot papers in Immutable Storage")
		return
	}
	
	return 
}

type GetPaperRequest struct {
}

type GetPaperReply struct {
	RecorderCert []byte
	Signature []byte
	Message []byte
}

func GetPaper(id *immclient.UserID, url string) (papers *[]Paper, retErr error) {
	req := &GetPaperRequest{}
	rsp := &GetPaperReply{}
	_, retErr = ballotFunc(id, url, FGetPaper, req, rsp)
	if retErr != nil {
		return
	} 

	jsonVal, cert, err := GetRecordValue(rsp.RecorderCert, rsp.Signature, rsp.Message)
	if err != nil {
		retErr = err
		return
	}

	role := immclient.GetCertRole(cert)
	if role != ROLE_AdminOfficial {
		retErr = errors.New("unexpected recorder")
		return
	}

	papers = &[]Paper{}
	err = json.Unmarshal([]byte(jsonVal), papers)
	if err != nil {
		retErr = errors.New("unexpected paper format")
		return
	}

	return // success
}

func GetLastRecord(id *immclient.UserID, url, storageGrp, rKey string) (recorder, signature, message []byte, retErr error) {
	txIDs, err := id.ListTxId(storageGrp, rKey, url)
	if err != nil {
		retErr = errors.New("failed to list TxIds: " + err.Error())
		return
	}
	if len(*txIDs) == 0 {
		retErr = errors.New("not found item")
		return
	}

	txId := (*txIDs)[len(*txIDs)-1] // last item
	recorder, signature, message, retErr = GetRecord(id, url, storageGrp, txId)
	return
}

func GetRecord(id *immclient.UserID, url, storageGrp, txId string) (recorder, signature, message []byte, retErr error) {
	block, err := id.QueryBlockByTxID(storageGrp, txId, url)
	if err != nil {
		retErr = errors.New("not found block")
		return
	}

	var header *common.SignatureHeader
	envelope := &common.Envelope{}
	payload := &common.Payload{}
	for _, blockData := range block.Data.Data {
		err = proto.Unmarshal(blockData, envelope)
		if err != nil {
			continue
		}
		
		err = proto.Unmarshal(envelope.Payload, payload)
		if err != nil {
			continue
		}
			
		chHeader := &common.ChannelHeader{}
		err = proto.Unmarshal(payload.Header.ChannelHeader, chHeader)
		if err != nil {
			continue
		}
		
		if chHeader.TxId != txId {
			continue
		}
		
		// found
		header = &common.SignatureHeader{}
		err = proto.Unmarshal(payload.Header.SignatureHeader, header)
		if err != nil {
			header = nil
		}
	}
	if header == nil {
		retErr = errors.New("not found block")		
		return // error
	}

	recorder = header.Creator
	signature = envelope.Signature
	message = envelope.Payload
	return // success
}


func GetRecordValue(recorder, signature, message []byte) (jsonVal string, recorderCert *x509.Certificate, retErr error) {
	recorderCert, retErr = immsign.VerifySignatureCreator(recorder, signature, message)
	if retErr != nil {
		return // error
	}

	payload := &common.Payload{}
	err := proto.Unmarshal(message, payload)
	if err != nil {
		retErr = errors.New("invalid message: " + err.Error())
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

	proposalRsp := &pp.ProposalResponsePayload{}
	err = proto.Unmarshal(ccAction.Action.ProposalResponsePayload, proposalRsp)
	if err != nil {
		retErr = errors.New("invalid proposal response payload: " + err.Error())
		return
	}

	ccAct := &pp.ChaincodeAction{}
	err = proto.Unmarshal(proposalRsp.Extension, ccAct)
	if err != nil {
		retErr = errors.New("invalid extension: " + err.Error())
		return
	}

	txRwset := &rwset.TxReadWriteSet{}
	err = proto.Unmarshal(ccAct.Results, txRwset)
	if err != nil {
		retErr = errors.New("invalid results: " + err.Error())
		return
	}

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
			
		value := &immclient.InstanceValue{}
		err := json.Unmarshal(kvRwset.Writes[0].Value, value)
		if err != nil {
			retErr = errors.New("unexpected key-value format: " + err.Error())
			return
		}

		jsonVal = value.Log
		return // success
	}

	retErr = errors.New("not found block")
	return
}

type GetSealKeyRequest struct {
}

type GetSealKeyReply struct {
	RecorderCert []byte
	Signature []byte
	Message []byte
}

func GetSealKey(id *immclient.UserID, url string) (pub *ecdsa.PublicKey, retErr error) {
	rsp := &GetSealKeyReply{}
	_, retErr = ballotFunc(id, url, FGetSealKey, &GetSealKeyRequest{}, rsp)
	if retErr != nil {
		return
	}

	_, cert, err := GetRecordValue(rsp.RecorderCert, rsp.Signature, rsp.Message)
	if err != nil {
		retErr = err
		return
	}

	role := immclient.GetCertRole(cert)
	if role != ROLE_ElectionOfficial {
		retErr = errors.New("unexpected recorder")
		return
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		retErr = errors.New("invalid public key in the certificate")
		return
	}
	return // success
}

type VoteRequest struct {
	Paper []byte
	PubKey []byte
}

func Vote(id *immclient.UserID, url string, papers *[]Paper) (retErr error) {
	sealPubKey, retErr := GetSealKey(id, url)
	if retErr != nil {
		return
	}
	
	sealPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		retErr = errors.New("failed to generate a seal key: " + err.Error())
		return
	}
	unsealPubAsn1, err := x509.MarshalPKIXPublicKey(sealPrivKey.Public())
	if err != nil {
		retErr = errors.New("failed to marshal an unseal key: " + err.Error())
		return
	}
	unsealPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: unsealPubAsn1})

	sealTool, retErr := immconf.GetSharedKey(sealPrivKey, sealPubKey)
	if retErr != nil {
		return
	}

	jsonPapers, err := json.Marshal(papers)
	if err != nil {
		retErr = errors.New("failed to marshal ballot papers: " + err.Error())
		return
	}
	sealedPaper, err := sealTool.Encrypt(jsonPapers)
	if err != nil {
		retErr = errors.New("failed to encrypt ballot papers: " + err.Error())
		return
	}

	req := &VoteRequest{
		Paper: sealedPaper,
		PubKey: unsealPub,
	}

	_, retErr = ballotFunc(id, url, FVote, req, nil)
	return
}

type GetResultVoteRequest struct {
}

type GetResultVoteReply struct {
	RecorderCert []byte
	Signature []byte
	Message []byte
}

func GetResultVote(id *immclient.UserID, url string) (papers *[]Paper, retErr error) {
	rsp := &GetResultVoteReply{}
	_, retErr = ballotFunc(id, url, FGetResultVote, &GetResultVoteRequest{}, rsp)
	if retErr != nil {
		return
	}

	jsonPapers, cert, err := GetRecordValue(rsp.RecorderCert, rsp.Signature, rsp.Message)
	if err != nil {
		retErr = err
		return
	}

	role := immclient.GetCertRole(cert)
	if role != ROLE_ElectionOfficial {
		retErr = errors.New("unexpected recorder")
		return
	}

	papers = &[]Paper{}
	err = json.Unmarshal([]byte(jsonPapers), papers)
	if err != nil {
		retErr = errors.New("unexpected paper format")
		return
	}

	return // success
}

type GetVoterStateRequest struct {
	Username string
}

type GetVoterStateReply struct {
	State string
}

func GetMyVoterState(id *immclient.UserID, url string) (state string, retErr error) {
	return GetVoterState(id, url, "")
}

func GetVoterState(id *immclient.UserID, url, username string) (state string, retErr error) {
	req := &GetVoterStateRequest{
		Username: username,
	}
	rsp := &GetVoterStateReply{}
	_, retErr = ballotFunc(id, url, FGetVoterState, req, rsp)
	if retErr != nil {
		return
	}

	state = rsp.State
	return // success
}
