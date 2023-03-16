/*
Copyright Hitachi, Ltd. 2020-2021 All Rights Reserved.

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
	"time"
	"context"
	"fmt"
	"strings"
	"os"
	"log"
	"sync/atomic"
	"encoding/json"
	"encoding/base64"
	"crypto/x509"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
		
	"fabric/protos/peer"
	"fabric/protos/shim"
	"fabric/protos/common"
	"fabric/protos/ledger/queryresult"
	
	"immplugin"
)

const (
	pluginSock = "unix:///run/immplugin.sock"
	maxRecvMsgSize = 100*1024*1024
)


type waitRecvMsg struct{
	sendMsg *shim.ChaincodeMessage
	rspMsg *shim.ChaincodeMessage
	retErr chan error
}


type manageWaitMap struct{
	state int32
	stream grpc.ClientStream
	list map[string]*waitRecvMsg
}

func newRecvMsgMap(cliStream grpc.ClientStream) (wm *manageWaitMap) {
	wm = &manageWaitMap{
		state: 0,
		stream: cliStream,
		list: make(map[string]*waitRecvMsg),
	}
	return
}

func (wm *manageWaitMap) lock() {
	for atomic.CompareAndSwapInt32(&wm.state, 0, 1) == false {
		time.Sleep(1*time.Millisecond)
	}
}

func (wm *manageWaitMap) unlock() {
	wm.state = 0
}

func (wm *manageWaitMap) blockingSend(msg *shim.ChaincodeMessage) (rspMsg *shim.ChaincodeMessage, retErr error) {
	waitMsg := &waitRecvMsg{
		sendMsg: msg,
		retErr: make(chan error, 1),
	}
	wID := msg.ChannelId+msg.Txid
	
	wm.lock()
	wm.list[wID] = waitMsg
	retErr = wm.stream.SendMsg(msg)
	wm.unlock()

	defer func() {
		wm.lock()
		delete(wm.list, wID)
		wm.unlock()
	}()
	
	if retErr != nil {
		return
	}
	
	retErr = <- waitMsg.retErr
	rspMsg = waitMsg.rspMsg
	return
}

func (wm *manageWaitMap) send(msg *shim.ChaincodeMessage) (retErr error) {
	wm.lock()
	retErr = wm.stream.SendMsg(msg)
	wm.unlock()

	return
}

func (wm *manageWaitMap) setResponseMsg(msg *shim.ChaincodeMessage, err error) (retErr error) {
	wID := msg.ChannelId+msg.Txid
	wm.lock()
	waitMsg, ok := wm.list[wID]
	wm.unlock()
	
	if !ok {
		retErr = fmt.Errorf("not found")
		return
	}
	waitMsg.rspMsg = msg
	waitMsg.retErr <- err
	return // success
}

func (wm *manageWaitMap) sendPutState(recvMsg *shim.ChaincodeMessage, key string,  value []byte) (retErr error) {
	payload, _ := proto.Marshal(&shim.PutState{Key: key, Value: value,})
	msg := &shim.ChaincodeMessage{
		Type: shim.ChaincodeMessage_PUT_STATE,
		Payload: payload,
		Txid: recvMsg.Txid,
		ChannelId: recvMsg.ChannelId,
	}

	rspMsg, retErr := wm.blockingSend(msg)
	if retErr != nil {
		return
	}

	switch rspMsg.Type {
	case shim.ChaincodeMessage_RESPONSE: // success
	case shim.ChaincodeMessage_ERROR:
		retErr = fmt.Errorf(string(rspMsg.Payload))
	default:
		retErr = fmt.Errorf("unknown message type=%s", rspMsg.Type)
	}	
	return
}

func (wm *manageWaitMap) sendGetState(recvMsg *shim.ChaincodeMessage, key string) (curValue []byte, retErr error) {
	payload, _ := proto.Marshal(&shim.GetState{Key: key})
	msg := &shim.ChaincodeMessage{
		Type: shim.ChaincodeMessage_GET_STATE,
		Payload: payload,
		Txid: recvMsg.Txid,
		ChannelId: recvMsg.ChannelId,
	}

	rspMsg, retErr := wm.blockingSend(msg)
	if retErr != nil {
		return
	}

	switch rspMsg.Type {
	case shim.ChaincodeMessage_RESPONSE:
		curValue = rspMsg.Payload // success
	case shim.ChaincodeMessage_ERROR:
		retErr = fmt.Errorf(string(rspMsg.Payload))
	default:
		retErr = fmt.Errorf("unknown message type=%s", rspMsg.Type)
	}
	return
}

func (wm *manageWaitMap) sendGetHistoryForKey(recvMsg *shim.ChaincodeMessage, key string) (history *shim.QueryResponse, retErr error) {
	payload, _ := proto.Marshal(&shim.GetHistoryForKey{Key: key})
	msg := &shim.ChaincodeMessage{
		Type: shim.ChaincodeMessage_GET_HISTORY_FOR_KEY,
		Payload: payload,
		Txid: recvMsg.Txid,
		ChannelId: recvMsg.ChannelId,
	}

	rspMsg, retErr := wm.blockingSend(msg)
	if retErr != nil {
		return
	}

	switch rspMsg.Type {
	case shim.ChaincodeMessage_RESPONSE:
	case shim.ChaincodeMessage_ERROR:
		retErr = fmt.Errorf(string(rspMsg.Payload))
		return
	default:
		retErr = fmt.Errorf("unknown message type=%s", rspMsg.Type)
		return
	}	

	history = &shim.QueryResponse{}
	err := proto.Unmarshal(rspMsg.Payload, history)
	if err != nil {
		retErr = fmt.Errorf("unexpected response: %s", err)
		return
	}
	
	return // success
}

func (wm *manageWaitMap) sendComplete(recvMsg *shim.ChaincodeMessage, payload *peer.Response) (retErr error) {
	payloadRaw, _ := proto.Marshal(payload)
	msg := &shim.ChaincodeMessage{
		Type: shim.ChaincodeMessage_COMPLETED,
		Payload: payloadRaw,
		ChannelId: recvMsg.ChannelId,
		Txid: recvMsg.Txid,
	}

	retErr = wm.send(msg)
	return
}

func (wm *manageWaitMap) sendSuccess(recvMsg *shim.ChaincodeMessage, successData []byte) (retErr error) {
	payload := &peer.Response{Status: 200,	Payload: successData,}
	retErr = wm.sendComplete(recvMsg, payload)
	return
}

func (wm *manageWaitMap) sendError(recvMsg *shim.ChaincodeMessage, errorMsg string) (retErr error) {
	payload := &peer.Response{Status: 500, Message: errorMsg, }
	retErr = wm.sendComplete(recvMsg, payload)
	return
}

func (wm *manageWaitMap) handleRecvMsg(msg *shim.ChaincodeMessage) (retErr error) {
	log.Printf("msg.Type=%s\n", msg.Type)
	switch msg.Type {
	case shim.ChaincodeMessage_KEEPALIVE:
		retErr = wm.send(msg)
	case shim.ChaincodeMessage_REGISTERED:
	case shim.ChaincodeMessage_READY:
	case shim.ChaincodeMessage_RESPONSE: // put and get state response
		fallthrough
	case shim.ChaincodeMessage_ERROR: // put and get state response
		err := wm.setResponseMsg(msg, nil)
		if err != nil {
			retErr = fmt.Errorf("unexpected reply: message type=%s", msg.Type)
			return
		}

	case shim.ChaincodeMessage_INIT:
		retErr = wm.sendSuccess(msg, nil)

	case shim.ChaincodeMessage_TRANSACTION:
		input := &peer.ChaincodeInput{}
		err := proto.Unmarshal(msg.Payload, input)
		if err != nil {
			retErr = fmt.Errorf("invalid input: %s\n", err)
			return
		}
		
		if msg.Proposal == nil {
			retErr = fmt.Errorf("unexpected chaincode message")
			return
		}
		
		prop := &peer.Proposal{}
		err = proto.Unmarshal(msg.Proposal.ProposalBytes, prop)
		if err != nil {
			retErr = fmt.Errorf("invalid proposal: %s", err)
			return
		}
		
		header := &common.Header{}
		err = proto.Unmarshal(prop.Header, header)
		if err != nil {
			retErr = fmt.Errorf("invalid header: %v", err)
			return
		}

		chHeader := &common.ChannelHeader{}
		err = proto.Unmarshal(header.ChannelHeader, chHeader)
		if err != nil {
			retErr = fmt.Errorf("invalid channel header: %v", err)
			return
		}
		if chHeader.Type != int32(common.HeaderType_ENDORSER_TRANSACTION) {
			retErr = fmt.Errorf("unexpected request: header type=%d", chHeader.Type)
			return
		}
		
		signHeader := &common.SignatureHeader{}
		err = proto.Unmarshal(header.SignatureHeader, signHeader)
		if err != nil {
			retErr = fmt.Errorf("failed to get a creator: %v", err)
			return
		}

		req := &immplugin.DoPluginRequest{
			Creator: signHeader.Creator,
			Args: input.Args,
			ChannelID: msg.ChannelId,
		}

		retErr = wm.invoke(msg, req)
		
	default:
		retErr = fmt.Errorf("unknown message type: %s", msg.Type)
	}

	return
}

func (wm *manageWaitMap) invoke(recvMsg *shim.ChaincodeMessage, req *immplugin.DoPluginRequest) (error) {
	conn, err := grpc.Dial(pluginSock, grpc.WithInsecure())
	if err != nil {
		retErr := fmt.Errorf("failed to connect to the plugin: " + err.Error())
		wm.sendError(recvMsg, retErr.Error())
		return retErr
	}
	defer conn.Close()
	cli := immplugin.NewImmPluginClient(conn)
	
	rsp, err := cli.DoPlugin(context.Background(), req)
	if err != nil {
		return wm.sendError(recvMsg, err.Error())
	}

	log.Printf("func=%s\n", rsp.Func)
	switch rsp.Func {
	case "PutState":
		err = wm.sendPutState(recvMsg, rsp.Key, rsp.Value)
		if err != nil {
			return wm.sendError(recvMsg, err.Error())
		}
		return wm.sendSuccess(recvMsg, nil)
		
	case "GetState":
		value, err := wm.sendGetState(recvMsg, rsp.Key)
		if err != nil {
			return wm.sendError(recvMsg, err.Error())
		}
		return wm.sendSuccess(recvMsg, value)
	case "GetHistoryForKey":
		history, err := wm.sendGetHistoryForKey(recvMsg, rsp.Key)
		if err != nil {
			return wm.sendError(recvMsg, err.Error())
		}

		getEntry := func(keyval *queryresult.KeyModification) ([]byte, error) {
			// json marshal only TxID string slice			
			return []byte(`"`+keyval.TxId+`"`), nil 
		}
		if string(rsp.Value) != "txId" {
			getEntry = func(keyval *queryresult.KeyModification) ([]byte, error) {
				return json.Marshal(*keyval)
			}
		}

		var retBuf []byte
		delimiter := ""
		retBuf = append(retBuf, []byte("[")...)
		for _, result := range history.Results{
			retBuf = append(retBuf, []byte(delimiter)...)
			
			keyval := &queryresult.KeyModification{}
			err := proto.Unmarshal(result.ResultBytes, keyval)
			if err != nil {
				return wm.sendError(recvMsg, err.Error())
			}

			keyvalRaw, err := getEntry(keyval)
			if err != nil {
				return wm.sendError(recvMsg, err.Error())
			}
			
			retBuf = append(retBuf, []byte(keyvalRaw)...)
			delimiter = ","
		}
		retBuf = append(retBuf, []byte("]")...)
		return wm.sendSuccess(recvMsg, retBuf)
	}
	
	return wm.sendError(recvMsg, "unknown function: " + rsp.Func)
}

func getPeerAddress(params []string) (peerAddress string) {
	for _, param := range params {
		tmpAddr := strings.TrimPrefix(param, "-peer.address=")
		if tmpAddr == param {
			continue
		}
		peerAddress = tmpAddr
		return // success
	}

	return // failure
}

func main() {
	if len(os.Args) < 2 {
		log.Printf("unexpected arguments\n")
		return
	}

	peerAddr := getPeerAddress(os.Args[1:])

	if os.Getenv("CORE_PEER_TLS_ENABLED") != "true" {
		log.Fatal("not support plain communication\n")
		return
	}

	cliPrivPath := os.Getenv("CORE_TLS_CLIENT_KEY_PATH")
	cliCertPath := os.Getenv("CORE_TLS_CLIENT_CERT_PATH")
	rootCertPath := os.Getenv("CORE_PEER_TLS_ROOTCERT_FILE")
	if cliPrivPath == "" || cliCertPath == "" || rootCertPath == "" {
		log.Fatal("not found key-pair")
		return
	}

	rootCertPem, err := os.ReadFile(rootCertPath)
	if err != nil {
		log.Fatal(err)
		return
	}	
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCertPem)

	cliCertBase64, err := os.ReadFile(cliCertPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	cliCertPem, err := base64.StdEncoding.DecodeString(string(cliCertBase64))
	if err != nil {
		log.Fatal(err)
		return
	}

	cliPrivBase64, err := os.ReadFile(cliPrivPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	cliPrivPem, err := base64.StdEncoding.DecodeString(string(cliPrivBase64))
	if err != nil {
		log.Fatal(err)
		return
	}
	
	tlsCert, err := tls.X509KeyPair(cliCertPem, cliPrivPem)
	if err != nil {
		log.Fatal(err)
		return
	}

	creds := credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
		Certificates: []tls.Certificate{tlsCert},
	})
	
	conn, err := grpc.Dial(peerAddr,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: time.Duration(1) * time.Minute,
			Timeout: time.Duration(20) * time.Second,
		}),
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSize)))
	if err != nil {
		log.Printf("failed to connect a storage: %s\n", err)
		return
	}

	cli := shim.NewChaincodeSupportClient(conn)

	stream, err := cli.Register(context.Background())
	if err != nil {
		log.Printf("failed to send a request%s\n", err)
		return
	}
	defer stream.CloseSend()

	wm := newRecvMsgMap(stream)

	chaincodename := os.Getenv("CORE_CHAINCODE_ID_NAME")
	payload, err := proto.Marshal(&peer.ChaincodeID{Name: chaincodename})
	if err != nil {
		log.Printf("%s\n", err)
		return
	}
	registerMsg := &shim.ChaincodeMessage{Type: shim.ChaincodeMessage_REGISTER, Payload: payload}
	err = wm.send(registerMsg)
	if err != nil {
		log.Printf("failed to send a message to register me: %s\n", err)
		return
	}

	for {
		recvMsg, err := stream.Recv()
		if err != nil {
			log.Printf("received error: %v\n", err)
			return
		}
		if recvMsg == nil {
			log.Printf("received empty message")
			return
		}

		go func (msg *shim.ChaincodeMessage) {
			err = wm.handleRecvMsg(recvMsg)
			if err != nil {
				log.Fatal("unexpected message: %s\n", err)
				return
			}
		}(recvMsg)
	}
	
}
