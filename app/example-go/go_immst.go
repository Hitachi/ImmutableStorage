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
	"immledger"
	"fmt"
	"strings"
	"os"
	"time"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"
	"fabric/protos/common"
	"fabric/protos/peer"
)

func main(){
    if len(os.Args) < 5 {
		fmt.Printf("Usage: %s key-directory username {read|write} storage-group [write-log] [log-key]\n", os.Args[0])
        os.Exit(5)
	}
	
	keyDir := os.Args[1]
    username := os.Args[2]
    op := os.Args[3] // operation {read|write}
    storageGrp := os.Args[4]
	logData := ""
	logKey := "logGO"
	logKeyP := 5

    if op != "write" && op != "read" {
        fmt.Printf("unsupported opertion: " + op + "\n")
        fmt.Printf("Usage: " + os.Args[0] + " key-directory username {read|write} storage-group [write-log] [log-key]\n")
        os.Exit(51)
    }
    if op == "write" {
        if len(os.Args) < 6 {
            fmt.Printf("Usage: " + os.Args[0] + " key-directory username write storage-group write-log [log-key]\n")
            os.Exit(52)
        }

        logData = os.Args[5]
		logKeyP = 6
    }

	if len(os.Args) > logKeyP {
		logKey = os.Args[logKeyP]
	}

	var ledger *immledger.ImmLedger
	password := ""
    for i := 0; i < 5; i++ {
		var err error
        ledger, err = immledger.OpenKey(username, keyDir, password);
        if err == nil {
            break // success
		}

        if i == 4 {
            fmt.Printf("error: %s\n", err)
            os.Exit(5)
        }
        
        if strings.HasPrefix(err.Error(), immledger.ERR_PASS_INCORRECT) {
			fmt.Printf("Please enter the password: ")
            passwordByte, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Printf("failed to read a password: %s\n", err)
				os.Exit(6)
			}
			password = string(passwordByte)
				
            continue
        }
        
        fmt.Printf("error: %s\n", err)
        os.Exit(1)
    }

    if op == "write" {
        err := ledger.Write(storageGrp, logKey, logData)
        if err != nil {
            fmt.Printf("error: RecordLedger: %s\n", err)
            os.Exit(2)
        }
        
        return // sucess
    }

    // read ledger
    txIDs, err := ledger.GetTxID(storageGrp, logKey)
    if err != nil {
		fmt.Printf("error: %s\n", err)
        os.Exit(3)
    }

    fmt.Printf("number of ids = %d\n", len(txIDs))
	for _, txID := range txIDs {
        fmt.Printf("TxID: " + txID + "\n");
        block, err := ledger.GetBlockByTxID(storageGrp, txID)
		if err != nil {
            fmt.Printf("error: %s\n", err)
			os.Exit(15)
        }

		blockByte, err := proto.Marshal(block)
        fmt.Printf("block size=%d\n", len(blockByte))
		
		channelHeaderSt := &common.ChannelHeader{}
		transactionSt := &peer.Transaction{}
        foundTxIdF := false
        for _, blockData := range block.Data.Data {
			envelopeSt := &common.Envelope{}
			err = proto.Unmarshal(blockData, envelopeSt)
            if err != nil {
                fmt.Printf("error: failed to parse the block: %s\n", err)
                os.Exit(10)
            }
			
			payloadSt := &common.Payload{}
			err = proto.Unmarshal(envelopeSt.Payload, payloadSt)
            if err != nil {
                fmt.Printf("error: failed to parse a payload: %s\n", err)
                os.Exit(11)
            }
            if payloadSt.Header == nil {
                fmt.Printf("error: unexpected payload format\n")
                os.Exit(12)
            }

			err = proto.Unmarshal(payloadSt.Header.ChannelHeader, channelHeaderSt)
            if err != nil {
                fmt.Printf("error: failed to parse a channel-header: %s\n", err)
                os.Exit(13)
            }

            foundTxIdF = (txID == channelHeaderSt.TxId)
            if foundTxIdF {
				err = proto.Unmarshal(payloadSt.Data, transactionSt)
                if err != nil {
                    fmt.Printf("error: failed to parse a transaction: %s\n", err)
                    os.Exit(14)
                }
                break
            }
        }

        if !foundTxIdF {
            fmt.Printf("error: not found TxID: %s\n", txID)
            os.Exit(4)
        }

        if channelHeaderSt.Timestamp == nil {
            continue
		}

		recordTime := time.Unix(channelHeaderSt.Timestamp.GetSeconds(),
			int64(channelHeaderSt.Timestamp.GetNanos()))
		recordTimeStr := recordTime.Local().Format(time.UnixDate)

        if len(transactionSt.Actions) != 1 {
			fmt.Printf("error: unexpected number of actions: %d\n", len(transactionSt.Actions))
			os.Exit(20)
        }

		chaincodeActionPayloadSt := &peer.ChaincodeActionPayload{}
		err = proto.Unmarshal(transactionSt.Actions[0].Payload, chaincodeActionPayloadSt)
        if err != nil {
            fmt.Printf("error: failed to parse a ChaincodeActionPayload: %s\n", err)
            os.Exit(21)
        }

		chaincodeProposalPayloadSt := &peer.ChaincodeProposalPayload{}
		err = proto.Unmarshal(chaincodeActionPayloadSt.ChaincodeProposalPayload, chaincodeProposalPayloadSt)
        if err != nil {
            fmt.Printf("error: failed to parse a ChaincodeProposalPayload: %s\n", err)
            os.Exit(22)
        }

		chaincodeInvocationSpecSt := &peer.ChaincodeInvocationSpec{}
		err = proto.Unmarshal(chaincodeProposalPayloadSt.Input, chaincodeInvocationSpecSt)
        if err != nil {
            fmt.Printf("error: failed to parse a ChaincodeInvocationSpec: %s\n", err)
            os.Exit(23)
        }
		if chaincodeInvocationSpecSt.ChaincodeSpec == nil {
            fmt.Printf("error: unexpected ChaincodeInvocationSpec\n")
            os.Exit(24)
        }
		
		chainIn := chaincodeInvocationSpecSt.ChaincodeSpec.Input
        if chainIn == nil {
            fmt.Printf("error: unexected ChaincodeSpec\n")
            os.Exit(25)
        }

        if len(chainIn.Args) != 4 {
            fmt.Printf("error: unexected log format\n")
            os.Exit(26)
        }
        fmt.Printf("%s.%09d | %s | %s\n", recordTimeStr, channelHeaderSt.Timestamp.GetNanos(),
			chainIn.Args[1], chainIn.Args[3])
    }
}

