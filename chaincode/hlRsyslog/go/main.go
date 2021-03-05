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
	"bytes"
	"encoding/json"
	// "encoding/hex" // log:
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
	// "hlRsyslog/go/authuser"
	"authuser"
)

// Define the Smart Contract structure
type SmartContract struct {
}

type InstanceValue struct {
	Format  string
	Log  string
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {
	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	fmt.Printf("function:%s\n", function)

	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "addLog" {
		return s.addLog(APIstub, args)
	} else if function == "initLedger" {
		return s.initLedger(APIstub)
	} else if function == "getLog" {
		return s.getLog(APIstub, args)
	}

	return shim.Error("Invalid Smart Contract function Name.")
}

func (s *SmartContract) addLog(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 3 or 4")
	}

	au := authuser.NewAuthUser()
	reqUserCert, err := au.GetUser(APIstub)
	if err != nil {
		return shim.Error(err.Error())
	}

	// fmt.Printf("log: addLog: user=%s\n", reqUserCert.Subject.CommonName)

	if !au.HasPermission(reqUserCert, "addLog") {
		return shim.Error("HasPermission: permission denied")
	}

	if !au.ValidateUser(reqUserCert) {
		return shim.Error("revoked user")
	}

	var inst = InstanceValue{Format: args[1], Log: args[2]}
	instAsBytes, err := json.Marshal(inst)
	if err != nil {
		fmt.Println(err)
		return shim.Error("encode error")
	}
	key := args[0]

	fmt.Printf("key=%s, value(instAsBytes)=%s\n", key, instAsBytes)
	err = APIstub.PutState(key, instAsBytes)
	if err != nil {
		return shim.Error("could not add a log")
	}

	return shim.Success(nil)
}

func (s *SmartContract) getLog(APIstub  shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	au := authuser.NewAuthUser()
	reqUserCert, err := au.GetUser(APIstub)
	if err != nil {
		return shim.Error(err.Error())
	}
	
	if !au.HasPermission(reqUserCert, "getLog") {
		return shim.Error("permission denied")
	}

	if !au.ValidateUser(reqUserCert) {
		return shim.Error("revoked user")
	}

	key := args[0];
	fmt.Printf("getHistory for key: %s\n", key)
	val, err := APIstub.GetState(key)
	if err != nil {
		return shim.Error("Invalid key: "+err.Error())
	}
	if len(val) == 0 {
		return shim.Error("Invalid key")
	}

	retHistory, err := APIstub.GetHistoryForKey(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer retHistory.Close()

	var retBuf bytes.Buffer

	retBuf.WriteString("[")
	hasNextB := retHistory.HasNext()
	for hasNextB {
		rsp, err := retHistory.Next()
		if err != nil {
			return shim.Error(err.Error())
		}

		b, err := json.Marshal(*rsp)
		if err != nil {
			return shim.Error(err.Error())
		}
		retBuf.Write(b)

		hasNextB = retHistory.HasNext()
		if hasNextB {
			retBuf.WriteString(",")
		}
	}
	retBuf.WriteString("]")

	//fmt.Printf("log: dump history:\n%s\n", hex.Dump(retBuf.Bytes()))
	return shim.Success(retBuf.Bytes())
}

func (s *SmartContract) initLedger(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

	// Create a new Smart Contract
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
