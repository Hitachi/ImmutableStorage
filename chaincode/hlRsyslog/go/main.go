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
	"bytes"
	"encoding/json"
	"context"

	"google.golang.org/grpc"
		
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	
	"immplugin"
)

// Define the Plugin Functions structure
type PluginFunc struct {
}

const (
	//pluginServer = "localhost:50052"
	pluginServer = "172.17.0.1:50052" // docker0 network
)


func (s *PluginFunc) Init(APIstub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (s *PluginFunc) Invoke(APIstub shim.ChaincodeStubInterface) peer.Response {
	creator, err := APIstub.GetCreator()
	if err != nil {
		return shim.Error(err.Error())
	}
	
	conn, err := grpc.Dial(pluginServer, grpc.WithInsecure())
	if err != nil {
		return shim.Error("failed to connect to the plugin: " + err.Error())
	}
	defer conn.Close()
	
	cli := immplugin.NewImmPluginClient(conn)
	req := &immplugin.DoPluginRequest{
		Creator: creator,
		Args: APIstub.GetArgs(),
	}
	rsp, err := cli.DoPlugin(context.Background(), req)
	if err != nil {
		return shim.Error(err.Error())
	}

	switch rsp.Func {
	case "PutState":
		err = APIstub.PutState(rsp.Key, rsp.Value)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(nil)
		
	case "GetState":
		value, err := APIstub.GetState(rsp.Key)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(value)
	case "GetHistoryForKey":
		retHistory, err := APIstub.GetHistoryForKey(rsp.Key)
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
		
		return shim.Success(retBuf.Bytes())
	}
	
	return shim.Error("unknown function: " + rsp.Func)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

	// Create a new Plugin
	err := shim.Start(new(PluginFunc))
	if err != nil {
		print("Error creating new Plugin: " + err.Error() + "\n")
	}
}
