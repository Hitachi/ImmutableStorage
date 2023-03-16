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

package immcommon

import (
	"context"
	"errors"
	"time"
	"encoding/json"
	"crypto/tls"
	
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	
	"immop"
	"immclient"
)

const (
	MCommon = "commonModule"
	FWhoamI = "WhoamI"
)

func ImmstFunc(id *immclient.UserID, url, modName, funcName string, req, reply interface{}) (retJson []byte, retErr error) {
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
	reqGrpc := &immop.ImmstFuncRequest{
		Mod: modName,
		Func: funcName,
		Req: reqJson,
	}

	var reqFunc = func(reqTime string) (retRspRaw []byte, retryTime string, retErr error) {
		reqGrpc.Time = reqTime
		reqGrpc.Cred = nil
		reqGrpc.Cred, err = id.SignMsg("ImmstFunc", reqGrpc)
		if err != nil {
			retErr = errors.New("failed to add a signature for this request: " + err.Error())
			return
		}
		
		rsp, err := cli.ImmstFunc(context.Background(), reqGrpc)
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
		retErr = errors.New("Your machine time is incorrect.")
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

type WhoamIReply struct{
	Username string
	Time string
}

func WhoamI(id *immclient.UserID, url string) (myname string, retErr error) {
	reply := &WhoamIReply{}
	_, retErr = ImmstFunc(id, url, MCommon, FWhoamI, nil, reply)
	if retErr != nil {
		return
	}

	myname = reply.Username
	return // success
}
