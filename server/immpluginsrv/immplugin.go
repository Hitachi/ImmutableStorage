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

package main

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/msp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"context"
	"log"
	"errors"
	"os"
	"net"
	
	"immplugin"
	"immutil"
	"cacli"
	"immclient"
)

const (
	port = ":50052"
)

type server struct{
	org string
}

type InstanceValue struct {
	Format  string
	Log  string
}

func (s *server) DoPlugin(ctx context.Context, req *immplugin.DoPluginRequest) (reply *immplugin.DoPluginReply, retErr error) {
	reply = &immplugin.DoPluginReply{}

	id := &msp.SerializedIdentity{}
	err := proto.Unmarshal(req.Creator, id)
	if err != nil {
		retErr = errors.New("Unexpected request: " + err.Error())
		return
	}
	
	p, _ := pem.Decode(id.IdBytes)
	if p.Type != "CERTIFICATE" {
		retErr = errors.New("Unexpected requestor")
		return
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		retErr = errors.New("Unexpected certificate")
		return
	}

	if len(req.Args) < 1 {
		retErr = errors.New("failed to get a function name")
		return
	}
	funcName := string(req.Args[0])


	err = s.validateUser(cert, funcName)
	if err != nil {
		retErr = errors.New("This transaction is not allowed: " + err.Error() )
		return
	}

	switch funcName {
	case "addLog":
		if len(req.Args) != 4 {
			retErr = errors.New("Unexpected argument")
			return
		}

		inst := &InstanceValue{
			Format: string(req.Args[2]),
			Log: string(req.Args[3]),
		}

		instJson, err := json.Marshal(inst)
		if err != nil {
			retErr = errors.New("failed to marshal parameters: " + err.Error())
			return
		}

		reply.Func = "PutState"
		reply.Key = string(req.Args[1])
		reply.Value = instJson
		return // success
		
	case "getLog":
		if len(req.Args) < 2 {
			retErr = errors.New("Unexpected argument")
			return
		}

		reply.Func = "GetHistoryForKey"
		reply.Key = string(req.Args[1])
		if len(req.Args) >= 3 {
			reply.Value = req.Args[2] // option
		}
		return // success
	}

	retErr = errors.New("unknown function: " + funcName)
	return
}

func (s *server) validateUser(cert *x509.Certificate, funcName string) error {
	if len(cert.Issuer.Organization) != 1 {
		return errors.New("Unexpected organization")
	}
	
	if cert.Issuer.Organization[0] != s.org {
		if funcName == "getLog" {
			return errors.New("Read operation is not allowed because you belong to a different storage.")
		}
		return nil // allowed
	}
	
	username := cert.Subject.CommonName
	caName := cert.Issuer.CommonName
	
	tmpID, _, err := immutil.GetAdminID(username, caName)
	if err != nil {
		// The requester does not have administrators.
		return nil // allowed
	}

	caCli := cacli.NewCAClient("https://"+caName+cacli.DefaultPort)
	adminID := &immclient.UserID{
		Name: tmpID.Name,
		Priv: tmpID.Priv,
		Cert: tmpID.Cert,
		Client: caCli,
	}

	userAttr, err := adminID.GetIdentity(caCli.UrlBase, username)
	if err != nil {
		return errors.New("The requester does not exist")
	}

	if userAttr.MaxEnrollments < 1 {
		return errors.New("The requester is disabled")
	}
	
	return nil // this request is allowed
}


func main() {
	immpluginsrv := &server{
		org: os.Getenv("IMMS_ORG"),
	}
	
	err := initPodInPod(immpluginsrv.org)
	if err != nil {
		log.Fatalf("%s\n", err)
	}
	
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %s\n", err)
	}

	
	s := grpc.NewServer()
	immplugin.RegisterImmPluginServer(s, immpluginsrv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
