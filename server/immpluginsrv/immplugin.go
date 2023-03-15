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
	"google.golang.org/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"fabric/protos/msp"

	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"context"
	"log"
	"errors"
	"os"
	"net"
	"syscall"
	"strings"
	"time"
	"sync/atomic"
	
	"immplugin"
	"immutil"
	"cacli"
	"immclient"
	"immadmin"
	"storagegrp"
)

const (
	pluginSock = "/run/immplugin.sock"
	configDir = "/var/lib/immconfig"
	StorageGrpPermDir = "/var/lib/immconfig/accessPerm/"
	maxRecvMsgSize = 100*1024*1024
)

type server struct{
	org string
	podName string
	immplugin.UnimplementedImmPluginServer
}

type InstanceValue struct {
	Format  string
	Log  string
}

var storageGrpPermCache map[string]string
var cacheLock int32

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


	err = s.validateUser(cert, funcName, req.ChannelID)
	if err != nil {
		retErr = errors.New("This transaction is not allowed: " + err.Error() )
		return
	}

	switch funcName {
	case "addLog":
		if len(req.Args) < 4 {
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

func (s *server) validateUser(cert *x509.Certificate, funcName, chID string) error {
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

	storageGrp := strings.TrimSuffix(chID, "-ch")
	perm := getStorageGrpPerm(storageGrp)
	switch perm {
	case immadmin.AccessPermAll: // All users can read and write data.
	case immadmin.AccessPermGrpMember: // This permission allows only members of this storage group to read and write data.
		userStorageGroup := storagegrp.GetStorageGrpAttr(cert)
		if userStorageGroup != storageGrp {
			return errors.New("access denied")
		}
	default:
		return errors.New("unknown permission")
	}
	
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

	if userAttr.MaxEnrollments < 1 &&  userAttr.MaxEnrollments != -1/* unlimited */ {
		return errors.New("The requester is disabled")
	}
	
	return nil // this request is allowed
}

func getStorageGrpPerm(storageGrp string) (retPerm string) {
	for atomic.CompareAndSwapInt32(&cacheLock, 0, 1) == false {
		time.Sleep(100*time.Millisecond)
	}
	defer func() {
		cacheLock = 0
	}()
	
	retPerm, ok := storageGrpPermCache[storageGrp]
	if ok {
		return
	}
	
	perm, err := os.ReadFile(StorageGrpPermDir+storageGrp)
	if err != nil {
		retPerm = immadmin.AccessPermAll // allows all users to access this storage group
		return
	}

	retPerm = string(perm)
	storageGrpPermCache[storageGrp] = retPerm
	return
}
	
func main() {
	storageGrpPermCache = make(map[string]string)
	
	immpluginsrv := &server{
		org: os.Getenv("IMMS_ORG"),
		podName: os.Getenv("IMMS_POD_NAME"),
	}
	
	initPluginExecutor(immpluginsrv.podName)
	
	lis, err := net.Listen("unix", pluginSock)
	if err != nil {
		log.Fatalf("failed to listen: %s\n", err)
	}
	
	s := grpc.NewServer(grpc.MaxRecvMsgSize(maxRecvMsgSize))
	immplugin.RegisterImmPluginServer(s, immpluginsrv)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Printf("failed to start server: %v", err)
	}

	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}
