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

package main

import (
	"log"
	"context"
	"io"
	"os"
	"net"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/credentials"	
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/proto"

	pp "fabric/protos/peer"
	"fabric/protos/common"
)

const (
	privPath = "/etc/tlskey/server.key"
	certPath = "/etc/tlskey/server.crt"
	backendHostEnv = "BACKEND_HOST"
	grpcProxyPort = ":50070"

	processPropPath =  "/protos.Endorser/ProcessProposal"

	maxRecvMsgSize = 100*1024*1024
)

var backendHost string

func proxyHandler(srv interface{}, inStream grpc.ServerStream) (retErr error) {
	fullMethod, ok := grpc.MethodFromServerStream(inStream)
	if !ok {
		retErr = status.Errorf(codes.InvalidArgument, "invalid stream")
		return
	}

	log.Printf("fullMethod: %s\n", fullMethod)

	var receivedData interface{}
	if fullMethod == processPropPath {
		receivedData, retErr =  processPropFilter(inStream)
		if retErr != nil {
			return
		}
	}

	// forward data to a backend
	var backStream grpc.ClientStream
	var backendCancel context.CancelFunc
	backStream, backendCancel, retErr = newBackend(inStream, fullMethod)
	if retErr != nil {
		return
	}
	defer backendCancel()
	
	forwardErrCh := make(chan error, 1)
	getBackendRspErrCh := make(chan error, 1)
	go func() {
		if receivedData != nil {
			forwardErrCh <- backStream.SendMsg(receivedData)
			return
		}
		forwardErrCh <- forwardData(inStream, backStream)
	}()
	go func() {
		getBackendRspErrCh <- getBackendRsp(inStream, backStream)
	}()

	for i := 0; i < 2; i++ {
		select {
		case retErr = <- forwardErrCh:
		case retErr = <- getBackendRspErrCh:
		}

		if retErr != nil {
			return
		}
	}
	return // success
}

func newBackend(inStream grpc.ServerStream, fullMethod string) (backStream grpc.ClientStream, backendCancel context.CancelFunc, retErr error) {
	ctx := inStream.Context()
	inMeta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		retErr =  status.Errorf(codes.InvalidArgument, "invalid metadata")
		return
	}

	forwardCtx := metadata.NewOutgoingContext(ctx, inMeta.Copy())
	backendCli, err := grpc.DialContext(forwardCtx, backendHost,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true,})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSize)))
	if err != nil {
		retErr = status.Errorf(codes.Unavailable, "failed to dial: %v", err)
		return
	}

	backCtx, backendCancel := context.WithCancel(forwardCtx)
	backStream, retErr = grpc.NewClientStream(backCtx,
		&grpc.StreamDesc{ServerStreams: true, ClientStreams: true,}, backendCli, fullMethod)
	return
}

func processPropFilter(inStream grpc.ServerStream) (signedProp *pp.SignedProposal, retErr error) {
	signedProp = &pp.SignedProposal{}
	retErr = inStream.RecvMsg(signedProp)
	if retErr != nil {
		return
	}
		
	prop := &pp.Proposal{}
	retErr = proto.Unmarshal(signedProp.ProposalBytes, prop)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid request: %v", retErr)
		return
	}

	header := &common.Header{}
	retErr = proto.Unmarshal(prop.Header, header)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid header: %v", retErr)
		return
	}

	chHeader := &common.ChannelHeader{}
	retErr = proto.Unmarshal(header.ChannelHeader, chHeader)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid channel header: %v", retErr)
		return
	}

	if chHeader.Type != int32(common.HeaderType_ENDORSER_TRANSACTION) {
		return // forward signed proposal to a backend
	}

	chPayload := &pp.ChaincodeProposalPayload{}
	retErr = proto.Unmarshal(prop.Payload, chPayload)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid payload: %v", retErr)
		return
	}

	inputCode := &pp.ChaincodeInvocationSpec{}
	retErr = proto.Unmarshal(chPayload.Input, inputCode)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid plugin argument: %v", retErr)
		return
	}

	codeName := inputCode.ChaincodeSpec.ChaincodeId.Name

	log.Printf("code ID: %s\n", codeName)
	if codeName == "qscc" {
		retErr = status.Errorf(codes.PermissionDenied, "not allowed: %v", retErr)
		return
	}

	return // forward signed proposal to a backend
}	


func forwardData(inStream grpc.ServerStream, backStream grpc.ClientStream) (retErr error) {
	defer func() {
		inStream.SetTrailer(backStream.Trailer())
		if retErr == io.EOF {
			retErr = nil // success
			return
		}
		
		retErr = status.Errorf(codes.Internal, "got an error (%v) during forwarding data", retErr)
	}()
	
	buf := &emptypb.Empty{}
	for retErr == nil {
		retErr = inStream.RecvMsg(buf)
		if retErr != nil {
			return
		}
		retErr = backStream.SendMsg(buf)
	}
	return
}

func getBackendRsp(inStream grpc.ServerStream, backStream grpc.ClientStream) (retErr error) {
	defer func() {
		if retErr == io.EOF {
			backStream.CloseSend()
			retErr = nil
			return // success
		}
		
		retErr = status.Errorf(codes.Internal, "got an error (%v) during handling backend response", retErr)
		return
	}()
	
	buf := &emptypb.Empty{}
	retErr = backStream.RecvMsg(buf)
	if retErr != nil {
		return
	}
	
	var backendRspHeader metadata.MD
	backendRspHeader, retErr = backStream.Header()
	if retErr != nil {
		return
	}
	
	retErr = inStream.SendHeader(backendRspHeader)
	if retErr != nil {
		return
	}
	
	for retErr == nil {
		retErr = inStream.SendMsg(buf)
		if retErr != nil {
			return
		}
		retErr = backStream.RecvMsg(buf)
	}
	return
}


func main() {
	backendHost = os.Getenv(backendHostEnv)

	creds, err := credentials.NewServerTLSFromFile(certPath, privPath)
	if err != nil {
		log.Printf("failed to get a key-pair: %s\n", err)
		return
	}

	lis, err := net.Listen("tcp", grpcProxyPort)
	if err != nil {
		log.Printf("faileed to listen port: %s\n", err)
		return
	}
	
	s := grpc.NewServer(grpc.Creds(creds), grpc.UnknownServiceHandler(proxyHandler), grpc.MaxRecvMsgSize(maxRecvMsgSize))
	if err := s.Serve(lis); err != nil {
		log.Printf("failed to start proxy: %v\n", err)
		return
	}
}
