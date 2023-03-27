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

	"encoding/pem"
	"encoding/asn1"
	"crypto/x509"
	"crypto/tls"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/credentials"
	//"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/proto"

	pp "fabric/protos/peer"
	"fabric/protos/common"
	"fabric/protos/gossip"
	"fabric/protos/msp"
)

const (
	tlsCAPath    = "/etc/keys/certs/tlsca.crt"
	tlsKeyPath   = "/etc/keys/tls/tls.key"
	tlsCertPath  = "/etc/keys/tls/tls.crt"
	signKeyPath  = "/etc/keys/tls/sign.key"
	signCertPath = "/etc/keys/certs/sign.crt"
	
	backendHostEnv = "BACKEND_HOST"
	grpcProxyPort = ":50070"

	processPropPath = "/protos.Endorser/ProcessProposal"
	gossipPath = "/gossip.Gossip/GossipStream"
	replaySignPath = "/immproxy.Ex/Replay"
	
	maxRecvMsgSize = 100*1024*1024
)

var (
	backendHost string
	tlsCACreds credentials.TransportCredentials
	tlsClientCreds credentials.TransportCredentials
	tlsCertHash []byte
	signKey *ecdsa.PrivateKey
)

func proxyHandler(srv interface{}, inStream grpc.ServerStream) (retErr error) {
	fullMethod, ok := grpc.MethodFromServerStream(inStream)
	if !ok {
		retErr = status.Errorf(codes.InvalidArgument, "invalid stream")
		return
	}

	log.Printf("fullMethod: %s\n", fullMethod)

	var receivedData interface{}
	switch fullMethod {
	case processPropPath:
		receivedData, retErr = processPropFilter(inStream)
		if retErr != nil {
			return
		}
	case gossipPath:
		receivedData, retErr = rebuildAuthMsg(inStream)
		if retErr != nil {
			log.Printf("failed to rebuild a message: %s\n", retErr)
			return
		}
	case replaySignPath:
		retErr = replaySignMsg(inStream)
		return
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
			log.Printf("error: %s\n", retErr)
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

	creds := tlsCACreds
	if fullMethod == gossipPath {
		creds = tlsClientCreds
	}
	
	forwardCtx := metadata.NewOutgoingContext(ctx, inMeta.Copy())
	backendCli, err := grpc.DialContext(forwardCtx, backendHost,
		grpc.WithTransportCredentials(creds), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSize)))
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

func rebuildAuthMsg(inStream grpc.ServerStream) (envelope *gossip.Envelope, retErr error) {
	envelope = &gossip.Envelope{}
	retErr = inStream.RecvMsg(envelope)
	if retErr != nil {
		log.Printf("failed to receive a message: %s\n", retErr)
		return
	}

	msg := &gossip.GossipMessage{}
	retErr = proto.Unmarshal(envelope.Payload, msg)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid request: %v", retErr)
		return
	}
	
	switch msg.Content.(type) {
	case *gossip.GossipMessage_Conn:
	default:
		return // forward incoming message to a backend
	}

	content := msg.Content.(*gossip.GossipMessage_Conn)
	replayMsg := &gossip.GossipMessage{
		Tag: gossip.GossipMessage_EMPTY,
		Nonce: 0,
		Content: &gossip.GossipMessage_Conn{
			Conn: &gossip.ConnEstablish{
				TlsCertHash: tlsCertHash,
				Identity: content.Conn.Identity,
				PkiId: content.Conn.PkiId,
			},
		},
	}

	srcID := &msp.SerializedIdentity{}
	err := proto.Unmarshal(content.Conn.Identity, srcID)
	if err != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
		return
	}

	certData, _ := pem.Decode(srcID.IdBytes)
	srcSignCert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid identity: %v", err)
		return
	}
	
	replayHost := srcSignCert.Subject.CommonName

	replayCli, err := grpc.Dial(replayHost+":443", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true,})))
	if err != nil {
		retErr = status.Errorf(codes.Unavailable, "failed to dial: %v", err)
		return
	}
	defer replayCli.Close()

	replayStream, retErr := grpc.NewClientStream(context.Background(), &grpc.StreamDesc{ServerStreams: true, ClientStreams: true,}, replayCli, replaySignPath)
	if retErr != nil {
		return
	}

	retErr = replayStream.SendMsg(replayMsg)
	if retErr != nil {
		return
	}

	envelope = &gossip.Envelope{}
	retErr = replayStream.RecvMsg(envelope)
	if retErr != nil {
		return
	}
	
	return // success
}

type ECDSASignature struct {
        R, S *big.Int
}

func signData(data []byte) (signature []byte, retErr error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, signKey, digest[:])
	if err != nil {
		retErr = status.Errorf(codes.Unavailable, "failed to sign: %s", err)
		return
	}
	baseN := signKey.Params().N
	if s.Cmp(new(big.Int).Rsh(baseN, 1)) == 1 {
		s.Sub(baseN, s)
	}
	
	signature, err = asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		retErr = status.Errorf(codes.Unavailable, "failed to create signature: %s", err)
		return
	}

	return
}

func replaySignMsg(inStream grpc.ServerStream) (retErr error) {
	replayMsg := &gossip.GossipMessage{}
	retErr = inStream.RecvMsg(replayMsg)
	if retErr != nil {
		return
	}

	signMsg := &gossip.Envelope{}
	signMsg.Payload, retErr = proto.Marshal(replayMsg)
	if retErr != nil {
		retErr = status.Errorf(codes.InvalidArgument, "invalid request: %v", retErr)
		return
	}
	
	signMsg.Signature, retErr = signData(signMsg.Payload)
	if retErr != nil {
		return
	}

	retErr = inStream.SendMsg(signMsg)
	if retErr != nil {
		return
	}

	return // success
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
	log.Printf("v1.1\n")
	backendHost = os.Getenv(backendHostEnv)

	tlsClientCert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
	if err != nil {
		log.Printf("failed to create a certificate for a GRPC client: %s\n", err)
		return
	}

	tlsCertHash32 := sha256.Sum256(tlsClientCert.Certificate[0])
	tlsCertHash = tlsCertHash32[:]

	tlsCAPem, err := os.ReadFile(tlsCAPath)
	if err != nil {
		log.Printf("could not read a certificate for the TLS CA: %s\n", err)
		return
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(tlsCAPem)
	
	tlsClientCreds = credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsClientCert},
		RootCAs: certPool,
	})

	tlsCACreds = credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	})


	signKeyPem, err := os.ReadFile(signKeyPath)
	if err != nil {
		log.Printf("could not read a private key to sign a message: %s\n", err)
		return
	}
	
	privData, _ := pem.Decode(signKeyPem)
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		log.Printf("unsupported key format: %s\n", err)
		return
	}

	var ok bool
	signKey, ok = privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		log.Printf("unexpected key\n")
		return
	}

	lis, err := net.Listen("tcp", grpcProxyPort)
	if err != nil {
		log.Printf("faileed to listen port: %s\n", err)
		return
	}
	
	s := grpc.NewServer(grpc.UnknownServiceHandler(proxyHandler), grpc.MaxRecvMsgSize(maxRecvMsgSize))
	if err := s.Serve(lis); err != nil {
		log.Printf("failed to start proxy: %v\n", err)
		return
	}
}
