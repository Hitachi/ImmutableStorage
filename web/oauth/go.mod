module enrolluser.wasm

go 1.17

replace websto => ../websto

replace immclient => ../immclient

replace immop => ../../server/immop

replace google.golang.org/grpc => ../grpc

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55 // indirect
	google.golang.org/grpc v1.44.0 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000 // indirect
)
