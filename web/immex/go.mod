module immex.wasm

go 1.14

replace websto => ../websto

replace immclient => ../immclient

replace immop => ../../server/immop

replace google.golang.org/grpc => ../grpc

require (
	github.com/cncf/udpa/go v0.0.0-20191209042840-269d4d468f6f // indirect
	github.com/golang/protobuf v1.4.2
	github.com/hyperledger/fabric v1.4.7 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	go.uber.org/zap v1.15.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000
)

