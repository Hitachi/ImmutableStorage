module enrolluser.wasm

go 1.19

replace websto => ../websto

replace immclient => ../immclient

replace immop => ../../server/immop

replace google.golang.org/grpc => ../grpc

require (
	immclient v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.29.1 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/mspdger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../server/fabric/protos/msp
