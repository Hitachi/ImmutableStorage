module readWriteLog.wasm

go 1.18

replace websto => ../../web/websto

replace immclient => ../../web/immclient

replace webutil => ../../web/webutil

replace google.golang.org/grpc => ../../web/grpc

replace immop => ../../server/immop

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000
	fabric/protos/msp v0.0.0-00010101000000-000000000000
	fabric/protos/peer v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.28.1
	rwlog v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000
	webutil v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace fabric/protos/peer => ../../server/fabric/protos/peer

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/token => ../../server/fabric/protos/token

replace rwlog => ./rwlog
