module workflowadminweb.wasm

go 1.18

replace immop => ../../../server/immop

replace google.golang.org/grpc => ../../../web/grpc

replace webutil => ../../../web/webutil

replace websto => ../../../web/websto

replace immclient => ../../../web/immclient

replace immadmin => ../../../client/immadmin

replace st2mng => ../../../client/st2mng

replace immcommon => ../../../client/immcommon

require (
	immadmin v0.0.0-00010101000000-000000000000
	st2mng v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000
	webutil v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immcommon v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/common => ../../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../../server/fabric/protos/msp