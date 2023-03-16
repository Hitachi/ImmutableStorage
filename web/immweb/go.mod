module immweb

go 1.14

replace immclient => ../immclient

replace websto => ../websto

replace immop => ../../server/immop

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.28.1
	immadmin v0.0.0-00010101000000-000000000000
	immclient v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000
	webcli v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000
	webutil v0.0.0-00010101000000-000000000000
)

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace webcli => ../webcli

replace webutil => ../webutil

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace immadmin => ../../client/immadmin
