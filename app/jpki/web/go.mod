module jpkiweb.wasm

go 1.16

replace immop => ../../../server/immop

replace jpkicli => ../clt

replace immclient => ../../../web/immclient

replace webjpki => ../../../web/webjpki

replace webutil => ../../../web/webutil

replace websto => ../../../web/websto

replace google.golang.org/grpc => ../../../web/grpc

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	immclient v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000
	webjpki v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000 // indirect
	webutil v0.0.0-00010101000000-000000000000
)

replace fabric/protos/common => ../../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../../server/fabric/protos/msp
