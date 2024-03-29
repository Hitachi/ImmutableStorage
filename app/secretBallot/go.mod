module secretballot.wasm

go 1.16

replace immclient => ../../web/immclient

replace jpkicli => ../../app/jpki/clt

replace ballotcli => ./clt

replace immconf => ../../web/immconf

replace immop => ../../server/immop

replace websto => ../../web/websto

replace google.golang.org/grpc => ../../web/grpc

replace immsign => ../immsign

replace webutil => ../../web/webutil

replace webjpki => ../../web/webjpki

replace webcli => ../../web/webcli

replace ballotweb => ./web

require (
	ballotcli v0.0.0-00010101000000-000000000000 // indirect
	ballotweb v0.0.0-00010101000000-000000000000
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset/kvrwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/peer v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immconf v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000 // indirect
	webcli v0.0.0-00010101000000-000000000000 // indirect
	webjpki v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000 // indirect
	webutil v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/ledger/rwset => ../../server/fabric/protos/ledger/rwset

replace fabric/protos/ledger/rwset/kvrwset => ../../server/fabric/protos/ledger/rwset/kvrwset

replace fabric/protos/peer => ../../server/fabric/protos/peer

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace fabric/protos/token => ../../server/fabric/protos/token
