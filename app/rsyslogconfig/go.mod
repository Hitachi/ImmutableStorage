module rsyslogconfig.wasm

go 1.19

replace immadmin => ../../client/immadmin

replace webutil => ../../web/webutil

replace websto => ../../web/websto

replace immclient => ../../web/immclient

replace immcommon => ../../client/immcommon

replace immop => ../../server/immop

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace rwlog => ../readWriteLog/rwlog

replace fabric/protos/peer => ../../server/fabric/protos/peer

replace fabric/protos/token => ../../server/fabric/protos/token

replace google.golang.org/grpc => ../../web/grpc

require (
	google.golang.org/protobuf v1.29.0
	immadmin v0.0.0-00010101000000-000000000000
	immblock v0.0.0-00010101000000-000000000000
	immclient v0.0.0-00010101000000-000000000000
	rwlog v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000
	webutil v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset/kvrwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/peer v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	immcommon v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
)

replace immblock => ../immblock

replace fabric/protos/ledger/rwset => ../../server/fabric/protos/ledger/rwset

replace fabric/protos/ledger/rwset/kvrwset => ../../server/fabric/protos/ledger/rwset/kvrwset

replace immsign => ../immsign
