module immDS.wasm

go 1.14

replace immweb => ./immweb

replace immop => ../server/immop

replace google.golang.org/grpc => ./grpc

require (
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	immcommon v0.0.0-00010101000000-000000000000 // indirect
	immweb v0.0.0-00010101000000-000000000000
)

replace websto => ./websto

replace immclient => ./immclient

replace webutil => ./webutil

replace webcli => ./webcli

replace fabric/protos/common => ../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../server/fabric/protos/msp

replace immadmin => ../client/immadmin

replace immcommon => ../client/immcommon
