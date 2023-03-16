module libimmds.so

go 1.14

replace immclient => ../web/immclient

replace libimmds => ./libimmds

replace immop => ../server/immop

replace peer => ./peer

replace common => ./common

replace token => ./token

replace immutil => ../immutil

replace immledger => ../app/immledger

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	libimmds v0.0.0-00010101000000-000000000000
)

replace fabric/protos/common => ../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../server/fabric/protos/msp
