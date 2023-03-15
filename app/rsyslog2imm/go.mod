module rsyslog2imm

go 1.14

replace immclient => ../../web/immclient

replace immop => ../../server/immop

replace immledger => ../immledger

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../server/fabric/protos/msp
