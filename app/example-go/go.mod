module go_immst

go 1.18

replace immledger => ../immledger

replace immclient => ../../web/immclient

replace immop => ../../server/immop

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/peer => ../../server/fabric/protos/peer

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace fabric/protos/token => ../../server/fabric/protos/token

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000
	fabric/protos/peer v0.0.0-00010101000000-000000000000
	golang.org/x/term v0.6.0
	google.golang.org/protobuf v1.28.1
	immledger v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/grpc v1.53.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
)
