module readledger

go 1.16

replace immledger => ../immledger

replace immblock => ../immblock

replace immsign => ../immsign

replace immclient => ../../web/immclient

replace immop => ../../server/immop

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset/kvrwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/peer v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/term v0.5.0
	google.golang.org/grpc v1.53.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immblock v0.0.0-00010101000000-000000000000
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
)

replace fabric/protos/common => ../../server/fabric/protos/common

replace fabric/protos/msp => ../../server/fabric/protos/msp

replace fabric/protos/peer => ../../server/fabric/protos/peer

replace fabric/protos/ledger/rwset => ../../server/fabric/protos/ledger/rwset

replace fabric/protos/ledger/rwset/kvrwset => ../../server/fabric/protos/ledger/rwset/kvrwset

replace fabric/protos/ledger/queryresult => ../../server/fabric/protos/ledger/queryresult

replace fabric/protos/token => ../../server/fabric/protos/token
