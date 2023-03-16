module hlRsyslog

go 1.19

replace fabric/protos/ledger/queryresult => ../../fabric/protos/ledger/queryresult

replace fabric/protos/shim => ../../fabric/protos/shim

replace fabric/protos/peer => ../../fabric/protos/peer

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000
	fabric/protos/peer v0.0.0-00010101000000-000000000000
	fabric/protos/shim v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
	immplugin v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/msp v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
)

replace fabric/protos/common => ../../fabric/protos/common

replace fabric/protos/token => ../../fabric/protos/token

replace fabric/protos/msp => ../../fabric/protos/msp

replace immplugin => ../../immplugin
