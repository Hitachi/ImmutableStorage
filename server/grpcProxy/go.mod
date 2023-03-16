module grpcProxy

go 1.19

replace fabric/protos/peer => ../fabric/protos/peer

replace fabric/protos/common => ../fabric/protos/common

require (
	fabric/protos/common v0.0.0-00010101000000-000000000000
	fabric/protos/peer v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
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

replace fabric/protos/msp => ../fabric/protos/msp

replace fabric/protos/token => ../fabric/protos/token
