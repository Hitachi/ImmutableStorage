module rsyslog2imm

go 1.14

replace immclient => ../../web/immclient

require (
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/hyperledger/fabric v1.4.7 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	go.uber.org/zap v1.15.0 // indirect
	google.golang.org/grpc v1.30.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
	immclient v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace immop => ../../server/immop
