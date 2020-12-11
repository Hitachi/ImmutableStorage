module go_immst

go 1.15

replace immledger => ../immledger

require (
	github.com/golang/protobuf v1.4.3
	github.com/hyperledger/fabric v1.4.8
	github.com/mitchellh/mapstructure v1.4.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.0.0-20201208171446-5f87f3452ae9
	golang.org/x/net v0.0.0-20201207224615-747e23833adb // indirect
	google.golang.org/grpc v1.34.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace immclient => ../../web/immclient

replace immop => ../../server/immop
