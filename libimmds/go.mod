module libimmds.so

go 1.14

require (
	github.com/golang/protobuf v1.4.2
	github.com/hyperledger/fabric v1.4.7 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	go.uber.org/zap v1.15.0 // indirect
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	google.golang.org/grpc v1.31.0 // indirect
	immclient v0.0.0-00010101000000-000000000000
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	immutil v0.0.0-00010101000000-000000000000
	libimmds v0.0.0-00010101000000-000000000000
)

replace immclient => ../web/immclient

replace libimmds => ./libimmds

replace immop => ../server/immop

replace peer => ./peer

replace common => ./common

replace token => ./token

replace immutil => ../immutil

replace immledger => ../app/immledger
