module  immDS.wasm

go 1.14

replace immweb => ./immweb

replace immop => ../server/immop

replace google.golang.org/grpc => ./grpc

require (
	github.com/cncf/udpa/go v0.0.0-20191209042840-269d4d468f6f // indirect
	github.com/fsouza/go-dockerclient v1.3.6 // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/hyperledger/fabric v1.4.7 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	go.uber.org/zap v1.15.0 // indirect
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immweb v0.0.0-00010101000000-000000000000
	websto v0.0.0-00010101000000-000000000000 // indirect
)

replace websto => ./websto

replace immclient => ./immclient
