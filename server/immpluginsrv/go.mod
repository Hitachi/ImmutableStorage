module immpluginsrv

go 1.16

replace immplugin => ../immplugin

replace immutil => ../../immutil

replace cacli => ../cacli

replace immclient => ../../web/immclient

require (
	cacli v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.5.9 // indirect
	github.com/docker/distribution v2.8.0+incompatible // indirect
	github.com/docker/docker v20.10.12+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/hyperledger/fabric v1.4.12
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	google.golang.org/grpc v1.40.0
	immclient v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	immplugin v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000
)

replace immop => ../immop
