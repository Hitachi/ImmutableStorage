module immpluginsrv

go 1.16

replace immplugin => ../immplugin

replace immutil => ../../immutil

replace cacli => ../cacli

replace immclient => ../../web/immclient

require (
	cacli v0.0.0-00010101000000-000000000000 // indirect
	github.com/containerd/containerd v1.5.9 // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immplugin v0.0.0-00010101000000-000000000000 // indirect
	immutil v0.0.0-00010101000000-000000000000 // indirect
)

replace immop => ../immop
