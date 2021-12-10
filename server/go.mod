module immsrv

go 1.16

replace immutil => ../immutil

replace immop => ./immop

replace fabconf => ./fabconf

require (
	ballotcli v0.0.0-00010101000000-000000000000
	cacli v0.0.0-00010101000000-000000000000
	fabconf v0.0.0-00010101000000-000000000000
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.4.15-0.20200113171025-3fe6c5262873 // indirect
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/Shopify/sarama v1.26.4 // indirect
	github.com/containerd/containerd v1.4.12 // indirect
	github.com/containerd/continuity v0.0.0-20200228182428-0f16d7a0959c // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.4.2-0.20191101170500-ac7306503d23
	github.com/docker/go-connections v0.4.0
	github.com/fsouza/go-dockerclient v1.3.6 // indirect
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.0
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hyperledger/fabric v1.4.11
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a // indirect
	github.com/hyperledger/fabric-lib-go v1.0.0 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.3.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/spf13/viper v1.7.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00 // indirect
	github.com/willf/bitset v1.1.10 // indirect
	go.uber.org/zap v1.15.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/grpc v1.27.1
	gopkg.in/yaml.v2 v2.3.0
	immclient v0.0.0-00010101000000-000000000000
	immconf v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000
	immsign v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000
	jpkicli v0.0.0-00010101000000-000000000000
	k8s.io/api v0.18.3
	k8s.io/apimachinery v0.18.3
)

replace github.com/docker/docker => github.com/docker/engine v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible

replace immclient => ../web/immclient

replace jpkicli => ../app/jpki/clt

replace cacli => ./cacli

replace ballotcli => ../app/secretBallot/clt

replace immconf => ../web/immconf

replace immsign => ../app/immsign
