module immsrv

go 1.16

replace immutil => ../immutil

replace immop => ./immop

replace immclient => ../web/immclient

replace jpkicli => ../app/jpki/clt

replace cacli => ./cacli

replace ballotcli => ../app/secretBallot/clt

replace immconf => ../web/immconf

replace immsign => ../app/immsign

require (
	ballotcli v0.0.0-00010101000000-000000000000
	cacli v0.0.0-00010101000000-000000000000
	fabconf v0.0.0-00010101000000-000000000000
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Shopify/sarama v1.31.0 // indirect
	github.com/containerd/containerd v1.5.9 // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.3.6 // indirect
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/go-version v1.4.0 // indirect
	github.com/hyperledger/fabric v1.4.12
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/hyperledger/fabric-lib-go v1.0.0 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/spf13/viper v1.7.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00 // indirect
	go.uber.org/zap v1.20.0 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
	golang.org/x/net v0.0.0-20220114011407-0dd24b26b47d // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/grpc v1.43.0
	gopkg.in/yaml.v2 v2.4.0
	immclient v0.0.0-00010101000000-000000000000
	immconf v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000
	immsign v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000
	jpkicli v0.0.0-00010101000000-000000000000
	k8s.io/api v0.23.4
	k8s.io/apimachinery v0.23.4
	k8s.io/client-go v0.23.4 // indirect
)

replace fabconf => ./fabconf
