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
	ballotcli v0.0.0-00010101000000-000000000000 // indirect
	cacli v0.0.0-00010101000000-000000000000 // indirect
	fabconf v0.0.0-00010101000000-000000000000 // indirect
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/Shopify/sarama v1.31.0 // indirect
	github.com/Shopify/toxiproxy v2.1.4+incompatible // indirect
	github.com/containerd/containerd v1.5.9 // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/libnetwork v0.8.0-dev.2.0.20180608203834-19279f049241 // indirect
	github.com/fsouza/go-dockerclient v1.3.6 // indirect
	github.com/go-ldap/ldap/v3 v3.4.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/hashicorp/go-version v1.4.0 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/hyperledger/fabric-lib-go v1.0.0 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/viper v1.7.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00 // indirect
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	go.uber.org/zap v1.20.0 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
	golang.org/x/net v0.0.0-20220114011407-0dd24b26b47d // indirect
	google.golang.org/grpc v1.43.0 // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/goidentity.v3 v3.0.0 // indirect
	gopkg.in/jcmturner/gokrb5.v7 v7.2.3 // indirect
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immconf v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
	immutil v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000 // indirect
	k8s.io/api v0.20.6 // indirect
	k8s.io/apimachinery v0.20.6 // indirect
)

replace fabconf => ./fabconf
