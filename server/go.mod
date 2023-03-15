module immsrv

go 1.18

replace immutil => ../immutil

replace immop => ./immop

replace immclient => ../web/immclient

replace jpkicli => ../app/jpki/clt

replace cacli => ./cacli

replace ballotcli => ../app/secretBallot/clt

replace immconf => ../web/immconf

replace immsign => ../app/immsign

replace fabconf => ./fabconf

replace st2mng => ../client/st2mng

replace immcommon => ../client/immcommon

replace immadmin => ../client/immadmin

replace fabric/protos/common => ./fabric/protos/common

replace fabric/protos/msp => ./fabric/protos/msp

replace fabric/protos/peer => ./fabric/protos/peer

replace fabric/protos/ledger/queryresult => ./fabric/protos/ledger/queryresult

replace fabric/protos/orderer => ./fabric/protos/orderer

replace fabric/protos/token => ./fabric/protos/token

replace fabric/channelconfig => ./fabric/channelconfig

require (
	ballotcli v0.0.0-00010101000000-000000000000
	cacli v0.0.0-00010101000000-000000000000
	couchcli v0.0.0-00010101000000-000000000000
	fabconf v0.0.0-00010101000000-000000000000
	fabric/channelconfig v0.0.0-00010101000000-000000000000
	fabric/protos/common v0.0.0-00010101000000-000000000000
	fabric/protos/msp v0.0.0-00010101000000-000000000000
	fabric/protos/orderer v0.0.0-00010101000000-000000000000
	fabric/protos/peer v0.0.0-00010101000000-000000000000
	github.com/go-ldap/ldap/v3 v3.4.4
	golang.org/x/crypto v0.7.0
	golang.org/x/oauth2 v0.6.0
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v2 v2.4.0
	immadmin v0.0.0-00010101000000-000000000000
	immclient v0.0.0-00010101000000-000000000000
	immcommon v0.0.0-00010101000000-000000000000
	immconf v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000
	immsign v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000
	jpkicli v0.0.0-00010101000000-000000000000
	k8s.io/api v0.26.2
	k8s.io/apimachinery v0.26.2
	st2mng v0.0.0-00010101000000-000000000000
	storagegrp v0.0.0-00010101000000-000000000000
)

require (
	fabric/protos/ledger/queryresult v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/ledger/rwset/kvrwset v0.0.0-00010101000000-000000000000 // indirect
	fabric/protos/token v0.0.0-00010101000000-000000000000 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20220621081337-cb9428e4ac1e // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/client-go v0.26.2 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	k8s.io/utils v0.0.0-20221107191617-1a15be271d1d // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace fabric/protos/ledger/rwset => ./fabric/protos/ledger/rwset

replace fabric/protos/ledger/rwset/kvrwset => ./fabric/protos/ledger/rwset/kvrwset

replace couchcli => ./couchcli

replace storagegrp => ./storagegrp
