module go_immst

go 1.15

replace immledger => ../immledger

require (
	github.com/golang/protobuf v1.5.2
	github.com/hyperledger/fabric v1.4.8
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/viper v1.9.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
)

replace immclient => ../../web/immclient

replace immop => ../../server/immop
