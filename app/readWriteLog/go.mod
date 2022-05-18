module readWriteLog.wasm

go 1.18

require github.com/hyperledger/fabric v1.4.12

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/viper v1.11.0 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4 // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220407144326-9054f6ed7bac // indirect
	google.golang.org/grpc v1.46.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000 // indirect
	webutil v0.0.0-00010101000000-000000000000 // indirect
)

replace websto => ../../web/websto

replace immclient => ../../web/immclient

replace webutil => ../../web/webutil

replace google.golang.org/grpc => ../../web/grpc

replace immop => ../../server/immop
