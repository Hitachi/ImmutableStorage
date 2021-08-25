module jpkiweb.wasm

go 1.16

replace immop => ../../../server/immop

replace jpkicli => ../clt

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.18.1 // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e // indirect
	google.golang.org/grpc v1.39.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000 // indirect
)

replace immclient => ../../../web/immclient

replace google.golang.org/grpc => ../../../web/grpc
