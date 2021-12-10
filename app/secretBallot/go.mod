module secretballot.wasm

go 1.16

replace immclient => ../../web/immclient

replace jpkicli => ../../app/jpki/clt

replace ballotcli => ./clt

require (
	ballotcli v0.0.0-00010101000000-000000000000 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4 // indirect
	github.com/cncf/xds/go v0.0.0-20211011173535-cb28da3451f1 // indirect
	github.com/envoyproxy/go-control-plane v0.9.10-0.20210907150352-cf90f659a021 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20211115234514-b4de73f9ece8 // indirect
	golang.org/x/net v0.0.0-20211116231205-47ca1ff31462 // indirect
	google.golang.org/grpc v1.42.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immconf v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000 // indirect
)

replace immconf => ../../web/immconf

replace immop => ../../server/immop

replace websto => ../../web/websto

replace google.golang.org/grpc => ../../web/grpc

replace immsign => ../immsign
