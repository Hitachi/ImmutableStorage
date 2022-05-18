module anonymoussurvey.wasm

go 1.18

replace ballotweb => ../secretBallot/web

replace ballotcli => ../secretBallot/clt

replace immclient => ../../web/immclient

replace jpkicli => ../../app/jpki/clt

replace immconf => ../../web/immconf

replace immop => ../../server/immop

replace websto => ../../web/websto

replace google.golang.org/grpc => ../../web/grpc

replace immsign => ../immsign

replace webutil => ../../web/webutil

replace webjpki => ../../web/webjpki

replace webcli => ../../web/webcli

require (
	ballotcli v0.0.0-00010101000000-000000000000 // indirect
	ballotweb v0.0.0-00010101000000-000000000000 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/crypto v0.0.0-20220511200225-c6db032c6c88 // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55 // indirect
	google.golang.org/grpc v1.46.0 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immconf v0.0.0-00010101000000-000000000000 // indirect
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
	jpkicli v0.0.0-00010101000000-000000000000 // indirect
	webcli v0.0.0-00010101000000-000000000000 // indirect
	webjpki v0.0.0-00010101000000-000000000000 // indirect
	websto v0.0.0-00010101000000-000000000000 // indirect
	webutil v0.0.0-00010101000000-000000000000 // indirect
)
