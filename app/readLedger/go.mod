module readledger

go 1.16

replace immledger => ../immledger

replace immblock => ../immblock

require (
	github.com/hyperledger/fabric v1.4.12 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
	golang.org/x/net v0.0.0-20211201190559-0a0e4e1bb54c // indirect
	golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1
	google.golang.org/grpc v1.42.0 // indirect
	immblock v0.0.0-00010101000000-000000000000
	immclient v0.0.0-00010101000000-000000000000 // indirect
	immledger v0.0.0-00010101000000-000000000000
	immop v0.0.0-00010101000000-000000000000 // indirect
	immsign v0.0.0-00010101000000-000000000000 // indirect
)

replace immsign => ../immsign

replace immclient => ../../web/immclient

replace immop => ../../server/immop
