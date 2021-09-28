module hlRsyslog

go 1.14

require (
	github.com/fsouza/go-dockerclient v1.7.4 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/hyperledger/fabric v1.4.12
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/spf13/viper v1.9.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210927181540-4e4d966f7476 // indirect
	google.golang.org/grpc v1.41.0
	immplugin v0.0.0-00010101000000-000000000000
)

replace immplugin => ../../immplugin
