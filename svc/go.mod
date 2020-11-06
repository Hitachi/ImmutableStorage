module immsSvc

go 1.15

replace casvc => ./caSvcK8s

require (
	casvc v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.4.1 // indirect
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a // indirect
	github.com/containerd/fifo v0.0.0-20201026212402-0724c46b320c // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.1 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2 // indirect
	github.com/opencontainers/selinux v1.6.0 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	google.golang.org/grpc v1.33.1 // indirect
	httpsvc v0.0.0-00010101000000-000000000000
	immsvc v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000 // indirect
	preloadimg v0.0.0-00010101000000-000000000000
)

replace immutil => ../immutil

replace httpsvc => ./httpSvcK8s

replace immsvc => ./immSvcK8s

replace preloadimg => ./preloadImg
