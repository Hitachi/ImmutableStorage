module immsSvc

go 1.15

replace casvc => ./caSvcK8s

require (
	casvc v0.0.0-00010101000000-000000000000
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/containerd/containerd v1.5.4 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/opencontainers/selinux v1.8.4 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	httpsvc v0.0.0-00010101000000-000000000000
	immsvc v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000 // indirect
	preloadimg v0.0.0-00010101000000-000000000000
)

replace immutil => ../immutil

replace httpsvc => ./httpSvcK8s

replace immsvc => ./immSvcK8s

replace preloadimg => ./preloadImg
