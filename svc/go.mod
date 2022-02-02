module immsSvc

go 1.16

replace casvc => ./caSvcK8s

require (
	casvc v0.0.0-00010101000000-000000000000
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/hcsshim v0.8.23 // indirect
	github.com/cilium/ebpf v0.6.2 // indirect
	github.com/containerd/containerd v1.5.0-beta.0 // indirect
	github.com/containerd/continuity v0.2.2 // indirect
	github.com/coreos/etcd v3.3.27+incompatible // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/docker/docker v20.10.12+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/docker/swarmkit v1.12.1-0.20200604173159-967c829cdd33 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/golang/snappy v0.0.4-0.20210608040537-544b4180ac70 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/klauspost/compress v1.12.3 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/moby/buildkit v0.8.3 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.5.0 // indirect
	github.com/moby/term v0.0.0-20201110203204-bea5bbe245bf // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.0-rc95 // indirect
	github.com/opencontainers/selinux v1.10.0 // indirect
	github.com/tonistiigi/fsutil v0.0.0-20210609172227-d72af97c0eaf // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210402141018-6c239bbf2bb1 // indirect
	google.golang.org/grpc v1.44.0 // indirect
	httpsvc v0.0.0-00010101000000-000000000000
	immsvc v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000 // indirect
	k8s.io/client-go v0.22.6 // indirect
	preloadimg v0.0.0-00010101000000-000000000000
)

replace immutil => ../immutil

replace httpsvc => ./httpSvcK8s

replace immsvc => ./immSvcK8s

replace preloadimg => ./preloadImg
