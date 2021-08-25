module immsSvc

go 1.15

replace casvc => ./caSvcK8s

require (
	casvc v0.0.0-00010101000000-000000000000
	github.com/Azure/azure-sdk-for-go v16.2.1+incompatible // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/Microsoft/hcsshim v0.8.14 // indirect
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d // indirect
	github.com/aws/aws-sdk-go v1.15.11 // indirect
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/bshuster-repo/logrus-logstash-hook v0.4.1 // indirect
	github.com/bugsnag/bugsnag-go v0.0.0-20141110184014-b1d153021fcd // indirect
	github.com/bugsnag/osext v0.0.0-20130617224835-0dd3f918b21b // indirect
	github.com/bugsnag/panicwrap v0.0.0-20151223152923-e2c28503fcd0 // indirect
	github.com/checkpoint-restore/go-criu/v4 v4.1.0 // indirect
	github.com/containerd/btrfs v1.0.0 // indirect
	github.com/containerd/cgroups v1.0.1 // indirect
	github.com/containerd/containerd v1.4.9 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/go-cni v1.0.2 // indirect
	github.com/containerd/go-runc v1.0.0 // indirect
	github.com/containerd/imgcrypt v1.0.3 // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/containernetworking/plugins v0.9.1 // indirect
	github.com/containers/ocicrypt v1.1.1 // indirect
	github.com/denverdino/aliyungo v0.0.0-20190125010748-a747050bb1ba // indirect
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1 // indirect
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa // indirect
	github.com/garyburd/redigo v0.0.0-20150301180006-535138d7bcd7 // indirect
	github.com/godbus/dbus v0.0.0-20190422162347-ade71ed3457e // indirect
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/gorilla/handlers v0.0.0-20150720190736-60c7bfde3e33 // indirect
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/jmespath/go-jmespath v0.0.0-20160803190731-bd40a432e4c7 // indirect
	github.com/klauspost/compress v1.11.13 // indirect
	github.com/marstr/guid v1.1.0 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/mitchellh/osext v0.0.0-20151018003038-5e2d6d41470f // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/symlink v0.1.0 // indirect
	github.com/ncw/swift v1.0.47 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/opencontainers/runtime-tools v0.0.0-20181011054405-1d69bd0f9c39 // indirect
	github.com/opencontainers/selinux v1.8.4 // indirect
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tchap/go-patricia v2.2.6+incompatible // indirect
	github.com/willf/bitset v1.1.11 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v0.0.0-20180618132009-1d523034197f // indirect
	github.com/yvasiyarov/go-metrics v0.0.0-20140926110328-57bccd1ccd43 // indirect
	github.com/yvasiyarov/gorelic v0.0.0-20141212073537-a9bba5b9ab50 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20140908184405-b21fdbd4370f // indirect
	google.golang.org/cloud v0.0.0-20151119220103-975617b05ea8 // indirect
	gotest.tools/v3 v3.0.3 // indirect
	httpsvc v0.0.0-00010101000000-000000000000
	immsvc v0.0.0-00010101000000-000000000000
	immutil v0.0.0-00010101000000-000000000000 // indirect
	k8s.io/apiserver v0.20.6 // indirect
	k8s.io/cri-api v0.20.6 // indirect
	k8s.io/kubernetes v1.13.0 // indirect
	preloadimg v0.0.0-00010101000000-000000000000
)

replace immutil => ../immutil

replace httpsvc => ./httpSvcK8s

replace immsvc => ./immSvcK8s

replace preloadimg => ./preloadImg
