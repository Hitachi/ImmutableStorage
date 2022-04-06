/*
Copyright Hitachi, Ltd. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package preloadimg

import (
	"github.com/docker/docker/daemon/images"
	"github.com/docker/docker/daemon/events"
	"github.com/docker/docker/image"
	"github.com/docker/docker/registry"
	"github.com/docker/docker/api/types"
	//"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/idtools"
	//"github.com/docker/docker/pkg/reexec"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/streamformatter"
	"github.com/docker/docker/pkg/progress"
	
	"github.com/docker/docker/layer"
	"github.com/docker/docker/plugin"
	"github.com/docker/docker/reference"
	distmeta "github.com/docker/docker/distribution/metadata"
	_ "github.com/docker/docker/daemon/graphdriver/overlay2"

	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/content/local"

	buildernext "github.com/docker/docker/builder/builder-next"
	"github.com/docker/docker/daemon"
	"github.com/docker/docker/api/types/backend"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/moby/buildkit/session"
	resolvercfg "github.com/moby/buildkit/util/resolver/config"
	"github.com/moby/buildkit/util/resolver"
	"github.com/docker/docker/daemon/config"	
	"github.com/docker/docker/libnetwork"
	"github.com/docker/docker/libnetwork/netlabel"
	"github.com/docker/docker/libnetwork/drivers/bridge"
	netconfig "github.com/docker/docker/libnetwork/config"
	"github.com/docker/docker/libnetwork/options"
	"github.com/vishvananda/netlink"
	
	"go.etcd.io/bbolt"

	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"io"
	"context"
	"bytes"

	"immutil"
)

const (
	DOCKER_IO_REPO = "docker.io/"
	baseDir = "/work"
)

func Main(args []string) {
	var findImgList = map[string] *struct{present bool; prefix string}{
		immutil.CaImg: { false, DOCKER_IO_REPO },
		immutil.OrdererImg: { false, DOCKER_IO_REPO },
		immutil.CouchDBImg: { false, DOCKER_IO_REPO },
		immutil.PeerImg: { false, DOCKER_IO_REPO },
		immutil.DockerImg: { false, ""},
		immutil.ImmHttpdImg: { false, DOCKER_IO_REPO },
		immutil.ImmSrvImg: { false, DOCKER_IO_REPO },
		immutil.EnvoyImg: { false, DOCKER_IO_REPO },
	}
	
	authCfgLocal := &types.AuthConfig{}
	authCfgDockerIO := &types.AuthConfig{}
	token := ""
	scheme := "http://"

	config, _, err := immutil.ReadOrgConfig("")
	if err != nil {
		fmt.Printf("failed to configure Immutable Storage: %s\n", err)
		os.Exit(4)
	}

	localRegAddr := ""
	regAddr := config.Registry
	if regAddr != "" {
		localRegAddr = regAddr
		
		regAuth := os.Getenv("IMMS_REGISTRY_CRED")
		authCfgLocal.Username, authCfgLocal.Password = immutil.ParseCredential(regAuth)
		
		token = os.Getenv("IMMS_REGISTRY_TOKEN")
		if token != "" || authCfgLocal.Password != "" {
			scheme = "https://"
			localRegAddr = ""
		}

		if authCfgLocal.Username == "" && authCfgLocal.Password != "" {
			token = authCfgLocal.Password
		}
	} else {
		regAddr, err = immutil.GetLocalRegistryAddr()
		if err != nil {
			fmt.Printf("failed to get local registry address: %s\n", err)
			os.Exit(1)
		}
		localRegAddr = regAddr
	}

	authCfgDockerIO.Username, authCfgDockerIO.Password = immutil.ParseCredential(os.Getenv("IMMS_DOCKER_IO_CRED"))

	// list images in a local registry
	regCli, err := immutil.NewRegClient(scheme + regAddr, token)
	if err != nil {
		fmt.Printf("could not connect to registry service: %s\n", err)
		os.Exit(2)
	}

	if token != "" {
		authCfgLocal.RegistryToken, err = regCli.GetRegistryToken()
		if err != nil {
			fmt.Printf("failed to get a registry token: %s\n", err)
			os.Exit(5)
		}
	}
	
	repos, err := regCli.ListRepositoriesInReg()
	if err != nil {
		fmt.Printf("failed to list repositories: %s\n", err)
		os.Exit(3)
	}

	for _, repo := range repos {
		tags, err := regCli.ListTagsInReg(repo)
		if err != nil {
			continue
		}

		for _, tag := range tags {
			ref := repo + ":" + tag
			_, ok := findImgList[ref]
			if !ok {
				continue
			}

			findImgList[ref].present = true
		}
	}

	imgSvc, boltdb, err := initImageService(localRegAddr)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(10)
	}
	defer boltdb.Close()

	plat, err := platforms.Parse("linux/amd64")
	if err != nil {
		fmt.Printf("failed to parse a platform: %s\n", err)
		os.Exit(11)
	}
	metaHeaders := map[string][]string{}

	resultR, resultW := io.Pipe()
	go displayProgress(resultR)
	defer resultW.Close()
	
	var pullPushImage = func(imgPrefix, imgName string) error {
		pullAuthCfg := &types.AuthConfig{}
		if imgPrefix == DOCKER_IO_REPO {		
			pullAuthCfg = authCfgDockerIO
		}

		fmt.Printf("pull %s\n", imgPrefix+imgName)
		err := imgSvc.PullImage(context.Background(), imgPrefix+imgName, "", &plat, metaHeaders, pullAuthCfg, resultW)
		if err != nil {
			return fmt.Errorf("failed to pull %s image: %s", imgName, err)
		}
		
		newTag, err := imgSvc.TagImage(imgName, regAddr+"/"+imgName, "")
		if err != nil {
			return fmt.Errorf("failed to tag %s image: %s", imgName, err)
		}
		fmt.Printf("tagged %s\n", newTag)

		fmt.Printf("push %s\n", regAddr+"/"+imgName)		
		err = imgSvc.PushImage(context.Background(), regAddr+"/"+imgName, "", metaHeaders, authCfgLocal, resultW)
		if err != nil {
			return fmt.Errorf("failed to push %s image: %s\n", imgName, err)			
		}

		findImgList[imgName].present = true
		return nil // success
	}

	for imgName, attr := range findImgList {
		if attr.present == true {
			continue
		}

		// This image does not exist in the registry			
		err = pullPushImage(attr.prefix, imgName)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(12)
		}
	}

	// build plugin image
	err = buildImmPluginImg(imgSvc, regAddr, &plat, authCfgLocal, resultW)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(13)
	}
}

func initImageService(localRegAddr string) (imgSvc *images.ImageService, boltdb *bbolt.DB, retErr error) {
	imageRoot := baseDir+"/image/overlayfs"	
	
	err := os.MkdirAll(baseDir+"/content", 0700)
	if err != nil {
		retErr = fmt.Errorf("failed to make a directory: %s", err)
		return
	}
	
	// create temporary stores
	pluginStore := plugin.NewStore()
	layerStore, err := layer.NewStoreFromOptions(layer.StoreOptions{
		Root: baseDir,
		MetadataStorePathTemplate: baseDir+"/image/%s/layerdb",
		IDMapping: idtools.IdentityMapping{},
		PluginGetter: pluginStore,
		ExperimentalEnabled: true,
	})
	if err != nil {
		retErr = fmt.Errorf("failed to create a layer store: %s", err)
		return
	}

	fsBackend, err := image.NewFSStoreBackend(imageRoot+"/imagedb")
	if err != nil {
		retErr = fmt.Errorf("failed to create a backend: %s", err)
		return
	}

	imageStore, err := image.NewImageStore(fsBackend, layerStore)
	if err != nil {
		retErr = fmt.Errorf("failed to create an image store: %s", err)
		return
	}

	refStore, err := reference.NewReferenceStore(imageRoot+"/repositories.json")
	if err != nil {
		retErr = fmt.Errorf("failed to create a reference store: %s", err)
		return
	}

	distMetaStore, err := distmeta.NewFSMetadataStore(imageRoot+"/distribution")
	if err != nil {
		retErr = fmt.Errorf("failed to create a metatdata store: %s", err)
		return
	}

	svcOpt := registry.ServiceOptions{}
	if localRegAddr != "" {
		svcOpt.InsecureRegistries = []string{localRegAddr,}
	}
	regSvc, err := registry.NewService(svcOpt)
	if err != nil {
		retErr = fmt.Errorf("failed to create a registry service: %s", err)
		return
	}

	contentStore, err := local.NewStore(baseDir+"/content/data")
	if err != nil {
		retErr = fmt.Errorf("failed to create a local content store: %s", err)
		return
	}
	
	boltdb, err = bbolt.Open(baseDir+"/content/metadata.db", 0600, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a bolt database: %s", err)
		return
	}
	metadb := metadata.NewDB(boltdb, contentStore, nil)
	
	imgSvcCfg := images.ImageServiceConfig{
		DistributionMetadataStore: distMetaStore,
		ImageStore: imageStore,
		ContentStore: metadb.ContentStore(),
		Leases: metadata.NewLeaseManager(metadb),
		ContentNamespace: "tmpstore",
		ReferenceStore: refStore,
		RegistryService: regSvc,
		LayerStore: layerStore,
		MaxConcurrentDownloads: 3,
		MaxConcurrentUploads: 5,
		MaxDownloadAttempts: 5,
		EventsService: events.New(),
	}
	
	imgSvc = images.NewImageService(imgSvcCfg)
	return// success
}

func initImgBuilder(imgSvc *images.ImageService) (builder *buildernext.Builder, retErr error) {
	sessionMng, err := session.NewManager()
	if err != nil {
		retErr = fmt.Errorf("failed to create a manager for session: %s", err)
		return
	}

	registryCfg := map[string]resolvercfg.RegistryConfig{}
	
	netOptions := []netconfig.Option{}
	netOptions = append(netOptions, netconfig.OptionDataDir(baseDir))
	netOptions = append(netOptions, netconfig.OptionExecRoot("/var/lib/docker")) // not rootless
	netOptions = append(netOptions, netconfig.OptionDefaultDriver("bridge"))
	netOptions = append(netOptions, netconfig.OptionDefaultNetwork("bridge"))
	netOptions = append(netOptions, netconfig.OptionNetworkControlPlaneMTU(1500))

	bridgeConfig := options.Generic{
		"EnableIPForwarding": true,
		"EnableIPTables": true,
		"EnableUserlandProxy": true,
	}
	
	bridgeOptions := options.Generic{netlabel.GenericData: bridgeConfig}
	netOptions = append(netOptions, netconfig.OptionDriverConfig("bridge", bridgeOptions))

	controller, err := libnetwork.New(netOptions...)
	if err != nil {
		retErr = fmt.Errorf("failed to create network controller: %s", err)
		return
	}

	net, err := controller.NetworkByName("bridge")
	if net != nil {
		err = net.Delete()
		if err != nil {
			retErr = fmt.Errorf("failed to delete the default bridge network: %s", err)
			return
		}
		
		link, err := netlink.LinkByName(bridge.DefaultBridgeName)
		if err == nil {
			err = netlink.LinkDel(link)
			if err != nil {
				retErr = fmt.Errorf("failed to delete bridge interface (%s): %s", bridge.DefaultBridgeName, err)
				return
			}
		}
	}

		netOption := map[string]string{
		bridge.BridgeName: bridge.DefaultBridgeName,
		bridge.DefaultBridge: "true",
		netlabel.DriverMTU: "1500",
		bridge.EnableIPMasquerade: "true",
		bridge.EnableICC: "true",
	}

	ipamV4Conf := &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
	ipamV4Conf.PreferredPool = "172.17.0.0/16"
	ipamV4Conf.Gateway = "172.17.0.1"
	v4Conf := []*libnetwork.IpamConf{ipamV4Conf}
	v6Conf := []*libnetwork.IpamConf{}
	
	_, err = controller.NewNetwork("bridge", "bridge", "",
		libnetwork.NetworkOptionEnableIPv6(false),
		libnetwork.NetworkOptionDriverOpts(netOption),
		libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil),
		libnetwork.NetworkOptionDeferIPv6Alloc(false))
	if err != nil {
		retErr = fmt.Errorf("failed to create default bridge network: %s", err)
		return
	}
	
	builder, err = buildernext.New(buildernext.Opt{
		SessionManager: sessionMng,
		Root: baseDir + "/buildkit",
		Dist: imgSvc.DistributionServices(),
		NetworkController: controller,
		DefaultCgroupParent: "docker",
		RegistryHosts: resolver.NewRegistryConfig(registryCfg),
		BuilderConfig: config.BuilderConfig{},
		Rootless: false,
		IdentityMapping: idtools.IdentityMapping{},
		DNSConfig: config.DNSConfig{},
		ApparmorProfile: daemon.DefaultApparmorProfile(),
	})

	if err != nil {
		retErr = fmt.Errorf("failed to create a builder: %s", err)
		return
	}

	return // success
}

func displayProgress(resultR *io.PipeReader) {
	err := jsonmessage.DisplayJSONMessagesStream(resultR, os.Stdout, os.Stdout.Fd(), true, nil)
	defer resultR.Close()

	if err != nil {
		fmt.Printf("got an error: %s\n", err)
	}	
}

func buildImg(builder *buildernext.Builder, src io.ReadCloser, srcSize int64, tag string, resultW *io.PipeWriter) (retErr error) {
	imgID, err := builder.Build(context.Background(),
		backend.BuildConfig{
			Source: src,
			Options: &types.ImageBuildOptions{
				Dockerfile: "Dockerfile",
				Version: types.BuilderBuildKit,
				Tags: []string{tag, },
			},
			ProgressWriter: backend.ProgressWriter{
				Output: resultW,
				StdoutFormatter: streamformatter.NewStdoutWriter(resultW),
				StderrFormatter: streamformatter.NewStdoutWriter(resultW),
				AuxFormatter: nil,
				ProgressReaderFunc: func(in io.ReadCloser) io.ReadCloser {
					progressOutput := streamformatter.NewJSONProgressOutput(resultW, true)
					return progress.NewProgressReader(in, progressOutput, srcSize, "Downloading context", "")
				},
			},
		})
	if err != nil {
		retErr = fmt.Errorf("failed to build a image: %s", err)
		return
	}
	
	fmt.Printf("image ID: %s\n", imgID.ImageID)
	return // success
}

func buildImmPluginImg(imgSvc *images.ImageService, regAddr string, plat *specs.Platform, authCfgLocal *types.AuthConfig, resultW *io.PipeWriter) error {
	baseImgName := immutil.ContRuntimeBaseImg
	metaHeaders := map[string][]string{}
	
	err := imgSvc.PullImage(context.Background(), regAddr+"/"+baseImgName, "", plat, metaHeaders, authCfgLocal, resultW)
	if err != nil {
		return fmt.Errorf("failed to pull %s: %s", baseImgName, err)
	}

	_, err = imgSvc.TagImage(regAddr+"/"+baseImgName, baseImgName, "")
	if err != nil {
		return fmt.Errorf("failed to tag %s image: %s", baseImgName, err)
	}

	builder, err := initImgBuilder(imgSvc)
	if err != nil {
		return fmt.Errorf("failed to create a builder: %s", err)
	}

	srcRunImg, err := os.OpenFile(immutil.ImmPluginDir+"/runtimeImg.tar.gz", os.O_RDONLY, 0755)
	if err != nil {
		return fmt.Errorf("failed to open a file: %s", err)
	}

	srcRunImgInfo, err := srcRunImg.Stat()
	if err != nil {
		return  fmt.Errorf("could not get the file length: %s", err)
	}
	
	err = buildImg(builder, srcRunImg, srcRunImgInfo.Size(), immutil.ContRuntimeImg, resultW)
	if err != nil {
		return fmt.Errorf("failed to build a plugin image: %s", err)
	}

	var tarBuf bytes.Buffer
	err = imgSvc.ExportImage([]string{immutil.ContRuntimeImg,}, &tarBuf)
	if err != nil {
		return fmt.Errorf("could not get a plugin image from the image service: %s", err)
	}

	var gzipBuf bytes.Buffer
	zipwriter := gzip.NewWriter(&gzipBuf)
	zipwriter.Write(tarBuf.Bytes())
	zipwriter.Close()

	dockerfileStr := `
FROM ` + baseImgName+`
WORKDIR /var/lib
COPY ./runtime.tar.gz ./
COPY ./immpluginsrv ./
`
	dockerfile := []byte(dockerfileStr)
	
	srcPluginSrvFile, err := os.OpenFile(immutil.ImmPluginDir+"/immpluginsrv", os.O_RDONLY, 0755)
	if err != nil {
		return fmt.Errorf("could not open the immpluginsrv file: %s", err)
	}
	
	srcPluginSrv, err := io.ReadAll(srcPluginSrvFile)
	if err != nil {
		return fmt.Errorf("failed to read the immpluginsrv flie: %s", err)
	}
	
	tarData := []immutil.TarData{
		{&tar.Header{ Name: "Dockerfile", Mode: 0444, Size: int64(len(dockerfile)), }, dockerfile },
		{&tar.Header{ Name: "immpluginsrv", Mode: 0775, Size: int64(len(srcPluginSrv)), }, srcPluginSrv },
		{&tar.Header{ Name: "runtime.tar.gz", Mode: 0664, Size: int64(gzipBuf.Len()), }, gzipBuf.Bytes() },
	}
	pluginSrc, err := immutil.GetTarBuf(tarData)
	if err != nil {
		return fmt.Errorf("failed to get tar data: %s", err)
	}

	err = buildImg(builder, io.NopCloser(&pluginSrc), int64(pluginSrc.Len()), immutil.ImmPluginSrvImg, resultW)
	if err != nil {
		return fmt.Errorf("failed to build the immpluginsrv image: %s", err)
	}

	imgName := immutil.ImmPluginSrvImg
	_, err = imgSvc.TagImage(imgName, regAddr+"/"+imgName, "")
	if err != nil {
		return fmt.Errorf("failed to tag %s image: %s", imgName, err)
	}

	err = imgSvc.PushImage(context.Background(), regAddr+"/"+immutil.ImmPluginSrvImg, "", metaHeaders, authCfgLocal, resultW)
	if err != nil {
		return fmt.Errorf("failed to push %s image: %s", immutil.ImmPluginSrvImg, err)
	}
	
	return nil /// success
}
