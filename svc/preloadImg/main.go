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
	netconfig "github.com/docker/docker/libnetwork/config"
	
	"go.etcd.io/bbolt"

	"fmt"
	"os"
	"os/exec"
	"bytes"
	"io"
	"context"

	"immutil"
)

const (
	DOCKER_IO_REPO = "docker.io/"
	baseDir = "/work"
)

type localRegistry struct{
	imgSvc *images.ImageService
	regAddr string
	plat *specs.Platform
	authCfgLocal *types.AuthConfig
	resultPipe *io.PipeWriter
	builder *buildernext.Builder
	isCgroupV2 bool
}

func Main(args []string) {
	var findImgList = map[string] *struct{present bool; prefix string}{
		immutil.CaImg: { false, DOCKER_IO_REPO },
		immutil.OrdererImg: { false, DOCKER_IO_REPO },
		immutil.CouchDBImg: { false, DOCKER_IO_REPO },
		immutil.PeerImg: { false, DOCKER_IO_REPO },
		immutil.ImmHttpdImg: { false, DOCKER_IO_REPO },
		immutil.ImmSrvBaseImg: { false, DOCKER_IO_REPO },
		immutil.EnvoyImg: { false, DOCKER_IO_REPO },
		immutil.RsyslogBaseImg: { false, DOCKER_IO_REPO },
		
		immutil.ST2AuthBaseImg: { false, DOCKER_IO_REPO },

		immutil.MongoDBImg: { false, DOCKER_IO_REPO },
		immutil.RabbitMQImg: { false, DOCKER_IO_REPO },
		immutil.RedisImg: { false, DOCKER_IO_REPO },
		
		immutil.ST2ActionRunnerImg: {},
		immutil.ST2APIImg: { false, DOCKER_IO_REPO },
		immutil.ST2StreamImg: { false, DOCKER_IO_REPO },
		immutil.ST2SchedulerImg: { false, DOCKER_IO_REPO },
		immutil.ST2WorkflowEngineImg: { false, DOCKER_IO_REPO },
		immutil.ST2GarbageCollectorImg: { false, DOCKER_IO_REPO },
		immutil.ST2NotifierImg: { false, DOCKER_IO_REPO },
		immutil.ST2RuleEngineImg: { false, DOCKER_IO_REPO },
		immutil.ST2SensorContainerImg: { false, DOCKER_IO_REPO },
		immutil.ST2TimerEngineImg: { false, DOCKER_IO_REPO },
		immutil.ST2ChatopsImg: { false, DOCKER_IO_REPO },
		immutil.ST2WebImg: { false, DOCKER_IO_REPO },
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

	// pull images to the local registry
	var retErr error
	defer func() {
		if retErr != nil {
			fmt.Printf("%s\n", retErr)
			os.Exit(14)
		}
	}()
	
	locReg := &localRegistry{
		imgSvc: imgSvc,
		regAddr: regAddr,
		plat: &plat,
		authCfgLocal: authCfgLocal,
		resultPipe: resultW,
	}

	// build images
	retErr = locReg.initImgBuilder()
	if retErr != nil {
		return
	}
	
	srcImgs := []struct{
		srcFile string
		baseImg string
		pushTag string
	}{
		{immutil.ImgSrcDir+"/immpluginsrv.tar", immutil.ContRuntimeBaseImg, immutil.ImmPluginSrvImg},
		{immutil.ImgSrcDir+"/immsrv.tar", immutil.ImmSrvBaseImg, immutil.ImmSrvImg},		
		{immutil.ImgSrcDir+"/rsyslog2imm.tar", immutil.RsyslogBaseImg, immutil.RsyslogImg},
		{immutil.ImgSrcDir+"/st2-auth-backend.tar", immutil.ST2AuthBaseImg, immutil.ST2AuthImg},
		{immutil.ImgSrcDir+"/immgrpcproxy.tar", immutil.ImmGRPCProxyBaseImg, immutil.ImmGRPCProxyImg},
	}
	
	for i := 0; i < len(srcImgs); i++ {
		srcImg := srcImgs[i]
		fmt.Printf("build %s image\n", srcImg.pushTag)

		
		retErr = locReg.pullImg(srcImg.baseImg)
		if retErr != nil {
			return
		}

		err = locReg.buildImg(srcImg.srcFile, srcImg.baseImg, srcImg.pushTag)
		if err != nil {
			retErr = fmt.Errorf("failed to build %s: %s", srcImg.pushTag, err)
			return
		}

		err = locReg.pushImg(srcImg.pushTag)
		if err != nil {
			retErr = err
		}
	}

	return // success
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

func shCmd(cmdStr string) (outStr string, retErr error) {
	var str bytes.Buffer
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	cmd.Stdout = &str
	retErr = cmd.Run()
	if retErr != nil {
		return
	}
	
	outBytes, retErr := io.ReadAll(&str)
	if retErr != nil {
		return
	}

	outStr = string(outBytes)
	return
}

func cgroupType() (retFileType string) {
	retFileType, _ = shCmd("echo -n $(stat -fc %T /sys/fs/cgroup/)")
	if retFileType == "" {
		retFileType = "Unknown"
	}
	return
}

func remountCgroupWritable() (retErr error) {
	_, retErr = shCmd("mount -t cgroup2 -o remount,rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot none /sys/fs/cgroup")
	return
}

func unmountCgroupForBuilder() (retErr error) {
	cgroupDirs := []string{"/sys/fs/cgroup/docker/buildkit", "/sys/fs/cgroup/docker"}
	for i := 0; i < len(cgroupDirs); i++ {
		_, retErr = shCmd("if [ -d "+cgroupDirs[i]+" ]; then rmdir "+cgroupDirs[i]+"; fi")
		if retErr != nil {
			return
		}
	}
	return // success
}

func (lr *localRegistry) initImgBuilder() (retErr error) {
	lr.isCgroupV2 = (cgroupType() == "cgroup2fs")
	if lr.isCgroupV2 {
		// remount the cgroup filesystem as writable
		err := remountCgroupWritable()
		if err != nil {
			retErr = err
			return
		}
	}
	
	sessionMng, err := session.NewManager()
	if err != nil {
		retErr = fmt.Errorf("failed to create a manager for session: %s", err)
		return
	}

	registryCfg := map[string]resolvercfg.RegistryConfig{}
	
	netOptions := []netconfig.Option{}
	netOptions = append(netOptions, netconfig.OptionDataDir(baseDir))
	netOptions = append(netOptions, netconfig.OptionExecRoot("/var/lib/docker")) // not rootless
	netOptions = append(netOptions, netconfig.OptionDefaultDriver("host"))
	netOptions = append(netOptions, netconfig.OptionDefaultNetwork("host"))

	controller, err := libnetwork.New(netOptions...)
	if err != nil {
		retErr = fmt.Errorf("failed to create network controller: %s", err)
		return
	}

	net, _ := controller.NetworkByName("host")
	if net == nil {
		_, err := controller.NewNetwork("host", "host", "", libnetwork.NetworkOptionPersist(true))
		if err != nil {
			retErr = fmt.Errorf("failed to create the default host network: %s", err)
			return
		}
	}
	
	lr.builder, err = buildernext.New(buildernext.Opt{
		SessionManager: sessionMng,
		Root: baseDir + "/buildkit",
		Dist: lr.imgSvc.DistributionServices(),
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

func (lr *localRegistry) pullImg(baseImgName string) error {
	metaHeaders := map[string][]string{}
	pullTag := lr.regAddr+"/"+baseImgName
	err := lr.imgSvc.PullImage(context.Background(), pullTag, "", lr.plat, metaHeaders, lr.authCfgLocal, lr.resultPipe)
	if err != nil {
		return fmt.Errorf("failed to pull %s: %s", baseImgName, err)
	}

	_, err = lr.imgSvc.TagImage(pullTag, baseImgName, "")
	if err != nil {
		return fmt.Errorf("failed to tag %s image: %s", baseImgName, err)
	}

	return nil // success
}

func (lr *localRegistry) pushImg(imgName string) error {
	metaHeaders := map[string][]string{}
	pushTag := lr.regAddr+"/"+imgName
	_, err := lr.imgSvc.TagImage(imgName, pushTag, "")
	if err != nil {
		return fmt.Errorf("failed to tag %s image: %s", imgName, err)
	}
	err = lr.imgSvc.PushImage(context.Background(), pushTag, "", metaHeaders, lr.authCfgLocal, lr.resultPipe)
	if err != nil {
		return fmt.Errorf("failed to push %s image: %s", imgName, err)
	}

	return nil /// success
}

func (lr *localRegistry) buildImg(srcTarFile, baseImg, tag string) (retErr error) {
	src, err := os.Open(srcTarFile)
	if err != nil {
		retErr = fmt.Errorf("failed to open a tar file: %s", err)
		return
	}

	srcStat, err := src.Stat()
	if err != nil {
		retErr = fmt.Errorf("could not get the length of the tar file: %s", err)
		return
	}
	srcSize := srcStat.Size()
	
	buildArgs := map[string]*string{
		"BASEIMG": &baseImg,
	}
	
	imgID, err := lr.builder.Build(context.Background(),
		backend.BuildConfig{
			Source: src,
			Options: &types.ImageBuildOptions{
				Dockerfile: "Dockerfile",
				Version: types.BuilderBuildKit,
				Tags: []string{tag, },
				NetworkMode: "host",
				BuildArgs: buildArgs,
			},
			ProgressWriter: backend.ProgressWriter{
				Output: lr.resultPipe,
				StdoutFormatter: streamformatter.NewStdoutWriter(lr.resultPipe),
				StderrFormatter: streamformatter.NewStdoutWriter(lr.resultPipe),
				AuxFormatter: nil,
				ProgressReaderFunc: func(in io.ReadCloser) io.ReadCloser {
					progressOutput := streamformatter.NewJSONProgressOutput(lr.resultPipe, true)
					return progress.NewProgressReader(in, progressOutput, srcSize, "Downloading context", "")
				},
			},
		})
	defer func(){
		unmountCgroupForBuilder()
	}()
	
	if err != nil {
		retErr = fmt.Errorf("failed to build a image: %s", err)
		return
	}
	
	fmt.Printf("image ID: %s\n", imgID.ImageID)
	return // success
}
