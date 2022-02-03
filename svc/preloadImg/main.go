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
	"github.com/docker/docker/layer"
	"github.com/docker/docker/plugin"
	"github.com/docker/docker/reference"
	distmeta "github.com/docker/docker/distribution/metadata"
	_ "github.com/docker/docker/daemon/graphdriver/overlay2"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/content/local"
	
	"go.etcd.io/bbolt"
	
	"fmt"
	"os"
	"context"

	"immutil"
)

const (
	DOCKER_IO_REPO = "docker.io/"
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
		immutil.ContBuildBaseImg: { false, DOCKER_IO_REPO },
	}
	
	regAddr := ""
	authCfgLocal := &types.AuthConfig{}
	authCfgDockerIO := &types.AuthConfig{}

	config, _, err := immutil.ReadOrgConfig("")
	if err == nil && config.Registry != "" {
		regAddr = config.Registry
		regAuth := os.Getenv("IMMS_REGISTRY_CRED")
		authCfgLocal.Username, authCfgLocal.Password = immutil.ParseCredential(regAuth)
	}else{
		regAddr, err = immutil.GetLocalRegistryAddr()
		if err != nil {
			fmt.Printf("failed to get local registry address: %s\n", err)
			os.Exit(1)
		}
	}

	authCfgDockerIO.Username, authCfgDockerIO.Password = immutil.ParseCredential(os.Getenv("IMMS_DOCKER_IO_CRED"))

	// list images in a local registry
	regCli, err := immutil.NewRegClient("http://" + regAddr)
	if err != nil {
		fmt.Printf("could not connect to registry service: %s\n", err)
		os.Exit(2)
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

	imgSvc, boltdb, err := initImageService(regAddr)
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
	
	var pullPushImage = func(imgPrefix, imgName string) error {
		pullAuthCfg := &types.AuthConfig{}
		if imgPrefix == DOCKER_IO_REPO {		
			pullAuthCfg = authCfgDockerIO
		}

		fmt.Printf("pull %s\n", imgPrefix+imgName)
		err := imgSvc.PullImage(context.Background(), imgPrefix+imgName, "", &plat, metaHeaders, pullAuthCfg, os.Stdout)
		if err != nil {
			return fmt.Errorf("failed to pull %s image: %s", imgName, err)
		}
		
		newTag, err := imgSvc.TagImage(imgName, regAddr+"/"+imgName, "")
		if err != nil {
			return fmt.Errorf("failed to tag %s image: %s", imgName, err)
		}
		fmt.Printf("tagged %s\n", newTag)

		fmt.Printf("push %s\n", regAddr+"/"+imgName)		
		err = imgSvc.PushImage(context.Background(), regAddr+"/"+imgName, "", metaHeaders, authCfgLocal, os.Stdout)
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
}

func initImageService(regAddr string) (imgSvc *images.ImageService, boltdb *bbolt.DB, retErr error){
	baseDir := "/work"
	imageRoot := baseDir+"/image/overlayfs"	
	
	err := os.MkdirAll(baseDir+"/content", 0700)
	if err != nil {
		retErr = fmt.Errorf("failed to make a directory: %s", err)
		return
	}
	
	// create temporary stores
	pluginStore := plugin.NewStore()
	layerStores := make(map[string]layer.Store)
	layerStores["linux"], err = layer.NewStoreFromOptions(layer.StoreOptions{
		Root: baseDir,
		MetadataStorePathTemplate: baseDir+"/image/%s/layerdb",
		IDMapping: &idtools.IdentityMapping{},
		PluginGetter: pluginStore,
		OS: "linux",
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

	layerMap := make(map[string]image.LayerGetReleaser)
	layerMap["linux"] = layerStores["linux"]
	
	imageStore, err := image.NewImageStore(fsBackend, layerMap)
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

	regSvc, err := registry.NewService(registry.ServiceOptions{
		InsecureRegistries: []string{regAddr,},
	})
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
		LayerStores: layerStores,
		MaxConcurrentDownloads: 3,
		MaxConcurrentUploads: 5,
		MaxDownloadAttempts: 5,
		EventsService: events.New(),
	}
	
	imgSvc = images.NewImageService(imgSvcCfg)
	return// success
}
