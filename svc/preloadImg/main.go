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
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	//	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	
	"fmt"
	"os"
	"context"

	"immutil"
)

const (
	DOCKER_IO_REPO = "docker.io/"
)

func Main(args []string) {
	var findImgList = map[string] *struct{ present bool; prefix string}{
		immutil.CaImg: { false, DOCKER_IO_REPO },
		immutil.OrdererImg: { false, DOCKER_IO_REPO },
		immutil.CouchDBImg: { false, DOCKER_IO_REPO },
		immutil.PeerImg: { false, DOCKER_IO_REPO },
		immutil.DockerImg: { false, DOCKER_IO_REPO },
		immutil.ImmHttpdImg: { false, DOCKER_IO_REPO },
		immutil.ImmSrvImg: { false, DOCKER_IO_REPO },
		immutil.EnvoyImg: { false, DOCKER_IO_REPO },
		immutil.ChainCcenvImg: { false, DOCKER_IO_REPO },
		immutil.ChainBaseOsImg: { false, DOCKER_IO_REPO },
	}
	
	regAddr := ""
	regAuth := ""
	cntUnixSock := "/var/snap/microk8s/common/run/containerd.sock"
	
	if immutil.IsInKube() {
		cntUnixSock = "/run/containerd.sock"
	}
	
	config, _, err := immutil.ReadOrgConfig("")
	if err == nil && config.Registry != "" {
		regAddr = config.Registry
		regAuth = config.RegistryAuth
	}else{
		regAddr, err = immutil.GetLocalRegistryAddr()
		if err != nil {
			fmt.Printf("failed to get local registry address: %s\n", err)
			os.Exit(1)
		}
	}

	regCli, err := immutil.NewRegClient("http://" + regAddr, regAuth)
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

	cntCli, err := containerd.New(cntUnixSock)
	if err != nil {
		fmt.Printf("could not connect to containerd socket: %s\n", err)
		os.Exit(4)
	}
	defer cntCli.Close()

	imgStore := cntCli.ImageService()
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
	
	for imgName, attr := range findImgList {
		if attr.present == true {
			continue
		}

		// This image does not exist in the registry
		var cntImg containerd.Image
		img, err := imgStore.Get(ctx, attr.prefix+imgName)
		if err != nil {
			// This image does not exist in containerd
			fmt.Printf("pull %s\n", imgName)

			cntImg, err = cntCli.Pull(ctx, attr.prefix+imgName, containerd.WithPlatform("linux/amd64"), containerd.WithPullUnpack)
			if err != nil {
				fmt.Printf("failed to pull %s image: %s\n", imgName, err)
				os.Exit(6)
			}
			img = cntImg.Metadata()
		} else {
			cntImg = containerd.NewImage(cntCli, img)
		}
		
		err = cntCli.Push(ctx, regAddr+"/"+imgName, cntImg.Target())
		if err == nil {
			continue // success
		}

		// retry

		plats, err := images.Platforms(ctx, cntImg.ContentStore(), cntImg.Target())
		if err != nil {
			fmt.Printf("failed to get platforms: %s\n", err)
			os.Exit(10)
		}
		
		fmt.Printf("image: %s\n", imgName)
		for _, plat := range plats {
			fmt.Printf("unpack ARCH: %s, OS: %s\n", plat.Architecture, plat.OS)
			i := containerd.NewImageWithPlatform(cntCli, img, platforms.Only(plat))
			err = i.Unpack(ctx, "")
			if err != nil {
				fmt.Printf("failed to unpack image: %s\n", err)

				_, err = cntCli.Pull(ctx, attr.prefix+imgName, containerd.WithPlatformMatcher(platforms.Only(plat)), containerd.WithPullUnpack)
				if err != nil {
					fmt.Printf("failed to pull %s\n", imgName)
					os.Exit(11)
				}
			}
		}
		
		err = cntCli.Push(ctx, regAddr+"/"+imgName, cntImg.Target())
		if err != nil {
			fmt.Printf("failed to push %s to the registry: %s\n", err)
			os.Exit(12)
		}
	}
}
