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
	"github.com/containerd/containerd/remotes/docker"	
	//	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"net/http"
	"time"
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
		immutil.DockerImg: { false, DOCKER_IO_REPO },
		immutil.ImmHttpdImg: { false, DOCKER_IO_REPO },
		immutil.ImmSrvImg: { false, DOCKER_IO_REPO },
		immutil.EnvoyImg: { false, DOCKER_IO_REPO },
		immutil.ChainCcenvImg: { false, DOCKER_IO_REPO },
		immutil.ChainBaseOsImg: { false, DOCKER_IO_REPO },
	}
	
	regAddr := ""
	cntUnixSock := "/var/snap/microk8s/common/run/containerd.sock"
	
	if immutil.IsInKube() {
		cntUnixSock = "/run/containerd.sock"
	}


	var pushHosts docker.RegistryHosts
	config, _, err := immutil.ReadOrgConfig("")
	if err == nil && config.Registry != "" {
		regAddr = config.Registry

		privUsername, privSecret := immutil.ParseCredential(config.RegistryAuth)
		if privSecret != "" {
			pushHosts = docker.ConfigureDefaultRegistries(
				docker.WithAuthorizer(
					docker.NewDockerAuthorizer(
						docker.WithAuthCreds(func(string) (string, string, error) {
							return privUsername, privSecret, nil
						}))))
		}
		
	}else{
		regAddr, err = immutil.GetLocalRegistryAddr()
		if err != nil {
			fmt.Printf("failed to get local registry address: %s\n", err)
			os.Exit(1)
		}

		pushHosts =  docker.ConfigureDefaultRegistries(
			docker.WithPlainHTTP(func(string) (bool, error) {
				return true, nil
			}))
	}
	
	pushResolver := containerd.WithResolver(
		docker.NewResolver(docker.ResolverOptions{
			Client: http.DefaultClient,
			Hosts: pushHosts,
		}))


	var dockerIoHosts docker.RegistryHosts
	dUsername, dSecret := immutil.ParseCredential(os.Getenv("IMMS_DOCKER_IO_CRED"))
	if dSecret != "" {
		dockerIoHosts = docker.ConfigureDefaultRegistries(
			docker.WithAuthorizer(
				docker.NewDockerAuthorizer(
					docker.WithAuthCreds(func(string) (string, string, error) {
						return dUsername, dSecret, nil
					}))))
	}
	dockerIoResolver := containerd.WithResolver(
		docker.NewResolver(docker.ResolverOptions{
			Client: http.DefaultClient,
			Hosts: dockerIoHosts,
		}))


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

	cntCli, err := containerd.New(cntUnixSock)
	if err != nil {
		fmt.Printf("could not connect to containerd socket: %s\n", err)
		os.Exit(4)
	}
	defer cntCli.Close()

	imgStore := cntCli.ImageService()
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	var pullPushImage = func(imgPrefix, imgName string) error {
		var cntImg containerd.Image
		img, err := imgStore.Get(ctx, imgPrefix+imgName)
		if err != nil {
			// This image does not exist in containerd
			fmt.Printf("pull %s\n", imgName)
			
			cntImg, err = cntCli.Pull(ctx, imgPrefix+imgName, containerd.WithPlatform("linux/amd64"), containerd.WithPullUnpack, dockerIoResolver)
			if err != nil {
				return fmt.Errorf("failed to pull %s image: %s", imgName, err)
			}
			img = cntImg.Metadata()
		} else {
			cntImg = containerd.NewImage(cntCli, img)
		}
		
		err = cntCli.Push(ctx, regAddr+"/"+imgName, cntImg.Target(), pushResolver)
		if err == nil {
			findImgList[imgName].present = true
			return nil // success
		}
			
		// retry
		plats, err := images.Platforms(ctx, cntImg.ContentStore(), cntImg.Target())
		if err != nil {
			return fmt.Errorf("failed to get platforms: %s", err)
		}
		
		fmt.Printf("image: %s\n", imgName)
		for _, plat := range plats {
			fmt.Printf("unpack ARCH: %s, OS: %s\n", plat.Architecture, plat.OS)
			i := containerd.NewImageWithPlatform(cntCli, img, platforms.Only(plat))
			err = i.Unpack(ctx, "")
			if err != nil {
				fmt.Printf("failed to unpack image: %s\n", err)
				
				_, err = cntCli.Pull(ctx, imgPrefix+imgName, containerd.WithPlatformMatcher(platforms.Only(plat)), containerd.WithPullUnpack, dockerIoResolver)
				if err != nil {
					return fmt.Errorf("failed to pull %s", imgName)
				}
			}
		}
			
		err = cntCli.Push(ctx, regAddr+"/"+imgName, cntImg.Target(), pushResolver)
		if err != nil {
			return fmt.Errorf("failed to push %s to the registry: %s", imgName, err)
		}
		
		findImgList[imgName].present = true // success
		return nil // success
	}

	for i := 0; i < 5; i++ {
		for imgName, attr := range findImgList {
			if attr.present == true {
				continue
			}

			// This image does not exist in the registry			
			err = pullPushImage(attr.prefix, imgName)
			if err != nil {
				fmt.Printf("%s\n", err)
			}
		}
		
		if err == nil {
			return // success
		}

		time.Sleep(5*time.Second) // sleep 5s
		err = nil // retry
	}

	if err != nil {
		os.Exit(5) // give up
	}
}
