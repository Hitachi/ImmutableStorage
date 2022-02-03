/*
Copyright Hitachi, Ltd. 2022 All Rights Reserved.

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

package main

import (
	"context"
	"time"
	"bytes"
	"fmt"
	"os"
	
	dclient "github.com/docker/docker/client"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/jsonmessage"

	"immutil"
)

func initPodInPod(org string) (retErr error) {
	dockerClient, err := dclient.NewClientWithOpts(dclient.WithHost("http://localhost:2376"))
	if err != nil {
		retErr = fmt.Errorf("failed to create podman client: %s\n", err)
		return
	}

	var dImgs []types.ImageSummary
	for i := 0; i < 3; i++ {
		dImgs, err = dockerClient.ImageList(context.Background(), types.ImageListOptions{})
		if err == nil {
			break // success
		}
			
		if i == 2 {
			// give up
			retErr = fmt.Errorf("failed to list docker images: %s", err)
			return
		}
		time.Sleep(2*time.Second) // sleep 2s
	}
		
	var findImgList = map[string] *struct{
		present bool
		srcName string
	}{
		immutil.ContBuildBaseImg: {}, // builder base image
		immutil.ImmSrvImg: {}, // runtime  base image
		immutil.ContBuildImg: {srcName: "/work/buildImg.tar.gz",}, // container builder image
		immutil.ContRuntimeImg: {srcName: "/work/runtimeImg.tar.gz",}, // runtime image
	}

	// find images in podman-in-podman
	for _, img := range dImgs {
		for _, tag := range img.RepoTags {
			_, ok := findImgList[tag]
			if ok {
				findImgList[tag].present = true
			}
		}
	}

	foundAllF := true
	for _, img := range findImgList {
		if img.present == false {
			foundAllF = false
			break
		}
	}
	if foundAllF {
		return // success
	}

	// find image in registry
	registryAddr := ""
	//registryAuth := ""
	config, _, err :=  immutil.ReadOrgConfig(org)
	if err == nil && config.Registry != ""{
		registryAddr = config.Registry
		//registryAuth = os.os.Getenv("IMMS_REGISTRY_CRED")
	} else {
		registryAddr, retErr = immutil.GetLocalRegistryAddr()
		if retErr != nil {
			return
		}
	}

	regCli, err := immutil.NewRegClient("http://" + registryAddr)
	if err != nil {
		retErr = fmt.Errorf("could not connect to registry service: %s", err)
		return
	}

	repos, err := regCli.ListRepositoriesInReg()
	if err != nil {
		retErr = fmt.Errorf("failed to list repositoires: %s", err)
		return
	}

	for _, repo := range repos {
		tags, err := regCli.ListTagsInReg(repo)
		if err != nil {
			continue
		}

		for _, tag := range tags {
			ref := repo + ":" + tag
			img, ok := findImgList[ref]
			if !ok || img.present == true {
				continue
			}

			// pull and tag image
			rsp, err := dockerClient.ImagePull(context.Background(), registryAddr+"/"+ref, types.ImagePullOptions{})
			if err != nil {
				retErr = fmt.Errorf("failed to pull %s: %s", ref, err)
				return
			}
			err = jsonmessage.DisplayJSONMessagesStream(rsp, os.Stdout, os.Stdout.Fd(), false, nil)
			rsp.Close()
			if err != nil {
				retErr = fmt.Errorf("failed to pull %s: %s", ref, err)
				return
			}
			
				
			err = dockerClient.ImageTag(context.Background(), registryAddr+"/"+ref, ref)
			if err != nil {
				retErr = fmt.Errorf("failed to tag %s: %s\n", ref, err)
				return
			}
			findImgList[ref].present = true
		}
	}

	if findImgList[immutil.ContBuildBaseImg].present == false || findImgList[immutil.ImmSrvImg].present == false {
		retErr = fmt.Errorf("A base image is not found in the specified registry")
		return
	}

	for tag, img := range findImgList {
		if img.present == true || img.srcName == "" {
			continue
		}

		retErr = buildImage(dockerClient, img.srcName, tag)
		if retErr != nil {
			return
		}

		// push a image to the registry
		dockerClient.ImageTag(context.Background(), tag,  registryAddr+"/"+tag)
		rsp, err := dockerClient.ImagePush(context.Background(), registryAddr+"/"+tag, types.ImagePushOptions{})
		if err != nil {
			retErr = fmt.Errorf("failed to push %s: %s", registryAddr+"/"+tag, err)
			return
		}
		err = jsonmessage.DisplayJSONMessagesStream(rsp, os.Stdout, os.Stdout.Fd(), false, nil)
		rsp.Close()
		if err != nil {
			retErr = fmt.Errorf("failed to push %s: %s", tag, err)
			return
		}
	}
	return // success
}

func buildImage(cli *dclient.Client, srcFilename, tag string) (retErr error) {
	dockerfile, err := os.ReadFile(srcFilename)
	if err != nil {
		retErr = fmt.Errorf("failed to read a Dockerfile: %s", err)
		return
	}

	rsp, err := cli.ImageBuild(context.Background(), bytes.NewReader(dockerfile), types.ImageBuildOptions{
		Dockerfile: "Dockerfile",
		Version: types.BuilderV1,
		Tags: []string{tag,},
	})
	if err != nil {
		retErr = fmt.Errorf("failed to build a image: %s\n", err)
		return
	}
	defer rsp.Body.Close()

	err = jsonmessage.DisplayJSONMessagesStream(rsp.Body, os.Stdout, os.Stdout.Fd(), false, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to build a image: %s\n", err)
		return
	}
	

	return // success
}
