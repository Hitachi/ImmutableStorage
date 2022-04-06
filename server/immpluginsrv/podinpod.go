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
		immutil.ContRuntimeImg: {srcName: "/var/lib/runtime.tar.gz",}, // runtime image
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

	srcTarFile, err := os.OpenFile(findImgList[immutil.ContRuntimeImg].srcName, os.O_RDONLY, 0755)
	if err != nil {
		retErr = fmt.Errorf("failed to open %s: %s", findImgList[immutil.ContRuntimeImg].srcName, err)
		return
	}
	
	rsp, err := dockerClient.ImageLoad(context.Background(), srcTarFile, false)
	if err != nil {
		retErr = fmt.Errorf("failed to load images: %s", err)
		return
	}
	defer rsp.Body.Close()

	err = jsonmessage.DisplayJSONMessagesStream(rsp.Body, os.Stdout, os.Stdout.Fd(), false, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to load images: %s", err)
		return
	}
	
	return // success
}
