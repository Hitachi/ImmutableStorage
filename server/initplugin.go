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

package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	
	"fmt"
	"context"
	
	"immutil"
)

func createPodmanConfig(configName, localReg string) (retErr error) {
	configMapCli, err := immutil.K8sGetConfigMapsClient()
	if err != nil {
		retErr = err
		return 
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: configName,
			Labels: map[string] string {
				"config": "podman",
			},
		},
		Data: map[string]string{
			"storage.conf": createStorageConfPodman(),
			"registries.conf": createRegConfPodman(localReg),
			"containers.conf": createCntConfPodman(),
			"subuid": "podman:10000:65536\n",
			"subgid": "podman:10000:65536\n",
		},
	}

	_, err = configMapCli.Create(context.TODO(), configMap, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a ConfigMap for the PodmanInPodman: %s\n", err)
		return
	}
	return // success
}

func createStorageConfPodman() string {
	str := `
[storage]
driver = "overlay"
runroot = "/tmp/podman-run-1000/containers"
graphroot = "/home/podman/.local/share/containers/storage"
rootless_storage_path = "$HOME/.local/share/containers/storage"

[storage.options]
[storage.options.overlay]
ignore_chown_errors = "true"
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,fsync=0"

[storage.options.thinpool]
`
	return str
}

func createRegConfPodman(localReg string) string {
	str := `
unqualified-search-registries = ["docker.io", "quay.io"]
short-name-mode="enforcing"
`
	if localReg == "" {
		return str
	}

	str += `
[[registry]]
location = "` + localReg + `"
insecure = true
`
	return str
}

func createCntConfPodman() string {
	str := `
[containers]
volumes = [
	"/proc:/proc",
]
`
	return str
}
