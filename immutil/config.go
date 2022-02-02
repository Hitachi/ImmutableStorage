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

package immutil

import (
	"fmt"
	"os"
	"crypto/x509/pkix"
	"gopkg.in/yaml.v2"
)

const (
	TmplDir = "/var/lib/ImmutableST/tmpl"
	VolBaseDir = "/var/lib/ImmutableST/org"
	CAHostname = "ca"
	HttpdHostname = "www"
	ImmsrvHostname = "immsrv"
	EnvoyHostname = "envoy"
	TlsCAHostname = "tlsca"
	DinDHostname = "dind"

	CaImg = "hyperledger/fabric-ca:1.5.0"
	OrdererImg = "hyperledger/fabric-orderer:1.4.11"
	CouchDBImg = "hyperledger/fabric-couchdb:amd64-0.4.22"
	PeerImg = "hyperledger/fabric-peer:1.4.11"
	//DockerImg = "library/docker:19.03.15-dind"
	DockerImg = "quay.io/podman/stable:v3.4.4"
	
	ImmHttpdImg = "library/httpd:2.4.46"

	ImmSrvImg = "library/ubuntu:20.04"
	EnvoyImg = "envoyproxy/envoy:v1.14.6"

	ContBuildBaseImg = "library/golang:1.17.6"
	ContBuildImg = "golang:contbuilder"
	ContRuntimeImg = "ubuntu:runtime"
	

	configYaml = "config.yaml"

	K8sSubDomain = "imm"
	K8sLocalSvc = ".default.svc.cluster.local"

	DockerNetPrefix = "net_hfl_"

	defaultCertCountry = `["JP"]`
	defaultCertLocality = `["Tokyo"]`
	defaultCertProvince = `["Shinagawa"]`

	workVolume = "work-vol"
	ImmsrvExpDir = "/export"
)

type ImmConfig struct {
	Subj pkix.Name
	NetName string `yaml:"DockerNetname"`
	ExternalIPs []string `yaml:"ExternalIPs"`
	Registry string `yaml:"Registry"`
}

func ReadConfigWithDefaultFile(org string) (config *ImmConfig, retErr error) {
	return ReadConfigWithFile(org, VolBaseDir + "/" + org + "/" + configYaml)
}

func ReadConfigWithFile(org, confFile string) (config *ImmConfig, retErr error) {
	confBuf, err := os.ReadFile(confFile)
	if err != nil {
		retErr = fmt.Errorf("could not read " + confFile + ": " + err.Error())
		return
	}

	config, retErr = convertYamlToStruct(org, confBuf)
	if retErr != nil {
		return
	}

	retErr = k8sWriteOrgConfig(org, string(confBuf), nil)
	return
}

func convertYamlToStruct(org string, src []byte) (config *ImmConfig, retErr error) {
	config = &ImmConfig{}
	err := yaml.Unmarshal(src, config)
	if err != nil {
		retErr = fmt.Errorf("could not read network configuration")
		return
	}
	
	err = yaml.Unmarshal(src, &config.Subj)
	if err != nil {
		retErr = fmt.Errorf("could not read a subject for certificate")
		return
	}

	config.Subj.Organization = append(config.Subj.Organization, org)

	if config.NetName == "" {
		config.NetName = DockerNetPrefix+org
	}

	return
}

func ReadOrgConfig(org string) (config *ImmConfig, retOrg string, retErr error) {
	config, retErr = k8sGenerateOrgConfig(org)
	if retErr != nil {
		return
	}

	retOrg = config.Subj.Organization[0]
	return
}
