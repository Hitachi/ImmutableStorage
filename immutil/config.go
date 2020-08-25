package immutil

import (
	"fmt"
	"io/ioutil"
	"crypto/x509/pkix"
	"gopkg.in/yaml.v2"
)

const (
	TmplDir = "/var/lib/ImmutableDS/tmpl"
	ConfBaseDir = "/var/lib/ImmutableDS/org"
	CAHostname = "ca"
	HttpdHostname = "www"
	ImmsrvHostname = "immsrv"
	EnvoyHostname = "envoy"
	TlsCAHostname = "tlsca"

	CaImg = "hyperledger/fabric-ca:1.4.6"
	OrdererImg = "hyperledger/fabric-orderer:1.4.6"
	CouchDBImg = "hyperledger/fabric-couchdb:amd64-0.4.20"
	PeerImg = "hyperledger/fabric-peer:1.4.6"
	DockerImg = "docker:19.03.9-dind"
	
	ImmHttpdImg = "httpd:2.4.43-alpine"

	ImmSrvImg = "ubuntu:20.10"
	EnvoyImg = "envoyproxy/envoy:v1.14.1"

	configYaml = "config.yaml"

	K8sSubDomain = "imm"
	K8sLocalSvc = ".default.svc.cluster.local"
	
	DockerNetPrefix = "net_hfl_"
)

type ImmConfig struct {
	Subj pkix.Name
	NetName string `yaml:"DockerNetname"`
	ExternalIPs []string `yaml:"ExternalIPs"`
}

func ReadConf(org string) (config *ImmConfig, retErr error) {
	config = &ImmConfig{}
	
	confFile := ConfBaseDir + "/" + org + "/" + configYaml
	confBuf, err := ioutil.ReadFile(confFile)
	if err != nil {
		retErr = fmt.Errorf("could not read " + confFile + ": " + err.Error())
		return
	}

	err = yaml.Unmarshal(confBuf, config)
	if err != nil {
		retErr = fmt.Errorf("could not read network configuration")
		return
	}
	
	err = yaml.Unmarshal(confBuf, &config.Subj)
	if err != nil {
		retErr = fmt.Errorf("could not read a subject")
		return
	}

	config.Subj.Organization = append(config.Subj.Organization, org)

	if config.NetName == "" {
		config.NetName = DockerNetPrefix+org
	}

	return
}
