package immutil

import (
	"fmt"
	"io/ioutil"
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

	CaImg = "hyperledger/fabric-ca:1.4.6"
	OrdererImg = "hyperledger/fabric-orderer:1.4.6"
	CouchDBImg = "hyperledger/fabric-couchdb:amd64-0.4.20"
	PeerImg = "hyperledger/fabric-peer:1.4.6"
	DockerImg = "library/docker:19.03.9-dind"
	
	ImmHttpdImg = "library/httpd:2.4.46"

	ImmSrvImg = "library/ubuntu:20.10"
	EnvoyImg = "envoyproxy/envoy:v1.14.1"

	ChainCcenvImg = "hyperledger/fabric-ccenv:1.4.7"
	ChainBaseOsImg = "hyperledger/fabric-baseos:amd64-0.4.18"

	configYaml = "config.yaml"

	K8sSubDomain = "imm"
	K8sLocalSvc = ".default.svc.cluster.local"

	DockerNetPrefix = "net_hfl_"

	defaultCertCountry = `["JP"]`
	defaultCertLocality = `["Tokyo"]`
	defaultCertProvince = `["Shinagawa"]`

	workVolume = "work-vol"
)

type ImmConfig struct {
	Subj pkix.Name
	NetName string `yaml:"DockerNetname"`
	ExternalIPs []string `yaml:"ExternalIPs"`
	Registry string `yaml:"Registry"`
	RegistryAuth string `yaml:"RegsitryAuth"`
}

func ReadConfigWithDefaultFile(org string) (config *ImmConfig, retErr error) {
	return ReadConfigWithFile(org, VolBaseDir + "/" + org + "/" + configYaml)
}

func ReadConfigWithFile(org, confFile string) (config *ImmConfig, retErr error) {
	confBuf, err := ioutil.ReadFile(confFile)
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
