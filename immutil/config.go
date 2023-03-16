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
	ImgSrcDir = "/var/lib/ImmutableST/imgsrc"
	
	CAHostname = "ca"
	HttpdHostname = "www"
	ImmsrvHostname = "immsrv"
	EnvoyHostname = "envoy"
	TlsCAHostname = "tlsca"
	OAuthHostname = "oauth"
	ST2WebHostname = "st2web"

	CaImg = "hyperledger/fabric-ca:1.5.0"
	OrdererImg = "hyperledger/fabric-orderer:1.4.12"
	PeerImg = "hyperledger/fabric-peer:1.4.12"
	
	CouchDBImg = "library/couchdb:2.3.1"
	ImmHttpdImg = "library/httpd:2.4.54"
	ImmSrvBaseImg = "library/ubuntu:22.04"
	ImmSrvImg = "immsrv:1.6.0"	
	EnvoyImg = "envoyproxy/envoy:v1.22.0"

	ContRuntimeBaseImg = "library/alpine:3.17"
	ContRuntimeImg = "immplugin:runtime1"
	ImmPluginSrvImg = "immpluginsrv:1.1"
	RsyslogBaseImg = "library/alpine:3.17"
	RsyslogImg = "rsyslog:immst1"
	ImmGRPCProxyImg = "immgrpcproxy:1"
	ImmGRPCProxyBaseImg = "library/alpine:3.17"

	ST2AuthBaseImg = "stackstorm/st2auth:3.8.0"
	ST2AuthImg = "st2auth:immst1"
	
	MongoDBImg = "library/mongo:4.4"
	RabbitMQImg = "library/rabbitmq:3.8"
	RedisImg = "library/redis:6.2"
	ST2ActionRunnerImg = "stackstorm/st2actionrunner:3.8.0"
	ST2APIImg = "stackstorm/st2api:3.8.0"
	ST2StreamImg = "stackstorm/st2stream:3.8.0"
	ST2SchedulerImg = "stackstorm/st2scheduler:3.8.0"
	ST2WorkflowEngineImg = "stackstorm/st2workflowengine:3.8.0"
	ST2GarbageCollectorImg = "stackstorm/st2garbagecollector:3.8.0"
	ST2NotifierImg = "stackstorm/st2notifier:3.8.0"
	ST2RuleEngineImg = "stackstorm/st2rulesengine:3.8.0"
	ST2SensorContainerImg = "stackstorm/st2sensorcontainer:3.8.0"
	ST2TimerEngineImg = "stackstorm/st2timersengine:3.8.0"
	ST2ChatopsImg = "stackstorm/st2chatops:3.8.0"
	ST2WebImg = "stackstorm/st2web:3.8.0"

	configYaml = "config.yaml"

	K8sSubDomain = "imm"
	K8sLocalSvc = ".default.svc.cluster.local"

	DockerNetPrefix = "net_hfl_"

	defaultCertCountry = `["JP"]`
	defaultCertLocality = `["Tokyo"]`
	defaultCertProvince = `["Shinagawa"]`

	workVolume = "work-vol"
	HTTPD_CONFIG_FILE = "/usr/local/apache2/conf/httpd.conf"
	
	EnvGenIngressConf = "IMMS_GENERATE_INGRESS_CONF" // enable, disable, (default=enable)
)

type ImmConfig struct {
	Subj pkix.Name
	NetName string `yaml:"DockerNetname"`
	ExternalIPs []string `yaml:"ExternalIPs"`
	Registry string `yaml:"Registry"`
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

func AddProxyPass(httpdBaseName, path, url string) (retErr error) {
	podName, retErr := K8sWaitPodReadyAndGetPodName("app=httpd", httpdBaseName)
	if retErr != nil {
		retErr = fmt.Errorf("There is no httpd pod in this cluster: %s", retErr)
		return
	}

	commands := [][]string{
		// delete old proxy pass
		{"sed", "-i", "-e", `/ProxyPass "\`+path+`"/d`, HTTPD_CONFIG_FILE},
		// add new proxy pass
		{"sed", "-i", "-e", `$aProxyPass "\`+path+`" "`+url+`"`, HTTPD_CONFIG_FILE},
		// restart httpd
		{"apachectl", "-k", "graceful"},
	}
	for _, cmd := range commands {
		err := K8sExecCmd(podName, HttpdHostname, cmd, nil, os.Stdout, nil)
		if err != nil {
			retErr = err
			return
		}
	}
	
	return // success
}

