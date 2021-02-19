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
	"net"
	"net/http"
	"fmt"
	"os"
	"strings"
	"strconv"
	"io/ioutil"
	"encoding/json"
)

type RegClient struct {
	url string
}

func GetLocalRegistryAddr() (addr string, retErr error) {
	service, err := K8sGetRegistryService()
	if err != nil {
		gw, err := getGW()
		if err != nil {
			retErr = fmt.Errorf("failed to get gateway: %s\n", err)
			return
		}
		addr = gw + ":32000"
		return
	}
	
	if service.Spec.Ports == nil {
		retErr = fmt.Errorf("unexpected registry service")
		return
	}

	if IsInKube() {
		addr = "registry.container-registry.svc.cluster.local:"
		addr += strconv.Itoa(int(service.Spec.Ports[0].Port))
		return
	}

	addr = "localhost"
	addr += strconv.Itoa(int(service.Spec.Ports[0].NodePort))
	return
}

func GetPullRegistryAddr(org string) (addr string, retErr error) {
	if IsInKube() {
		config, _, err := ReadOrgConfig(org)
		if err == nil && config.Registry != "" {
			addr = config.Registry
			return
		}
	}

	service, retErr := K8sGetRegistryService()
	if retErr != nil {
		return
	}

	if service.Spec.Ports == nil {
		retErr = fmt.Errorf("unexpected registry service")
		return
	}

	addr = "localhost"
	addr += ":" + strconv.Itoa(int(service.Spec.Ports[0].NodePort))
	return
}

func ParseCredential(cred string) (username, secret string) {
	attr := strings.SplitN(cred, ":", 2)
	if len(attr) == 1 {
		username = ""
		secret = attr[0]
		return
	}

	username = attr[0]
	secret = attr[1]
	return
}

func NewRegClient(url string) (cli *RegClient, retErr error) {
	cli = &RegClient{}
	cli.url = url

	retErr = cli.GetBase()
	if retErr != nil {
		cli = nil
	}
	return
}

func getGW() (gwAddr string, retErr error) {
	hostname, err := os.Hostname()
	if err != nil {
		retErr = fmt.Errorf("could not get my hostname: %s", err)
		return
	}
	
	myIP, err := net.LookupIP(hostname)
	if err != nil {
		retErr = fmt.Errorf("failed to lookup IP: %s", err)
		return
	}
	
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		retErr = fmt.Errorf("failed in InterfaceAddrs: %s", err)
		return
	}

	for _, addr := range addrs {
		//fmt.Printf("net:%s addr:%s\n", addr.Network(), addr.String())
		ipAddr, netAddr, err := net.ParseCIDR(addr.String())
		if err != nil {
			// failed to parse CIDR
			continue
		}

		if ipAddr.Equal(myIP[0]) {
			gwAddr = strings.TrimSuffix(netAddr.IP.String(), ".0")
			if gwAddr == netAddr.IP.String() {
				gwAddr = ""
				retErr = fmt.Errorf("unexpected IP address: %s", netAddr.IP.String())
				return
			}
			
			gwAddr += ".1"
			return
		}
	}

	retErr = fmt.Errorf("could not get gateway")
	return
}

func (regCli *RegClient) sendReq(req *http.Request) (rsp *http.Response, rspBody []byte, retErr error) {
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		retErr = fmt.Errorf("failed to request: " + err.Error())
		return
	}
	
	if rsp.Body == nil {
		retErr = fmt.Errorf("responded body is nil")
		return
	}
	defer rsp.Body.Close()

	rspBody, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	return
}

func (cli *RegClient) GetBase() (retErr error) {
	url := cli.url + "/v2/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request: " + err.Error())
		return
	}

	rsp, _, retErr := cli.sendReq(req)
	if retErr != nil {
		return
	}

	if rsp.Status == "200 OK" {
		return // success
	}

	retErr = fmt.Errorf("get error: status=%s", rsp.Status)
	return // success
}

func (cli *RegClient) ListRepositoriesInReg() (repo []string, retErr error) {
	url := cli.url + "/v2/_catalog"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for listing repositories: "  + err.Error())
		return
	}

	_, rspBody, err := cli.sendReq(req)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	rspData := &struct{ Repositories []string }{}
	err = json.Unmarshal(rspBody, rspData)
	if err != nil {
		retErr = fmt.Errorf("failed to unmarshal the body: " + err.Error())
		return
	}

	repo = rspData.Repositories
	return // success
}

func (cli *RegClient) GetDigest(name, tag string) (digest string, retErr error){
	url := cli.url + "/v2/" + name + "/manifests/" + tag
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for getting deigest: " + err.Error())
		return
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.list.v2+json")

	rsp, _, err := cli.sendReq(req)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	digest = rsp.Header.Get("Docker-Content-Digest")
	return
}

func (cli *RegClient) DeleteImgInReg(name, tag string) (retErr error) {
	digest, retErr := cli.GetDigest(name, tag)
	if retErr != nil {
		return
	}
	
	url := cli.url + "/v2/" + name + "/manifests/" + digest
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to a request for deleting image: " + err.Error() )
		return
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		retErr = fmt.Errorf("failed to request: " + err.Error())
		return
	}
	if rsp.Body != nil {
		defer rsp.Body.Close()
	}

	if rsp.Status == "202 Accepted" {
		return // success
	}
	
	retErr = fmt.Errorf("got error: status=%s", rsp.Status)
	return
}

func (cli *RegClient) ListTagsInReg(repoName string) (tags []string, retErr error) {
	url := cli.url + "/v2/" + repoName + "/tags/list"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for listing tags: "  + err.Error())
		return
	}

	_, rspBody, err := cli.sendReq(req)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	rspData := &struct{ Name string; Tags []string }{}
	err = json.Unmarshal(rspBody, rspData)
	if err != nil {
		retErr = fmt.Errorf("failed to unmarshal the body: " + err.Error())
		return
	}

	tags = rspData.Tags
	return
}
