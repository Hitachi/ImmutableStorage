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
	"io"
	"bytes"
	"strings"
	"strconv"
	"encoding/json"
)

type RegClient struct {
	url string
	token string // token such as Azure AD access token
}

const (
	acrSuffix = "azurecr.io"
)

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
	addr += ":" + strconv.Itoa(int(service.Spec.Ports[0].NodePort))
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

func NewRegClient(url, token string) (cli *RegClient, retErr error) {
	cli = &RegClient{}
	cli.url = url
	cli.token = token

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

func (cli *RegClient) sendReq(req *http.Request) (rsp *http.Response, rspBody []byte, retErr error) {
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		retErr = fmt.Errorf("failed to request: " + err.Error())
		return
	}
	
	if rsp.Body == nil {
		//retErr = fmt.Errorf("responded body is nil")
		return
	}
	defer rsp.Body.Close()

	rspBody, err = io.ReadAll(rsp.Body)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	return
}

func (cli *RegClient) sendReqWithAuth(req *http.Request, expectedStatus int) (rsp *http.Response, rspBody []byte, retErr error) {
	rsp, rspBody, retErr = cli.sendReq(req)
	if retErr != nil {
		return
	}
	
	if rsp.StatusCode == expectedStatus {
		return // success
	}
	
	if rsp.StatusCode != http.StatusUnauthorized {
		retErr = fmt.Errorf("got an error: status=%s", rsp.Status)
		return // error
	}
	
	accessToken, scheme, err := cli.getAccessToken(rsp.Header.Get("WWW-Authenticate"), "")
	if err != nil {
		retErr = err
		return
	}
	token := scheme + " " + accessToken
	req.Header.Set("Authorization", token)

	rsp, rspBody, retErr = cli.sendReq(req)
	if retErr != nil {
		return
	}

	if rsp.StatusCode == expectedStatus {
		return // success
	}

	retErr = fmt.Errorf("got an error: status=%s", rsp.Status)
	return // failure
}

func (cli *RegClient) getAccessToken(wwwAuth, expectScope string) (accessToken, scheme string, retErr error) {
	// authenticate
	if cli.token == "" {
		retErr = fmt.Errorf("Token is not specified")
		return // error
	}

	if wwwAuth == "" {
		retErr = fmt.Errorf("failed to get WWW-Authenticate")
		return
	}
		
	paramsStr := strings.TrimPrefix(wwwAuth, "Bearer ")
	if paramsStr == wwwAuth {
		paramsStr = strings.TrimPrefix(wwwAuth, "Basic ")
		if paramsStr != wwwAuth {
			scheme = "Basic"
			accessToken = cli.token
			return
		}
		
		retErr = fmt.Errorf("unsupported scheme")
		return
	}

	// Bearer
	scheme = "Bearer"
	paramsStr = strings.ReplaceAll(paramsStr, `"`, "")
	params := strings.Split(paramsStr, ",")
	tokenURL := ""
	service := ""
	scope := ""
	for _, param := range params {
		realm := strings.TrimPrefix(param, `realm=`)
		if realm != param {
			tokenURL = realm
		}
		if strings.HasPrefix(param, "service=") {
			service = param
		}
		if strings.HasPrefix(param, "scope=") {
			scope = param
		}
	}

	if !strings.HasSuffix(tokenURL, acrSuffix + "/oauth2/token") {
		retErr = fmt.Errorf("Unknown realm: %s", tokenURL)
		return
	}

	exchangeURL := strings.Replace(tokenURL, "/oauth2/token", "/oauth2/exchange", 1)
	exchangeParams := "grant_type=access_token&" + service + "&access_token=" + cli.token

	req, err := http.NewRequest("POST", exchangeURL, bytes.NewReader([]byte(exchangeParams)))
	if err != nil {
		retErr = fmt.Errorf("failed to create a POST reqeust: %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rsp, rspBody, err := cli.sendReq(req)

	if rsp.StatusCode != http.StatusOK {
		retErr = fmt.Errorf("failed to get a refresh token: status=%s", rsp.Status)
		return
	}

	rspData := &struct{REFRESH_TOKEN string}{}
	err = json.Unmarshal(rspBody, rspData)
	if err != nil {
		retErr = fmt.Errorf("unexpected refresh token: %s", err)
		return
	}
	refreshToken := rspData.REFRESH_TOKEN

	getTokenParams := "grant_type=refresh_token&" + service
	
	if scope == "" {
		scope = "scope=registry::"
	}
	if expectScope != "" {
		scope = expectScope
	}
	getTokenParams += "&" + scope
	getTokenParams += "&refresh_token=" + refreshToken
	req, err = http.NewRequest("POST", tokenURL, bytes.NewReader([]byte(getTokenParams)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rsp, rspBody, err = cli.sendReq(req)

	if rsp.StatusCode != http.StatusOK {
		retErr = fmt.Errorf("failed to get an access token: status=%s", rsp.Status)
		return
	}

	tokenData := &struct{ACCESS_TOKEN string}{}
	err = json.Unmarshal(rspBody, tokenData)
	if err != nil {
		retErr = fmt.Errorf("unexpected access token: %s", err)
		return
	}

	accessToken = tokenData.ACCESS_TOKEN
	return // success
}

func (cli *RegClient) GetRegistryToken() (token string, retErr error) {
	url := cli.url + "/v2/"
	req, err :=  http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request: " + err.Error())
		return
	}
	
	rsp, _, retErr := cli.sendReq(req)
	if retErr != nil {
		return
	}

	if rsp.StatusCode != http.StatusUnauthorized {
		retErr = fmt.Errorf("got an error: status=%s", rsp.Status)
		return // error
	}

	accessToken, scheme, err := cli.getAccessToken(rsp.Header.Get("WWW-Authenticate"), "scope=repository:*:pull,push")
	if err != nil {
		retErr = err
		return
	}

	if scheme != "Bearer" {
		retErr = fmt.Errorf("unsupported scheme: %s", scheme)
		return
	}

	token = accessToken
	return // success
}

func (cli *RegClient) GetBase() (retErr error) {
	url := cli.url + "/v2/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request: " + err.Error())
		return
	}

	_, _, retErr = cli.sendReqWithAuth(req, http.StatusOK)
	return
}

func (cli *RegClient) ListRepositoriesInReg() (repo []string, retErr error) {
	url := cli.url + "/v2/_catalog"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for listing repositories: "  + err.Error())
		return
	}

	_, rspBody, err := cli.sendReqWithAuth(req, http.StatusOK)
	if err != nil {
		retErr = fmt.Errorf("failed to list repositories: %s", err)
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

	manifestFormats := []string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}

	req.Header.Set("Accept", manifestFormats[0]+","+manifestFormats[1])
	rsp, _, err := cli.sendReqWithAuth(req, http.StatusOK)
	if err != nil {
		retErr = fmt.Errorf("The specified image does not exist in the registry: %s", err)
		return
	}
	
	contentType := rsp.Header.Get("Content-Type")
	if contentType == manifestFormats[0] ||  contentType == manifestFormats[1] {
		digest = rsp.Header.Get("Docker-Content-Digest")
		return // success
	}

	retErr = fmt.Errorf("unsupported manifest format")
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
		retErr = fmt.Errorf("failed to create a request deleting an image: " + err.Error() )
		return
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	_, _, err = cli.sendReqWithAuth(req, http.StatusAccepted)
	if err != nil {	
		retErr = fmt.Errorf("failed to delete an image in the registry: %s", err)
	}
	return
}

func (cli *RegClient) ListTagsInReg(repoName string) (tags []string, retErr error) {
	url := cli.url + "/v2/" + repoName + "/tags/list"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for listing tags: "  + err.Error())
		return
	}

	_, rspBody, err := cli.sendReqWithAuth(req, http.StatusOK)
	if err != nil {
		retErr = fmt.Errorf("failed to list tags: " + err.Error())
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
