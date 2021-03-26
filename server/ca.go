/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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
	"encoding/json"
	"encoding/base64"	
	"crypto/tls"
	"bytes"
	"fmt"
	"net/http"
	"immclient"
	"immop"
)

type caClient struct {
	urlBase string
	client *http.Client
}

func newCAClient(urlBase string) (*caClient){
	client := immclient.GetDefaultHttpClient()
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	return &caClient{
		urlBase: urlBase,
		client: client,
	}
}

func (cli *caClient) registerCAUser(adminID *immclient.UserID, req *immclient.RegistrationRequest) (secret string, retErr error) {
	uri := "/register"
	url := cli.urlBase + uri
	
	reqData, err := json.Marshal(req)
	if err != nil {
		retErr = fmt.Errorf("failed to create a request for registration: %s", err)
		return
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqData) )
	if err != nil {
		retErr = fmt.Errorf("failed to create a POST request for registration: %s", err)
		return
	}

	retErr = adminID.AddToken(reqData, httpReq, uri)
	if retErr != nil {
		return
	}

	regRsp := &immclient.RegistrationResponse{}
	rsp := &immclient.Response{Result: regRsp}
	retErr = immclient.SendReqCA(httpReq, rsp)
	if retErr != nil {
		return
	}

	secret = regRsp.Secret
	return // success
}

func (cli *caClient) enrollCAUser(username string, req *immop.EnrollUserRequest) (cert []byte, retErr error) {
	uri := "/enroll"
	csrUrl := cli.urlBase + uri
	
	certSignReq, err := http.NewRequest("POST", csrUrl, bytes.NewReader(req.EnrollReq))
	if err != nil {
		retErr = fmt.Errorf("failed to create a CA request: %s", err)
		return
	}
	certSignReq.SetBasicAuth(username, req.Secret)
	
	cert, retErr = cli.sendCSR(certSignReq)
	return
}

func (cli *caClient) reenrollCAUser(id *immclient.UserID, req *immop.EnrollUserRequest) (cert []byte, retErr error) {
	uri := "/reenroll"
	url := cli.urlBase + uri
	certSignReq, err := http.NewRequest("POST", url, bytes.NewReader(req.EnrollReq) )
	if err != nil {
		retErr = fmt.Errorf("failed to create a request: %s", err)
		return
	}

	retErr = id.AddToken(req.EnrollReq, certSignReq, uri)
	if retErr != nil {
		return
	}

	cert, retErr = cli.sendCSR(certSignReq)
	return
}

func (cli *caClient) sendCSR(csr *http.Request) (cert []byte, retErr error) {
	csrRsp := &immclient.EnrollmentResponseNet{}
	caRsp := &immclient.Response{Result: csrRsp}
	retErr = immclient.SendReqCA(csr, caRsp)
	if retErr != nil {
		return
	}
	
	cert, err := base64.StdEncoding.DecodeString(csrRsp.Cert)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate format: %s", err)
		return
	}

	return // success
}

func (cli *caClient) registerAndEnrollUser(adminID *immclient.UserID, username string, req *immop.EnrollUserRequest) (cert []byte, retErr error) {
	caSecret := immclient.RandStr(8)
	req.Secret = caSecret

	_, err := adminID.GetIdentity(cli.urlBase, username)
	if err == nil {
		// There is a record for this user in CA DB
		adminID.ChangeSecret(cli.urlBase, username, caSecret)
		return cli.enrollCAUser(username, req)
	}
	
	// register an LDAP user
	regReq := &immclient.RegistrationRequest{
		Name: username,
		Type: "client",
		MaxEnrollments: -1, //unlimit
		Secret: caSecret,	
	}
	
	_, err = cli.registerCAUser(adminID, regReq)
	if err != nil {
		return nil, err
	}
	
	// enroll a user
	return cli.enrollCAUser(username, req)
}
