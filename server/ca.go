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
	"encoding/base64"	
	"crypto/tls"
	"bytes"
	"fmt"
	"time"
	"io"
	"net/http"
	"immclient"
	"immop"
)


type caClient struct {
	urlBase string
	client *http.Client
}

func newCAClient(urlBase string) (*caClient){
	client := &http.Client{}
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

func (cli *caClient) sendReqCA(req *http.Request) (rsp []byte, retErr error){
	resp, err := cli.client.Do(req)
	if err != nil {
		retErr = fmt.Errorf("failed to request: " + err.Error())
		return
	}
	if resp.Body == nil {
		retErr = fmt.Errorf("responded body is nil")
		return
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			print("log: failed to close the body: " + err.Error() + "\n")
		}
	}()
	
	rsp, err = io.ReadAll(resp.Body)
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}
	
	return // success
}

func (cli *caClient) registerCAUser(adminID *immclient.UserID, req *immclient.RegistrationRequest) (secret string, retErr error) {
	regRsp := &immclient.RegistrationResponse{}
	reqCA := &immclient.ReqCAParam{
		Func: "Register",
		URLBase: cli.urlBase,
		URI: "/register",
		Method: "POST",
		Param: req,
		Result: regRsp,
	}
	
	err := adminID.SendReqCA(reqCA)
	if err != nil {
		retErr = fmt.Errorf("failed to register a user: %s", err)
		return
	}

	secret = regRsp.Secret
	return // success
}

func (cli *caClient) enrollCAUser(username, secret string, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	csrRsp := &immclient.EnrollmentResponseNet{}
	reqCA := &immclient.ReqCAParam{
		Func: "Enroll",
		URLBase: cli.urlBase,
		URI: "/enroll",
		Method: "POST",
		Param: req,
		Result: csrRsp,
	}

	id := immclient.UserID{Name: username, Priv: []byte(secret), Client: cli}
	err := id.SendReqCA(reqCA)
	if err != nil {
		retErr = fmt.Errorf("failed to enroll a user: %s", err)
		return
	}
	
	cert, err = base64.StdEncoding.DecodeString(csrRsp.Cert)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate format: %s", err)
		return
	}
	return
}

func (cli *caClient) reenrollCAUser(id *immclient.UserID, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	csrRsp := &immclient.EnrollmentResponseNet{}
	reqCA := &immclient.ReqCAParam{
		Func: "Reenroll",
		URLBase: cli.urlBase,
		URI: "/reenroll",
		Method: "POST",
		Param: req,
		Result: csrRsp,
	}
	
	err := id.SendReqCA(reqCA)
	if err != nil {
		retErr = fmt.Errorf("failed to reenroll a user: %s", err)
		return
	}
	
	cert, err = base64.StdEncoding.DecodeString(csrRsp.Cert)
	if err != nil {
		retErr = fmt.Errorf("unexpected certificate format: %s", err)
		return
	}
	return
}

func (cli *caClient) registerAndEnrollUser(adminID *immclient.UserID, username string, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	caSecret := immclient.RandStr(8)

	_, err := adminID.GetIdentity(cli.urlBase, username)
	if err == nil {
		// There is a record for this user in CA DB
		adminID.ChangeSecret(cli.urlBase, username, caSecret)
		return cli.enrollCAUser(username, caSecret, req)
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
	return cli.enrollCAUser(username, caSecret, req)
}

func (cli *caClient) addAffiliation(caRegID *immclient.UserID, affiliation string) (error) {
	affL, err := caRegID.GetAllAffiliations(cli.urlBase)
	if err != nil {
		return err
	}
	
	for _, item := range affL.Affiliations {
		if item.Name == affiliation {
			return nil // The specifed affiliation already exists.
		}
	}

	return caRegID.AddAffiliation(cli.urlBase, affiliation)
}

func (cli *caClient) registerAndEnrollAdmin(caRegID *immclient.UserID, regReq *immclient.RegistrationRequest, roleDurationYear time.Duration) ([]byte, error) {
	// add an affilication
	err := cli.addAffiliation(caRegID, regReq.Affiliation)
	if err != nil {
		return nil, err
	}

	// register a user
	secret, err := cli.registerCAUser(caRegID, regReq)
	if err != nil {
		return nil, err
	}

	// pre-enrollment
	_, csrPem, err := immclient.CreateCSR(regReq.Name)
	if err != nil {
		return nil, err
	}

	nowT := time.Now().UTC()
	preenrollReq := &immclient.EnrollmentRequestNet{
		SignRequest: immclient.SignRequest{
			Request: string(csrPem),
			NotBefore: nowT,
			NotAfter: nowT.Add(roleDurationYear*365*24*time.Hour).UTC(),
		},
	}

	return cli.enrollCAUser(regReq.Name, secret, preenrollReq)
}

var caOP = map[string] struct{Method string}{
	"GetAllIdentities": {Method: "GET",},
	"GetAllAffiliations": {Method: "GET",},
	"GetAffiliation": {Method: "GET",},
	"AddAffiliation": {Method: "POST", },
	"RemoveAffiliation": {Method: "DELETE",},
	"Register": {Method: "POST",},
	"GetIdentity": {Method: "GET",},
	"RemoveIdentity": {Method: "DELETE",},
	"RevokeIdentity": {Method: "POST",},
	"Enroll": {Method: "POST",},
	"Reenroll": {Method: "POST", },
	"ModifyIdentity": {Method: "PUT",},
}

func (cli *caClient) RequestCA(req *immop.CommCARequest) (rsp []byte, retErr error) {
	op, ok := caOP[req.Func]
	if !ok {
		return nil, fmt.Errorf("unknown function")
	}

	reqCA, err := http.NewRequest(op.Method, cli.urlBase+req.URI, bytes.NewReader(req.Param) )
	if err != nil {
		return nil, fmt.Errorf("failed to create a request")
	}
	reqCA.Header.Set("authorization", req.Token)

	return cli.sendReqCA(reqCA)	
}
