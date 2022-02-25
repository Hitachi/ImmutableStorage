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

package cacli

import (
	"immclient"
	"immop"

	"bytes"
	"fmt"
	"time"
	"io"
	"encoding/base64"
	"crypto/tls"
	"net/http"
)

const (
	DefaultPort = ":7054"
)

type CAClient struct {
	UrlBase string
	client *http.Client
}

func NewCAClient(urlBase string) (*CAClient){
	client := &http.Client{}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	return &CAClient{
		UrlBase: urlBase,
		client: client,
	}
}

func (cli *CAClient) sendReqCA(req *http.Request) (rsp []byte, retErr error){
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

func (cli *CAClient) RegisterCAUser(adminID *immclient.UserID, req *immclient.RegistrationRequest) (secret string, retErr error) {
	regRsp := &immclient.RegistrationResponse{}
	reqCA := &immclient.ReqCAParam{
		Func: "Register",
		URLBase: cli.UrlBase,
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

func (cli *CAClient) EnrollCAUser(username, secret string, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	csrRsp := &immclient.EnrollmentResponseNet{}
	reqCA := &immclient.ReqCAParam{
		Func: "Enroll",
		URLBase: cli.UrlBase,
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

func (cli *CAClient) ReenrollCAUser(id *immclient.UserID, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	csrRsp := &immclient.EnrollmentResponseNet{}
	reqCA := &immclient.ReqCAParam{
		Func: "Reenroll",
		URLBase: cli.UrlBase,
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

func (cli *CAClient) RegisterAndEnrollUser(adminID *immclient.UserID, userType, username string, userAttrs *[]immclient.Attribute, req *immclient.EnrollmentRequestNet) (cert []byte, retErr error) {
	caSecret := immclient.RandStr(8)

	_, err := adminID.GetIdentity(cli.UrlBase, username)
	if err == nil {
		// There is a record for this user in CA DB
		adminID.ChangeSecret(cli.UrlBase, username, caSecret)
		return cli.EnrollCAUser(username, caSecret, req)
	}
	
	// register a user
	regReq := &immclient.RegistrationRequest{
		Name: username,
		Attributes: *userAttrs,
		Type: userType,
		MaxEnrollments: -1, //unlimit
		Secret: caSecret,	
	}
	
	_, err = cli.RegisterCAUser(adminID, regReq)
	if err != nil {
		return nil, err
	}
	
	// enroll a user
	return cli.EnrollCAUser(username, caSecret, req)
}

func (cli *CAClient) RegisterAndEnrollAdmin(caRegID *immclient.UserID, regReq *immclient.RegistrationRequest, roleDurationYear time.Duration) ([]byte, error) {
	// add an affilication
	err := caRegID.CheckAndAddAffiliation(cli.UrlBase, regReq.Affiliation)
	if err != nil {
		return nil, err
	}

	// register a user
	secret, err := cli.RegisterCAUser(caRegID, regReq)
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

	return cli.EnrollCAUser(regReq.Name, secret, preenrollReq)
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

func (cli *CAClient) RequestCA(req *immop.CommCARequest) (rsp []byte, retErr error) {
	op, ok := caOP[req.Func]
	if !ok {
		return nil, fmt.Errorf("unknown function")
	}

	reqCA, err := http.NewRequest(op.Method, cli.UrlBase+req.URI, bytes.NewReader(req.Param) )
	if err != nil {
		return nil, fmt.Errorf("failed to create a request")
	}
	reqCA.Header.Set("authorization", req.Token)

	return cli.sendReqCA(reqCA)	
}
