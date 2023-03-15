/*
Copyright Hitachi, Ltd. 2023 All Rights Reserved.

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

package couchcli

import (
	"net/http"
	"encoding/json"
	"fmt"
	"io"
	"bytes"
)

const (
	DefaultURL = "http://couchdb:5984"
)

type CouchDBClient struct{
	urlBase string
	client *http.Client
}

func New(urlBase string) (cli *CouchDBClient) {
	cli = &CouchDBClient{
		client: &http.Client{},
	}

	cli.urlBase = urlBase
	if cli.urlBase == "" {
		cli.urlBase = DefaultURL
	}
	
	return // success
}

func (cli *CouchDBClient) requestWithMethod(method, path string, reqData, rspData any) (retErr error) {
	var reqRaw []byte
	var err error
	
	if reqData != nil {
		reqRaw, err = json.Marshal(reqData)
		if err != nil {
			retErr = fmt.Errorf("failed to marshal a request data: %s", err)
			return
		}
	}

	req, err := http.NewRequest(method, cli.urlBase + path, bytes.NewReader(reqRaw))
	if err != nil {
		retErr = fmt.Errorf("failed to create a request: %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	
	rsp, err := cli.client.Do(req)
	if err != nil {
		retErr = fmt.Errorf("failed to request to couchdb: %s", err)
		return
	}

	if rsp.Body == nil {
		retErr = fmt.Errorf("failed to get a body")
		return
	}
	defer func() {
		err := rsp.Body.Close()
		if err != nil {
			retErr2 := fmt.Errorf("failed to close the body: %s", err)
			if retErr != nil {
				retErr = fmt.Errorf("%s\n%s", retErr, retErr2)
				return
			}
			retErr = retErr2
		}
	}()

	bodyRaw, err := io.ReadAll(rsp.Body)
	if err != nil {
		retErr = fmt.Errorf("could not read a body: %s", err)
		return
	}

	if rspData != nil {
		err = json.Unmarshal(bodyRaw, rspData)
		if err != nil {
			retErr = fmt.Errorf("failed to unmarshal a body: %s", err)
			return
		}
	}

	return // success
}

func (cli *CouchDBClient) Get(path string, rspData any) (error) {
	return cli.requestWithMethod(http.MethodGet, path, nil, rspData)
}
