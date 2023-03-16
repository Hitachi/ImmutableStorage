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

package st2mng

import (
	"immclient"
	"immadmin"
	"immcommon"
)

const (
	MST2 = "ST2Module"
	FCreateEnv = "CreateEnvironment"
	ROLE_ST2EnvAdmin = "ST2EnvAdmin"
)

type CreateEnvReq struct{
	StorageGrp string 
	RsyslogUser string
}

func createST2EnvAdminID(id *immclient.UserID, url string) (adminID *immclient.UserID, retErr error) {
	return immadmin.CreateTemporaryUserWithRole(id, url, ROLE_ST2EnvAdmin)
}

func CreateEnv(id *immclient.UserID, url, storageGrp, rsyslogUser string) (retErr error) {
	adminID, err := createST2EnvAdminID(id, url)
	if err != nil {
		retErr = err
		return
	}
	defer func() {
		id.RemoveIdentity(url, adminID.Name)
	}()
	
	req := &CreateEnvReq{
		StorageGrp: storageGrp,
		RsyslogUser: rsyslogUser,
	}
	
	_, retErr = immcommon.ImmstFunc(adminID, url, MST2, FCreateEnv, req, nil)
	return
}
