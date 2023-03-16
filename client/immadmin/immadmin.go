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

package immadmin

import (
	"time"
	"errors"
	
	"immclient"
	"immcommon"
)

const (
	FCreateRsyslogEnv = "createRsyslogEnv"
	FListRsyslogEnv = "listRsyslogEnv"
	FSetStorageGrpPerm = "setStorageGrpPerm"
	FGetStorageGrpPerm = "getStorageGrpPerm"
	FListKeyInStorageGrp = "listKeyInStorageGrp"
	
	ROLE_Prefix = "imm.Role."
	ROLE_RsyslogEnvAdmin = "RsyslogEnvAdmin"
	ROLE_RsyslogUser = "RsyslogUser"

	AccessPermAll = "0666" // All users can read and write data.
	AccessPermGrpMember = "0660" // This permission allows only members of this storage group to read and write data.
)

type CreateRsyslogEnvReq struct{
	StorageGrp string
	LoggingCondition string
	LoggingKey string
	Priv []byte
	Cert []byte
}

type ListRsyslogEnvReply struct{
	Usernames []string
}

type SetStorageGrpPermReq struct{
	AccessPermission string
}

type GetStorageGrpPermReply struct{
	AccessPermission string	
}

type ListKeyInStorageGrpReply struct{
	Keys []string
}

func createTmpUser(id *immclient.UserID, url string, req *immclient.RegistrationRequest) (tmpID *immclient.UserID, retErr error) {
	_, err := id.Register(req, url)
	if err != nil {
		retErr = errors.New("failed to register a temporary user with the specified role or priviledge: " + err.Error())
		return
	}

	tmpID, err = immclient.EnrollUser(req.Name, 5*time.Minute, req.Secret, url)
	if err != nil {
		id.RemoveIdentity(url, req.Name)
		retErr = errors.New("failed to enroll a temporary user with th specified role or priviledge: " + err.Error())
		return
	}

	return // success	
}

func CreateTemporaryUserWithRole(id *immclient.UserID, url, role string) (tmpUserID *immclient.UserID, retErr error) {
	tmpUserRegReq := &immclient.RegistrationRequest{
		Name: role + immclient.RandStr(8),
		Secret: immclient.RandStr(16),
		MaxEnrollments: 1,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: ROLE_Prefix+role, Value: "true", ECert: true},
		},
		Type: "temporary",
	}

	tmpUserID, retErr = createTmpUser(id, url, tmpUserRegReq)
	return
}


func CreateTmpUserWithGrpPrivilege(id *immclient.UserID, url, storageGrp string) (tmpUserID *immclient.UserID, retErr error) {
	tmpUserRegReq := &immclient.RegistrationRequest{
		Name: id.Name + storageGrp + immclient.RandStr(8),
		Secret: immclient.RandStr(16),
		MaxEnrollments: 1,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: immclient.StorageGrpAttr, Value: storageGrp, ECert: true},
		},
		Type: "client",
	}

	tmpUserID, retErr = createTmpUser(id, url, tmpUserRegReq)
	return
}

func createRsyslogEnvAdminID(id *immclient.UserID, url string) (rsyslogEnvAdmin *immclient.UserID, retErr error) {
	return CreateTemporaryUserWithRole(id, url, ROLE_RsyslogEnvAdmin)
}

func CreateRsyslogEnv(id *immclient.UserID, url, storageGrp, rsyslogUsername, condition, recordKey string) (retErr error) {
	adminID, err := createRsyslogEnvAdminID(id, url)
	if err != nil {
		retErr = err
		return
	}
	defer func() {
		id.RemoveIdentity(url, adminID.Name)
	}()
	
	regReq := &immclient.RegistrationRequest{
		Name: rsyslogUsername,
		Secret: immclient.RandStr(16),
		MaxEnrollments: 2,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: ROLE_Prefix+ROLE_RsyslogUser, Value: "true", ECert: true},
			immclient.Attribute{Name: immclient.StorageGrpAttr, Value: storageGrp, ECert: true},
		},
		Type: "client",
	}
	
	_, err = id.Register(regReq, url)
	if err != nil {
		retErr = errors.New("failed to register a user for rsyslog: " + err.Error())
		return
	}
	defer func() {
		if retErr != nil {
			id.RemoveIdentity(url, regReq.Name)
		}
	}()

	rsyslogUser, err := immclient.EnrollUser(regReq.Name, immclient.TenYears, regReq.Secret, url)
	if err != nil {
		retErr = errors.New("failed to enroll a user for rsyslog: " + err.Error())
		return
	}

	req := &CreateRsyslogEnvReq{
		StorageGrp: storageGrp,
		Priv: rsyslogUser.Priv,
		Cert: rsyslogUser.Cert,
		LoggingCondition: condition,
		LoggingKey: recordKey,
	}
	_, retErr = immcommon.ImmstFunc(adminID, url, immcommon.MCommon, FCreateRsyslogEnv, req, nil)
	return
}

func ListRsyslogEnv(id *immclient.UserID, url string) (envList []string, retErr error) {
	adminID, err := createRsyslogEnvAdminID(id, url)
	if err != nil {
		retErr = err
		return
	}
	defer func() {
		id.RemoveIdentity(url, adminID.Name)
	}()

	reply := &ListRsyslogEnvReply{}
	_, retErr = immcommon.ImmstFunc(adminID, url, immcommon.MCommon, FListRsyslogEnv, nil, reply)
	if retErr != nil {
		return
	}

	envList = reply.Usernames
	return
}

func SetStorageGrpPerm(id *immclient.UserID, url, perm string) (retErr error) {
	req := &SetStorageGrpPermReq{
		AccessPermission: perm,
	}
	_, retErr = immcommon.ImmstFunc(id, url, immcommon.MCommon, FSetStorageGrpPerm, req, nil)
	return
}

func GetStorageGrpPerm(id *immclient.UserID, url string) (perm string, retErr error) {
	reply := &GetStorageGrpPermReply{}
	_, retErr = immcommon.ImmstFunc(id, url, immcommon.MCommon, FGetStorageGrpPerm, nil, reply)
	if retErr != nil {
		return
	}
	
	perm = reply.AccessPermission
	return // success
}

func ListKeyInStorageGrp(id *immclient.UserID, url string) (keys []string, retErr error) {
	reply := &ListKeyInStorageGrpReply{}
	_, retErr = immcommon.ImmstFunc(id, url, immcommon.MCommon, FListKeyInStorageGrp, nil, reply)
	if retErr != nil {
		return
	}
	
	keys = reply.Keys
	return // success
}
