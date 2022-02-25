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
	"crypto/x509"
	"crypto/ecdsa"
	"encoding/json"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"regexp"
	"fmt"
	"time"
	"errors"

	"github.com/golang/protobuf/proto"
	
	"cacli"
	"immutil"
	"immop"
	"immconf"
	"immclient"
	"immsign"
	bcli "ballotcli"
)

const (
	voterRegNameSuffix = "@voter"
	ballotSuffix = ".ballot"
	ballotAuthTypeLDAP = "LDAP.ballot"
	ballotAuthTypeCA = "CA.ballot"
	ballotAuthTypeJPKI = "JPKI.ballot"
	VOTER_STA = "imm.VoterState"
	VOTER_STA_registered = "registered"
	VOTER_STA_voted = "voted"
	AUTH_UserParam = "imm.AuthUserParam"
)

func ballotCreateBox(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	createBoxReq := &bcli.CreateBoxRequest{}
	err := json.Unmarshal(req.Req, createBoxReq)
	if err != nil {
		retErr = fmt.Errorf("unexpected request: " + err.Error())
		return
	}
	
	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_AdminOfficial {
		retErr = fmt.Errorf("authentication error")
		return
	}

	pubKey, err := createBallotBoxAgent(cert)
	if err != nil {
		retErr = fmt.Errorf("failed to create a key-pair for our ballot box: " + err.Error())
		return
	}

	jsonRsp := &bcli.CreateBoxReply{
		BoxPub: pubKey,
	}

	rsp, err = json.Marshal(jsonRsp)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a response: " + err.Error())
		return
	}

	return // success
}

func createBallotBoxAgent(cert *x509.Certificate) (pubKey []byte, retErr error) {
	caName := cert.Issuer.CommonName
	caPriv, caCert, retErr := immutil.K8sGetKeyPair(caName)
	if retErr != nil {
		return
	}

	tmpPriv, tmpCert, retErr := immutil.CreateTemporaryCert(cert, caPriv, caCert)
	if retErr != nil {
		return
	}

	if cert.Issuer.Organization == nil || len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("failed to get an organization name")
		return
	}

	secret := immclient.RandStr(16)
	req := &immclient.RegistrationRequest{
		Name: "ballotbox." + cert.Issuer.Organization[0],
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: bcli.ROLE_Prefix+bcli.ROLE_BallotBoxAgent, Value: "true", ECert: true},
		},
		Type: "client",
		Secret: secret,
		MaxEnrollments: 2,
	}

	caCli := cacli.NewCAClient("https://"+caName+cacli.DefaultPort)
	electionAdmin := &immclient.UserID{Name: "tmpUser", Priv: tmpPriv, Cert: tmpCert, Client: caCli}

	_, retErr = caCli.RegisterCAUser(electionAdmin, req)
	if retErr != nil {
		return
	}

	privPem, csrPem, retErr := immclient.CreateCSR(req.Name)
	if retErr != nil {
		return
	}

	nowT := time.Now().UTC()
	enrollReq := &immclient.EnrollmentRequestNet{
		SignRequest: immclient.SignRequest{
			Request: string(csrPem),
			NotBefore: nowT,
			NotAfter: nowT.Add(1*356*24*time.Hour/* one year */).UTC(),
		},
	}

	certPem, retErr := caCli.EnrollCAUser(req.Name, secret, enrollReq)
	if retErr != nil {
		return
	}

	retErr = immutil.K8sStoreKeyPairOnSecret(privPem, certPem, req.Name)
	if retErr != nil {
		return
	}

	pubKey = certPem
	return //success
}

func getBallotBoxAgent(cert *x509.Certificate) (agentID *immclient.UserID, retErr error) {
	if cert.Issuer.Organization == nil || len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("failed to get an organization name")
		return
	}
	
	agentName := "ballotbox." + cert.Issuer.Organization[0]
	agentPriv, agentCert, err := immutil.K8sGetKeyPair(agentName)
	if err != nil {
		retErr = fmt.Errorf("not found agent for the ballot box")
		return
	}

	caName := cert.Issuer.CommonName
	caCli := cacli.NewCAClient("https://" + caName + cacli.DefaultPort)
	agentID = &immclient.UserID{Name: agentName, Priv: agentPriv, Cert: agentCert, Client: caCli,}
	return // success
}

func ballotSelectVoter(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	selVoterReq := &bcli.SelectVoterRequest{}
	err := json.Unmarshal(req.Req, selVoterReq)

	if err != nil {
		retErr = fmt.Errorf("unexpected request: " + err.Error())
		return
	}

	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_AdminVoterReg {
		retErr = fmt.Errorf("authentication denied")
		return
	}

	switch selVoterReq.AuthType {
	case "CA":
		retErr = registerVoterReg(cert, ballotAuthTypeCA, "", nil)
	case "LDAP":
		retErr = registerVoterRegForLDAP(cert, selVoterReq.AuthParam)
	case "JPKI":
		retErr = registerVoterRegForJPKI(cert, selVoterReq.AuthParam)
	default:
		retErr = fmt.Errorf("unexpected authentication type")
		return
	}

	return
}

func registerVoterReg(cert *x509.Certificate, authType, regNamePrefix string, authParamRaw []byte) (retErr error) {
	hfRegAttrVal := VOTER_STA
	if authType == ballotAuthTypeJPKI {
		hfRegAttrVal += "," + AUTH_UserParam
	}
	
	// register a user to the CA DB	
	regReq := &immclient.RegistrationRequest{
		Name: regNamePrefix + voterRegNameSuffix,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: bcli.ROLE_Prefix+bcli.ROLE_VoterReg, Value: "true", ECert: true},
			immclient.Attribute{Name: AUTH_Param, Value: string(authParamRaw), ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Roles", Value: "voterReg,voter", ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Attributes", Value: hfRegAttrVal, ECert: false},
		},
		Type: "voterReg",
		MaxEnrollments: -1, // unlimit
	}
	if !strings.HasPrefix(regReq.Name, "@") {
		retErr = fmt.Errorf("invalid group name")
		return
	}

	caName := cert.Issuer.CommonName
	caPriv, caCert, retErr := immutil.K8sGetKeyPair(caName)
	if retErr != nil {
		return
	}

	tmpPriv, tmpCert, retErr := immutil.CreateTemporaryCert(cert, caPriv, caCert)
	if retErr != nil {
		return
	}

	caCli := cacli.NewCAClient("https://"+caName+cacli.DefaultPort)
	caRegID := &immclient.UserID{Name: "tmpUser", Priv: tmpPriv, Cert: tmpCert, Client: caCli}
	adminCert, retErr := caCli.RegisterAndEnrollAdmin(caRegID, regReq, 1/*one year*/)
	if retErr != nil {
		return
	}

	retErr = immutil.StoreCertID(adminCert, authType)
	return
}

func registerVoterRegForLDAP(cert *x509.Certificate, authParamRaw []byte) (error) {
	authParam := &bcli.VoterAuthParamLDAP{}
	err := json.Unmarshal(authParamRaw, authParam)
	if err != nil {
		return fmt.Errorf("invalid authentication parameter: %s", err)
	}

	err = PingLDAP(authParam.BindServer)
	if err != nil {
		return err
	}

	if authParam.QueryServer != "" {
		err = PingLDAP(authParam.QueryServer)
		if err != nil {
			return err
		}
	}

	return registerVoterReg(cert, ballotAuthTypeLDAP,  authParam.GroupName, authParamRaw)
}

func getBirthdayFilter(filter string) (filterDate *time.Time, cmpFlag string, retErr error) {
	validCmpFlags := []string{"<",">","<=",">="}
	tmpDate := ""
	validF := false
	for _, cmpFlag = range validCmpFlags {
		tmpDate = strings.TrimSuffix(filter, cmpFlag)
		validF = (tmpDate != filter)
		if validF {
			break // valid
		}
	}
	if !validF {
		retErr = errors.New("invalid compare flag")
		return
	}

	// The specified compare flag is valid.
	// check date format
	filterDate = &time.Time{}
	err := filterDate.UnmarshalText([]byte(tmpDate))
	if err != nil {
		retErr = fmt.Errorf("invaild birthday: %s", err)
	}

	return // success
}

func registerVoterRegForJPKI(cert *x509.Certificate, authParamRaw []byte) (error) {
	authParam := &bcli.VoterAuthParamJPKI{}
	err := json.Unmarshal(authParamRaw, authParam)
	if err != nil {
		return fmt.Errorf("invaild authentication parameter: %s", err)
	}

	_, _ , err = getBirthdayFilter(authParam.BirthdayFilter)
	if err != nil {
		return err
	}

	return registerVoterReg(cert, ballotAuthTypeJPKI, authParam.GroupName, authParamRaw)
}

func ballotGetUserTypeAndAttr() (userType string, attr *[]immclient.Attribute) {
	userType = "voter"
	attr = &[]immclient.Attribute{
		immclient.Attribute{Name: bcli.ROLE_Prefix+bcli.ROLE_Voter, Value: "true", ECert: true},
		immclient.Attribute{Name: VOTER_STA, Value: VOTER_STA_registered, ECert: false},	
	}
	return
}

func ballotGetLDAPAttr(attrs *[]immclient.Attribute) (ldapAttr map[string] string, retErr error) {
	privilegeF := false
	for _, attr := range *attrs {
		switch attr.Name {
		case bcli.ROLE_Prefix+bcli.ROLE_VoterReg:
			privilegeF = (attr.Value == "true")
		case AUTH_Param:
			authParam := &bcli.VoterAuthParamLDAP{}
			err := json.Unmarshal([]byte(attr.Value), authParam)
			if err != nil {
				retErr = fmt.Errorf("authentication error")
				return
			}

			ldapAttr = map[string] string{
				"LDAP.BindServer": authParam.BindServer,
				"LDAP.BindDN": authParam.BindDN,
				"LDAP.QueryServer": authParam.QueryServer,
				"LDAP.BaseDN": authParam.BaseDN,
				"LDAP.Query": authParam.Query,
			}
		}
	}

	if privilegeF {
		return // succes
	}

	retErr = fmt.Errorf("authentication error")
	return
}

func ballotAuthenticateJPKIUser(id *immclient.UserID, userParam *jpkiAuthUserParam) (retErr error) {
	role := id.GetRole()
	if role != bcli.ROLE_VoterReg {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	adminAttr, err := id.GetIdentity("", id.Name)
	if err != nil {
		retErr = fmt.Errorf("failed to get attributes of an administrator")
		return
	}

	var authParam *bcli.VoterAuthParamJPKI
	
	for _, attr := range adminAttr.Attributes {
		if attr.Name == AUTH_Param {
			authParam = &bcli.VoterAuthParamJPKI{}
			err = json.Unmarshal([]byte(attr.Value), authParam)
			if err != nil {
				retErr = fmt.Errorf("failed to unmarshal parameters: " + err.Error())
				return
			}
			break // found
		}
	}
	if authParam == nil {
		retErr = fmt.Errorf("not found authentication parameter")
		return
	}

	matchF, err := regexp.MatchString(authParam.AddressFilter, userParam.PrivacyInfo.Address)
	if !matchF || err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	filterDate, cmpFlag, err := getBirthdayFilter(authParam.BirthdayFilter)
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	bStr := userParam.PrivacyInfo.Birthday
	birthday := bStr[1:5]+"-"+bStr[5:7]+"-"+bStr[7:9]+"T00:00:00+09:00"
	bDay := &time.Time{}
	err = bDay.UnmarshalText([]byte(birthday))
	if err != nil {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	withinDayF := false
	switch cmpFlag {
	case "<": // filterDate (older than) < birthday
		withinDayF = filterDate.Before(*bDay)
	case "<=": // filterDate (older than or equal to) <= birthday
		withinDayF = filterDate.Before(*bDay)
		withinDayF = withinDayF || filterDate.Equal(*bDay)
	case ">": // filterDate (newer than) > birthday
		withinDayF = filterDate.After(*bDay)
	case ">=":
		withinDayF = filterDate.After(*bDay)
		withinDayF = withinDayF || filterDate.Equal(*bDay)
	}
	if !withinDayF {
		retErr = fmt.Errorf("authentication failure")
		return
	}

	return // success
}

func ballotGetPaper(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_Voter && role != bcli.ROLE_ElectionOfficial {
		retErr = fmt.Errorf("authentication error")
		return
	}

	agentID, retErr := getBallotBoxAgent(cert)
	if retErr != nil {
		return
	}
	
	url := "localhost" + port
	storageGrp, err := bcli.GetStorageForBallotBox(agentID, url)
	if err != nil {
		retErr = fmt.Errorf("not found ballot box")
		return
	}

	paper := &bcli.GetPaperReply{}
	paper.RecorderCert, paper.Signature, paper.Message, retErr =
		bcli.GetLastRecord(agentID, url, storageGrp, bcli.RKEY_Paper)
	if retErr != nil {
		return
	}

	rsp, err = json.Marshal(paper)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a response: " + err.Error())
		return
	}

	return // success
}

func ballotGetSealKey(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_Voter {
		retErr = fmt.Errorf("authentication error")
		return
	}

	agentID, retErr := getBallotBoxAgent(cert)
	if retErr != nil {
		return
	}
	
	url := "localhost" + port
	storageGrp, err := bcli.GetStorageForBallotBox(agentID, url)
	if err != nil {
		retErr = fmt.Errorf("not found ballot box")
		return
	}

	pubKey := &bcli.GetSealKeyReply{}
	pubKey.RecorderCert, pubKey.Signature, pubKey.Message, retErr =
		bcli.GetLastRecord(agentID, url, storageGrp, bcli.RKEY_SealPub1)
	if retErr != nil {
		return
	}

	rsp, err = json.Marshal(pubKey)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a public key: " + err.Error())
		return

	}

	return // success
}

func ballotVote(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	now := time.Now()
	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_Voter {
		retErr = fmt.Errorf("authentication error")
		return
	}

	username := cert.Subject.CommonName
	caName := cert.Issuer.CommonName
	voterRegID, _,  err := immutil.GetAdminID(username, caName)
	if err != nil {
		retErr = fmt.Errorf("authentication error")
		return
	}
	
	caCli := cacli.NewCAClient("https://" + caName + cacli.DefaultPort)
	voterRegUser := &immclient.UserID{Name: voterRegID.Name, Priv: voterRegID.Priv, Cert: voterRegID.Cert, Client: caCli, }

	voterState, retErr := getVoterState(voterRegUser, username)
	if retErr != nil {
		return
	}
	if voterState == VOTER_STA_voted {
		retErr = fmt.Errorf("you have already voted")
		return
	}
	if voterState != VOTER_STA_registered {
		retErr = fmt.Errorf("invalid state")
		return
	}
	// voterState == VOTER_ST_registered

	agentID, retErr := getBallotBoxAgent(cert)
	if retErr != nil {
		return
	}

	url := "localhost" + port
	storageGrp, err := bcli.GetStorageForBallotBox(agentID, url)
	if err != nil {
		retErr = fmt.Errorf("not found ballot box")
		return
	}

	pollTimes, retErr := getPollTimes(agentID, url, storageGrp)
	if retErr != nil {
		return
	}
	retErr = checkPollTimes(now, pollTimes)
	if retErr != nil {
		return
	}
	
	adminOfficialCertRaw, _, _, retErr :=
		bcli.GetLastRecord(agentID, url, storageGrp, bcli.RKEY_SealPub2)

	adminOfficialCert, err := immsign.GetRecorderCertificate(adminOfficialCertRaw)
	if err != nil {
		retErr = fmt.Errorf("There is no administrator for election official in this system")
		return
	}
	
	recorderRole := immclient.GetCertRole(adminOfficialCert)
	if recorderRole != bcli.ROLE_AdminOfficial {
		retErr = fmt.Errorf("failed to get a public key to seal ballot papers")
		return
	}

	adminOfficialPub, ok := adminOfficialCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		retErr = fmt.Errorf("invalid public key in the certificate")
		return
	}
	
	agentPrivData, _ := pem.Decode(agentID.Priv)
	agentPrivBase, _ :=  x509.ParsePKCS8PrivateKey(agentPrivData.Bytes)
	agentPriv, ok :=  agentPrivBase.(*ecdsa.PrivateKey)
	if !ok {
		retErr = fmt.Errorf("unexpected agent")
		return
	}

	sealTool, err := immconf.GetSharedKey(agentPriv, adminOfficialPub)
	if err != nil {
		retErr = fmt.Errorf("failed to get a key to seal ballot papers: " + err.Error())
		return
	}

	plainReq, err := proto.Marshal(req)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal ballot papers: " + err.Error())
		return
	}

	sealedReq, err := sealTool.Encrypt(plainReq)
	if err != nil {
		retErr = fmt.Errorf("failed to encrypt ballot papers: " + err.Error())
		return
	}
	sealedReqBase64 := base64.StdEncoding.EncodeToString(sealedReq)
	
	err = agentID.RecordLedger(storageGrp, bcli.RKEY_BallotBox, sealedReqBase64, url)
	if err != nil {
		retErr = fmt.Errorf("failed to insert papers into the ballot box")
		return
	}

	modifyingReq := &immclient.ModifyIdentityRequest{
		Attributes: []immclient.Attribute{
			immclient.Attribute{ Name: VOTER_STA, Value: VOTER_STA_voted, ECert: false},
		},
	}
	voterRegUser.ModifyIdentity(caCli.UrlBase, username, modifyingReq)

	return // success
}

func ballotGetVotingResult(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	role := immclient.GetRole(req.Cred.Cert)
	if role != bcli.ROLE_Voter && role == bcli.ROLE_ElectionOfficial {
		retErr = fmt.Errorf("authentication error")
		return
	}

	agentID, retErr := getBallotBoxAgent(cert)
	if retErr != nil {
		return
	}

	url := "localhost" + port
	storageGrp, err := bcli.GetStorageForBallotBox(agentID, url)
	if err != nil {
		retErr = fmt.Errorf("not found ballot box")
		return
	}

	result := &bcli.GetResultVoteReply{}
	result.RecorderCert, result.Signature, result.Message, retErr =
		bcli.GetLastRecord(agentID, url, storageGrp, bcli.RKEY_Result)
	if retErr != nil {
		return
	}

	rsp, err = json.Marshal(result)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a public key: " + err.Error())
		return
	}
	return // success
}

func getPollTimes(id *immclient.UserID, url, storageGrp string) (pollTimes *bcli.PollTimes, retErr error) {
	recorder, signature, message, err := bcli.GetLastRecord(id, url, storageGrp, bcli.RKEY_PollTimes)
	if err != nil {
		retErr = err
		return
	}

	pollTimesJson, cert, err :=  bcli.GetRecordValue(recorder, signature, message)
	if err != nil {
		retErr = err
		return
	}

	role := immclient.GetCertRole(cert)
	if role != bcli.ROLE_AdminOfficial {
		retErr = errors.New("unexpected recorder for poll times")
		return
	}

	pollTimes = &bcli.PollTimes{}
	err = json.Unmarshal([]byte(pollTimesJson), pollTimes)
	if err != nil {
		retErr = errors.New("unexpected record: " + err.Error())
		return
	}

	return // success
}

func checkPollTimes(now time.Time, pollTimes *bcli.PollTimes) (error) {
	openingT := &time.Time{}
	closingT := &time.Time{}

	err := openingT.UnmarshalText([]byte(pollTimes.OpeningTime))
	if err != nil {
		return errors.New("Opening time is unexpected format: " + err.Error())
	}
	err = closingT.UnmarshalText([]byte(pollTimes.ClosingTime))
	if err != nil {
		return errors.New("Closing time is unexpected format: " + err.Error())
	}

	withinF := openingT.Before(now)
	withinF = withinF || openingT.Equal(now)
	if (openingT.Before(now)||openingT.Equal(now)) && closingT.After(now) {
		return nil
	}
	return errors.New("out of time")
}

func ballotGetVoterState(req *immop.BallotFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	reqName := &bcli.GetVoterStateRequest{}
	err := json.Unmarshal(req.Req, reqName)
	if err != nil {
		retErr = fmt.Errorf("unexpected request: " + err.Error())
		return
	}

	username := cert.Subject.CommonName
	caName := cert.Issuer.CommonName
	if reqName.Username != "" {
		role := immclient.GetRole(req.Cred.Cert)
		if role != bcli.ROLE_AdminOfficial {
			retErr = fmt.Errorf("authentication errror")
			return
		}

		username = reqName.Username
	}
	
	voterRegID, _,  err := immutil.GetAdminID(username, caName)
	if err != nil {
		retErr = fmt.Errorf("authentication error")
		return
	}
	
	caCli := cacli.NewCAClient("https://" + caName + cacli.DefaultPort)
	voterRegUser := &immclient.UserID{Name: voterRegID.Name, Priv: voterRegID.Priv, Cert: voterRegID.Cert, Client: caCli, }

	state, retErr := getVoterState(voterRegUser, username)
	if retErr != nil {
		return
	}

	voterState := &bcli.GetVoterStateReply{
		State: state,
	}
	rsp, err = json.Marshal(voterState)
	if err !=nil {
		retErr = fmt.Errorf("failed to marshal a state: " + err.Error())
		return
	}
	
	return // success
}

func getVoterState(voterRegUser *immclient.UserID, username string) (state string, retErr error) {	
	attrs, err := voterRegUser.GetIdentity(voterRegUser.Client.(*cacli.CAClient).UrlBase, username)
	if err != nil {
		retErr = fmt.Errorf("authentication error")
		return
	}

	for _, attr := range attrs.Attributes {
		if attr.Name == VOTER_STA {
			state = attr.Value
			return // success
		}
	}

	retErr = fmt.Errorf("not found state")
	return
}
