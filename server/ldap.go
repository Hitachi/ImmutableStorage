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
	"crypto/tls"
	"regexp"
	"strings"
	"fmt"

	"github.com/golang/protobuf/proto"
	
	"immop"
	"immclient"
	"cacli"
	
	ldap "github.com/go-ldap/ldap/v3"
)

func PingLDAP(serverName string) error {
	ldapSrv, err := ldap.Dial("tcp", serverName)
	if err != nil {
		return fmt.Errorf("could not connect to the LDAP server (%s): %s", serverName, err)
	}
	ldapSrv.Close()
	return nil
}

func registerLDAPAdmin(caCli *cacli.CAClient, tmpPriv, tmpCert []byte, req *immop.RegisterUserRequest) ([]byte, error) {
	authParam := &immop.AuthParamLDAP{}
	err := proto.Unmarshal(req.AuthParam, authParam)
	if err != nil {
		return nil, fmt.Errorf("invalid authentication parameter: %s", err)
	}

	err = PingLDAP(authParam.BindServer)
	if err != nil {
		return nil, err
	}

	if authParam.QueryServer != "" {
		err = PingLDAP(authParam.QueryServer)
		if err != nil {
			return nil, err
		}
	}

	// register an LDAP user to the CA DB
	affiliation := affnLDAPPrefix + strings.ReplaceAll(authParam.UserNameOnCA, ".", ":")
	regReq := &immclient.RegistrationRequest{
		Name: authParam.UserNameOnCA,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: "LDAP.BindServer", Value: authParam.BindServer, ECert: false},
			immclient.Attribute{Name: "LDAP.BindDN", Value: authParam.BindDN, ECert: false},
			immclient.Attribute{Name: "LDAP.QueryServer", Value: authParam.QueryServer, ECert: false},
			immclient.Attribute{Name: "LDAP.BaseDN", Value: authParam.BaseDN, ECert: false},
			immclient.Attribute{Name: "LDAP.Query", Value: authParam.Query, ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Roles", Value: "client", ECert: false},
		},
		Affiliation: affiliation,
		Type: "client",
		MaxEnrollments: -1, // unlimit
	}

	caRegID := &immclient.UserID{Name: "tmpUser", Priv: tmpPriv, Cert: tmpCert, Client: caCli}
	return caCli.RegisterAndEnrollAdmin(caRegID, regReq, 1/*one year*/)
}

func connLDAP(serverName string) (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", serverName)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the LDAP server: %s", err)
	}
	
	err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		return conn, nil // success
	}
	
	fmt.Printf("log: insecure connection with the LDAP server: %s\n", err)
	conn.Close()
	
	conn, err = ldap.Dial("tcp", serverName)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the LDAP server: %s", err)
	}
	return conn, nil // success	
}

func getLDAPAttr(adminID *immclient.UserID, authType, authUsername string) (ldapAttr map[string] string, username string, retErr error) {
	caCli := adminID.Client.(*cacli.CAClient)
	adminAttr, err := adminID.GetIdentity(caCli.UrlBase, adminID.Name)
	if err != nil {
		retErr = fmt.Errorf("authentication error")
		return
	}

	if authType == ballotAuthTypeLDAP {
		ldapAttr, retErr =  ballotGetLDAPAttr(&adminAttr.Attributes)
		username = strings.TrimSuffix(authUsername, voterRegNameSuffix)
		return
	}

	ldapAttr = map[string] string{
		"LDAP.BindServer": "",
		"LDAP.BindDN": "",
		"LDAP.QueryServer": "",
		"LDAP.BaseDN": "",
		"LDAP.Query": "",
	}
	
	for _, attr := range adminAttr.Attributes {
		_, ok := ldapAttr[attr.Name]
		if ok {
			ldapAttr[attr.Name] = attr.Value
		}
	}
	username = authUsername
	return
}

func authenticateLDAPUser(adminID *immclient.UserID, authType, authUsername, secret string) (retErr error) {
	ldapAttr, username, err := getLDAPAttr(adminID, authType, authUsername)
	if err != nil {
		retErr = err
		return
	}
	
	for ldapAttr["LDAP.BindServer"] == "" || ldapAttr["LDAP.BindDN"] == "" {
		// not LDAP user
		retErr = fmt.Errorf("invalid user")
		return 
	}

	semiExp, _ := regexp.Compile("^\\s*\"(.*)\"(.*)")
	spExp, _ := regexp.Compile("\\s")


	var bindDNArgVals []interface{}
	bindDNStr := semiExp.ReplaceAllString(ldapAttr["LDAP.BindDN"], "$1")
	bindDNArgsStr := semiExp.ReplaceAllString(ldapAttr["LDAP.BindDN"], "$2")
	bindDNArgsStr = spExp.ReplaceAllString(bindDNArgsStr, "")
	bindDNArgs := strings.Split(bindDNArgsStr, ",")

	for _, bindArg := range bindDNArgs {
		if bindArg == "username" {
			nameAndOrg := strings.SplitN(username, "@", 2)
			bindDNArgVals = append(bindDNArgVals,  nameAndOrg[0])
		}
	}
	
	if ldapAttr["LDAP.QueryServer"] != "" {
		queryStr := semiExp.ReplaceAllString(ldapAttr["LDAP.Query"], "$1")
		queryArgsStr := semiExp.ReplaceAllString(ldapAttr["LDAP.Query"], "$2")
		queryArgsStr = spExp.ReplaceAllString(queryArgsStr, "")
		queryArgs := strings.Split(queryArgsStr, ",")
		
		for _, queryArg := range queryArgs {
			if queryArg == "username" {
				queryStr = fmt.Sprintf(queryStr, username)
			}
		}

		queryArgs = nil
		for _, queryArg := range bindDNArgs {
			if queryArg == "" {
				continue // skip
			}

			queryArgs = append(queryArgs, queryArg)
		}
		bindDNArgs = queryArgs
	
		if queryArgs == nil {
			queryArgs = []string{"dn"}
		}

		var querySrv *ldap.Conn
		querySrv, retErr = connLDAP(ldapAttr["LDAP.QueryServer"])
		if retErr != nil {
			return
		}
		defer querySrv.Close()
	
		searchReq := ldap.NewSearchRequest(
			ldapAttr["LDAP.BaseDN"],
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			queryStr, queryArgs, nil)
		queryResult, err := querySrv.Search(searchReq)
		if err != nil {
			retErr = fmt.Errorf("failed to search a user in the LDAP with the \""+queryStr+"\" filter: " + err.Error())
			return
		}
		if queryResult.Entries == nil {
			retErr = fmt.Errorf("could not get a bind-DN for the specified user")
			return
		}

		notFoundAttr := ""
		for _, ldapEntry := range queryResult.Entries {
			notFoundAttr = ""
			for _, queryArg := range bindDNArgs {
				bindArg := ldapEntry.GetAttributeValue(queryArg)
				if bindArg == "" {
					notFoundAttr = queryArg
					break // go to next entry
				}

				bindDNArgVals = append(bindDNArgVals, bindArg)
			}
			if notFoundAttr == "" { 
			break
			}

			bindDNArgVals = nil // go to next entry
		}
	
		if notFoundAttr != "" {
			retErr = fmt.Errorf("\""+notFoundAttr+"\" attribute is not found")
			return
		}
	}

	bindDNStr = fmt.Sprintf(bindDNStr, bindDNArgVals...)

	bindSrv, retErr := connLDAP(ldapAttr["LDAP.BindServer"])
	if retErr != nil {
		return
	}
	defer bindSrv.Close()

	err = bindSrv.Bind(bindDNStr, secret)
	if err != nil {
		retErr = fmt.Errorf("authentication error")
		return
	}

	return // authentication success
}
