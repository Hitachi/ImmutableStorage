/*
Copyright Hitachi, Ltd. 2022 All Rights Reserved.

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
	"crypto/x509"
	"crypto/tls"
	"net/http"
	"strings"
	"fmt"
	"log"
	"io"
	"context"
	"golang.org/x/oauth2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	
	"cacli"
	"immop"
	"immclient"
	"immutil"
)

const (
	REG_NAME_SUFFIX = "@oauth"
	GRAPHCALLBACK_PATH = "/graphcallback"
	HTTPD_CONFIG_FILE = "/usr/local/apache2/conf/httpd.conf"
)

type OAuthParam struct{
	GroupName string
	ClientID string
	SecretValue string
	AllowDomains string	
}

func registerOAuthAdmin(caCli *cacli.CAClient, tmpPriv, tmpCert []byte, req *immop.RegisterUserRequest) (cert []byte, retErr error) {
	authParam := &OAuthParam{}
	err := json.Unmarshal(req.AuthParam, authParam)
	if err != nil {
		retErr = fmt.Errorf("invalid authentication parameters")
		return
	}

	adminName := "@" + authParam.GroupName + REG_NAME_SUFFIX
	affiliation := affnFEDPrefix + strings.ReplaceAll(adminName, ".", ":")
	regReq := &immclient.RegistrationRequest{
		Name: adminName,
		Attributes: []immclient.Attribute{
			immclient.Attribute{Name: ROLE_Prefix+"AdminReg", Value: "true", ECert: true},
			immclient.Attribute{Name: AUTH_Param, Value: string(req.AuthParam), ECert: false},
			immclient.Attribute{Name: "hf.Registrar.Roles", Value: "client,oauthReg", ECert: false},
		},
		Affiliation: affiliation,
		Type: "oauthReg",
		MaxEnrollments: -1, // unlimit
	}

	caRegID := &immclient.UserID{Name: "tmpUser", Priv: tmpPriv, Cert: tmpCert, Client: caCli}
	cert, retErr = caCli.RegisterAndEnrollAdmin(caRegID, regReq, 1/*one year*/)
	if retErr != nil {
		return
	}

	org, err := caRegID.GetIssuerOrg()
	if err != nil {
		retErr = fmt.Errorf("failed to get an organization name: %s", err)
		return
	}

	retErr = createOAuthHandler(org)
	if retErr != nil {
		return
	}
	
	return
}

type userConfig struct{
	oauthConfig *oauth2.Config
	allowDomains string
	adminID *immclient.UserID
}
var oauthState map[string]*userConfig
var oauthSrv *http.Server
var oauthCAName string

type allowUserAttr struct{
	username string
	adminID *immclient.UserID
}
var oauthAllowUser map[string]*allowUserAttr

func createOAuthHandler(org string) (retErr error){
	oauthCAName = immutil.CAHostname+"."+org
	adminIDs, err := immutil.GetAdminIDs("OAUTH_GRAPH", oauthCAName)
	if err != nil {
		retErr = err
		return
	}
	if len(adminIDs) <= 0 {
		return // not necessary
	}

	tlsCASecretName := immutil.TlsCAHostname + "." +  org
	tlsCAPriv, tlsCACert, err := immutil.K8sGetKeyPair(tlsCASecretName)
	if err != nil {
		retErr = fmt.Errorf("failed to read TLS keys: %s", err)
		return
	}

	tlsSubj, err := immutil.NewCertSubject(tlsCACert, immutil.OAuthHostname)
	if err != nil {
		retErr = fmt.Errorf("failed to create a subject for a certiifcate: %s", err)
		return
	}
		
	keyName, err := immutil.K8sCreateKeyPair(tlsSubj, tlsCAPriv, tlsCACert, nil)
	if err != nil {
		retErr = err
		return
	}
	privPem, pubPem, _ := immutil.K8sGetKeyPair(keyName)
	
	caRoots := x509.NewCertPool()
	ok := caRoots.AppendCertsFromPEM(tlsCACert)
	if !ok {
		retErr = fmt.Errorf("failed to append a certificate to CA root")
		return
	}
	cert, err := tls.X509KeyPair(pubPem, privPem)
	if err != nil {
		retErr = fmt.Errorf("failed to parse a key pair: %s\n", err)
		return
	}

	if oauthSrv != nil {
		if err := oauthSrv.Shutdown(context.Background()); err != nil {
			log.Printf("failed to shutdown the HTTP server: %s\n", err)
		}
		oauthSrv = nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", oauthGraphCallback)
	mux.HandleFunc("/login/", oauthGraphLogin)
	oauthSrv := &http.Server{
		Addr: ":50053",
		Handler: mux,
		TLSConfig: &tls.Config{
			RootCAs: caRoots,
			Certificates: []tls.Certificate{cert},
		},
	}
	oauthState = make(map[string]*userConfig)
	oauthAllowUser = make(map[string]*allowUserAttr)

	go func(){
		err = oauthSrv.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("ListenAndServeTLD: %s\n", err)
			return
		}
	}()


	retErr = createOAuthSvc(org)
	if retErr != nil {
		return
	}
	
	return // success
}


func oauthGraphLogin(w http.ResponseWriter, req *http.Request) {
	adminIDs, err := immutil.GetAdminIDs("OAUTH_GRAPH", oauthCAName)
	if err != nil || len(adminIDs) <= 0{
		return // ignore
	}
	caCli := cacli.NewCAClient("https://"+oauthCAName+cacli.DefaultPort)

	groupName := strings.TrimPrefix(req.URL.Path, "/login/")
	if groupName == req.URL.Path {
		return // ignore
	}

	var authParam *OAuthParam
	cfg := &userConfig{} 
	for _, adminID := range adminIDs {
		adminUser := &immclient.UserID{Name: adminID.Name, Priv: adminID.Priv, Cert: adminID.Cert, Client: caCli, }
		adminAttr, err := adminUser.GetIdentity(caCli.UrlBase, adminUser.Name)
		if err != nil {
			continue
		}

		privilegeF := false
		for _, attr := range adminAttr.Attributes {
			switch attr.Name {
			case ROLE_Prefix+"AdminReg":
				privilegeF = (attr.Value == "true")
			case AUTH_Param:
				authParam = &OAuthParam{}
				err := json.Unmarshal([]byte(attr.Value), authParam)
				if err != nil {
					authParam = nil
					break
				}

				if groupName != authParam.GroupName {
					authParam = nil
					break
				}
			}
		}

		if authParam != nil && privilegeF {
			cfg.adminID = adminUser
			break
		}
	}
	if authParam == nil {
		log.Printf("Authentication failure: not allow group=%s\n", groupName)
		return // authentication failure
	}

	org, _ := cfg.adminID.GetIssuerOrg()
	cfg.oauthConfig =  &oauth2.Config{
		ClientID: authParam.ClientID,
		ClientSecret: authParam.SecretValue,
		Scopes: []string{"User.Read"},
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: "https://www."+org+GRAPHCALLBACK_PATH,
	}
	cfg.allowDomains = authParam.AllowDomains

	state := immclient.RandStr(64)
	oauthState[state] = cfg
	url := cfg.oauthConfig.AuthCodeURL(state)
	http.Redirect(w, req, url, http.StatusTemporaryRedirect)
}

type graphUserOdata struct{
	OdataContext string `json:"@odata.context"`
	Principal string `json:"userPrincipalName"`
}

func oauthGraphCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")

	cfg, ok := oauthState[state]
	if !ok {
		log.Printf("unexpected state: %s", state)
		fmt.Fprintf(w, "Authentication failure\n")
		return
	}
	defer delete(oauthState, state)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	token, err := cfg.oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("failed to get an access token: %s\n", err)
		fmt.Fprintf(w, "Authentication failure\n")		
		return
	}

	client := cfg.oauthConfig.Client(ctx, token)

	rsp, err := client.Get("https://graph.microsoft.com/v1.0/me/")
	if err != nil {
		log.Printf("failed to get user information: %s\n", err)
		fmt.Fprintf(w, "Authentication failure\n")
		return
	}
	defer rsp.Body.Close()

	userOdata := &graphUserOdata{}
	dec := json.NewDecoder(rsp.Body)
	for {
		if err := dec.Decode(userOdata); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(w, "Unexpected response: %s\n", err)
			return
		}
	}
	
	//log.Printf("context: %s\n", msg.OdataContext)
	//log.Printf("principal: %s\n", msg.Principal)

	if userOdata.OdataContext != "https://graph.microsoft.com/v1.0/$metadata#users/$entity" {
		fmt.Fprintf(w, "Unexpected reponse\n")
		return
	}

	allowDomains := strings.Split(cfg.allowDomains, ",")
	allowF := false
	for _, allowDomain := range allowDomains {
		if strings.HasSuffix(userOdata.Principal, "@" + allowDomain) {
			allowF = true
			break
		}
	}
	if ! allowF {
		fmt.Fprintf(w, "Authentication failure")
		return
	}
	
	tmpState := immclient.RandStr(16)
	username := userOdata.Principal + REG_NAME_SUFFIX
	oauthAllowUser[tmpState] = &allowUserAttr{
		username: username,
		adminID: cfg.adminID,
	}

	html := `
<!doctype html>
<html>
<body>
  <script src="../wasm_exec.js"></script>
  <script>
    if (!WebAssembly.instantiateStreaming) { // polyfill
        WebAssembly.instantiateStreaming = async (resp, importObject) => {
            const source = await (await resp).arrayBuffer();
            return await WebAssembly.instantiate(source, importObject);
        };
    }
    const go = new Go();
    let mod, inst;
    WebAssembly.instantiateStreaming(fetch("../enrolluser.wasm"), go.importObject).then( async(result) => {
        mod = result.module;
        inst = result.instance;
        await go.run(inst);
    });
  </script>
  <div id="enrollUserContent">
    <input type="hidden" id="username" readonly="readonly" value="`+username+`">
    <input type="hidden" id="secret" readonly="readonly" value="`+tmpState+`">
  </div>
  <div id="result"></div>
</body>
</html>
`
	fmt.Fprintf(w, html)
}

func createOAuthSvc(org string) (retErr error) {
	serviceName := immutil.OAuthHostname
	serviceClient, err := immutil.K8sGetServiceClient()
	if err != nil {
		retErr = err
		return
	}

	svc, err := serviceClient.Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err == nil {
		// This service has already been created.
		if len(svc.Spec.Ports) >= 1 && svc.Spec.Ports[0].Port == 50053 {
			return
		}

		immutil.K8sDeleteService(serviceName)
	}
	
	// create a service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: immutil.OAuthHostname,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": "imm-server",
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port: 50053,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 50053,
					},
				},
			},
		},
	}

	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("Create service %q.\n", resultSvc.GetObjectMeta().GetName())

	err = addProxyPass(org)
	if err != nil {
		log.Printf("%s\n", err)
		immutil.K8sDeleteService(serviceName)
		return err
	}
	
	return nil
}

func addProxyPass(org string) (retErr error) {
	httpdPods, retErr := immutil.K8sListPod("app=httpd")
	if retErr != nil {
		retErr = fmt.Errorf("failed to list pods: %s\n", retErr)
		return
	}

	podNamePrefix := immutil.HttpdHostname + "." + org
	var httpdPod *corev1.Pod
	for i, item := range httpdPods.Items {
		if strings.HasPrefix(item.Name, podNamePrefix) {
			httpdPod = &httpdPods.Items[i]
			break
		}
	}
	if httpdPod == nil {
		retErr = fmt.Errorf("There is no httpd pod in this cluster: %s\n", retErr)
		return
	}

	commands := [][]string{
		// delete old proxy pass
		[]string{"sed", "-i", "-e", `/ProxyPass "\`+GRAPHCALLBACK_PATH+`"/d`, HTTPD_CONFIG_FILE},
		// add new proxy pass
		[]string{"sed", "-i", "-e", `$aProxyPass "\`+GRAPHCALLBACK_PATH+`" "https://`+immutil.OAuthHostname+"."+org+`:50053"`, HTTPD_CONFIG_FILE},
		// restart httpd
		[]string{"apachectl", "-k", "graceful"},
	}
	for _, cmd := range commands {
		err := immutil.K8sExecCmd(httpdPod.Name, immutil.HttpdHostname, cmd)
		if err != nil {
			retErr = err
			return
		}
	}
	
	return // success
}

func getOAuthAdminID(username, secret string) (adminID *immclient.UserID, authType string) {
	if oauthAllowUser == nil {
		return
	}
	
	attr, ok := oauthAllowUser[secret]
	if !ok || attr.username != username {
		return
	}

	adminID = attr.adminID
	authType = "OAUTH_GRAPH"
	return
}

func authenticateOAuthUser(adminID *immclient.UserID, authType, username, secret string) (retErr error) {
	if oauthAllowUser == nil {
		retErr = fmt.Errorf("Authentication failure")
		return
	}

	attr, ok := oauthAllowUser[secret]
	if !ok || attr.username != username {
		retErr = fmt.Errorf("Authentication failure")
		return
	}

	delete(oauthAllowUser, secret)
	return // authentication success
}
