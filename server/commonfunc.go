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

package main

import (
	"strings"
	"strconv"
	"errors"
	"time"
	"crypto/x509"
	"encoding/json"
	"log"
	_ "embed"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"immutil"
	"immclient"
	"immop"
	"immadmin"
	"immcommon"
	"cacli"
	"couchcli"
	"storagegrp"
)

//go:embed rsyslog/rsyslog.conf
var templ_rsyslog_conf string
//go:embed rsyslog/config.yaml
var templ_rsyslog2imm_conf string

const (
	EXConfigName = "exconfig"
	StorageGrpPermAttr = "AccessPermission: "
	DefaultEXConfig = StorageGrpPermAttr+immadmin.AccessPermAll
	StorageGrpPermDir = "/var/lib/immconfig/accessPerm/"
)

func (s *server) commonFunc(req *immop.ImmstFuncRequest, cert *x509.Certificate) (reply *immop.ImmstFuncReply, retErr error) {
	reply = &immop.ImmstFuncReply{}

	switch req.Func {
	case immadmin.FCreateRsyslogEnv:
		reply.Rsp, retErr = s.createRsyslogEnv(req, cert)
	case immadmin.FListRsyslogEnv:
		reply.Rsp, retErr = s.listRsyslogEnv(req, cert)
	case immadmin.FSetStorageGrpPerm:
		reply.Rsp, retErr = s.setStorageGrpPerm(req, cert)
	case immadmin.FGetStorageGrpPerm:
		reply.Rsp, retErr = s.getStorageGrpPerm(req, cert)
	case immadmin.FListKeyInStorageGrp:
		reply.Rsp, retErr = s.listKeyInStorageGrp(req, cert)
	case immcommon.FWhoamI:
		reply.Rsp, retErr = s.WhoamI(req, cert)
	}
	
	log.Printf("error: %s\n", retErr)
	return
}

func checkRsyslogEnvAdminRole(cert *x509.Certificate) error {
	role := immclient.GetCertRole(cert)
	if role != immadmin.ROLE_RsyslogEnvAdmin {
		return errors.New("access denied")
	}
	return nil // access allowed
}

func (s *server) createRsyslogEnv(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	retErr = checkRsyslogEnvAdminRole(cert)
	if retErr != nil {
		return
	}

	createReq := &immadmin.CreateRsyslogEnvReq{}
	err := json.Unmarshal(req.Req, createReq)
	if err != nil {
		retErr = errors.New("unexpected request: " + err.Error())
		return
	}

	list, err := immutil.K8sListSecret("user=rsyslog")
	if err != nil {
		retErr = errors.New("unexpected state: "+err.Error())
		return
	}
	
	numSc := len(list.Items)
	allocatedN := make([]uint64, numSc/64+1)
	for _, sc := range list.Items {
		curSvcName := strings.TrimSuffix(sc.ObjectMeta.Name, "." + s.org)
		curN, err := strconv.Atoi(strings.TrimPrefix(curSvcName, "rsyslog"))
		if err != nil {
			continue
		}
		allocatedN[curN/64] |= uint64(1)<<(curN%64)
	}

	nextN := func() int {
		var i, j int
		for i = 0; i < numSc+1; i++ {
			for j = 0; j < 64; j++ {
				if allocatedN[i] & (uint64(1)<<j) == 0 {
					return i*64+j
				}
			}
		}
		return i*64+j
	}()
	svcName := "rsyslog" + strconv.Itoa(nextN)

	rsyslogCert, _, err := immutil.ReadCertificate(createReq.Cert)
	if err != nil {
		retErr = errors.New("unexpected certificate: " + err.Error())
		return
	}
	rsyslogUsername := rsyslogCert.Subject.CommonName
	
	secretName := svcName + "." + s.org
	retErr = immutil.K8sStoreKeyPairOnSecret(createReq.Priv, createReq.Cert, secretName, &map[string]string{"user": "rsyslog",})
	if retErr != nil {
		return
	}

	var rollbackFunc []func()
	defer func() {
		if retErr == nil {
			return
		}
		for i := len(rollbackFunc)-1; i >= 0; i-- {
			rollbackFunc[i]()
		}
	}()
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteSecret(secretName)
	})

	// make configuration files
	rsyslogConfig := strings.Replace(templ_rsyslog_conf, "LOGGING_CONDITION", createReq.LoggingCondition, 1)
	rsyslogConfig = strings.Replace(rsyslogConfig, "LOGGING_KEY", createReq.LoggingKey, 1)
	
	rsys2immConfig := strings.Replace(templ_rsyslog2imm_conf, "USERNAME", rsyslogUsername, 1)
	rsys2immConfig = strings.Replace(rsys2immConfig, "STORAGE_GRP", createReq.StorageGrp, 1)

	rsysConfigFiles := &map[string]string{
		"rsyslog.conf": rsyslogConfig,
		"config.yaml": rsys2immConfig,
	}
	err = immutil.K8sStoreFilesOnConfig(secretName, &map[string]string{"config": "rsyslog"}, rsysConfigFiles, nil)
	if err != nil {
		retErr = errors.New("failed to create a ConfigMap for a rsyslogd: " + err.Error())
		return
	}
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteConfigMap(secretName)
	})

	pullRegAddr, err := immutil.GetPullRegistryAddr(s.org)
	if err == nil {
		pullRegAddr += "/"
	}
	
	repn := int32(1)
	ndots := "1"
	fsGroup := int64(101)
	defaultMode := int32(0440)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Labels: map[string]string{
				"app": svcName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": svcName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": svcName,
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup: &fsGroup,
					},
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config-files",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secretName,
									},
								},
							},
						},
						{
							Name: "rsysloguser",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName,
									DefaultMode: &defaultMode,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name: "rsyslogd",
							Image: pullRegAddr + immutil.RsyslogImg,
							Command: []string{"sh", "-c", "mkfifo -m 0660 /tmp/logpipe; chown root.syslog /tmp/logpipe; while true; do if read line < /tmp/logpipe; then echo $line; fi;done &  rsyslogd -n"},
							ImagePullPolicy: corev1.PullAlways,
							Ports: []corev1.ContainerPort{
								{
									Name: "rsyslogport",
									Protocol: corev1.ProtocolUDP,
									ContainerPort: 514,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "config-files", MountPath: "/etc/rsyslog.conf", SubPath: "rsyslog.conf", ReadOnly: true, },
								{ Name: "config-files", MountPath: "/etc/rsyslog2imm/config.yaml", SubPath: "config.yaml", ReadOnly: true, },
								{ Name: "rsysloguser", MountPath: "/etc/rsyslog2imm/"+rsyslogUsername+"_sk", SubPath: "key", ReadOnly: true, },
								{ Name: "rsysloguser", MountPath: "/etc/rsyslog2imm/"+rsyslogUsername+"-cert.pem", SubPath: "cert", ReadOnly: true, },
							},
						},
					},
				},
			},
		},
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
			Labels: map[string]string{
				"svc": "rsyslog",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": svcName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "rsyslog",
					Port: 514,
					Protocol: corev1.ProtocolUDP,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 514,
					},
				},
			},
		},
	}

	retErr = immutil.K8sDeployPodAndService(deployment, service)
	if retErr != nil {
		return
	}
	
	return // success
}

func (s *server) listRsyslogEnv(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	retErr = checkRsyslogEnvAdminRole(cert)
	if retErr != nil {
		return
	}

	list, err := immutil.K8sListSecret("user=rsyslog")
	if err != nil {
		retErr = err
		return
	}

	reply := &immadmin.ListRsyslogEnvReply{}
	for _, sc := range list.Items {
		if sc.Data == nil {
			continue
		}
		
		certPem, ok := sc.Data["cert"]
		if !ok {
			continue
		}
		
		rsyslogCert, _, err := immutil.ReadCertificate(certPem)
		if err != nil {
			continue
		}

		reply.Usernames = append(reply.Usernames, rsyslogCert.Subject.CommonName)
	}

	rsp, err = json.Marshal(reply)
	if err != nil {
		retErr = errors.New("failed to marshal usernames: " + err.Error())
		return
	}

	return // success
}

func (s *server) getRsyslogSvcName(rsyslogUsername string) (svcName string, retErr error) {
	list, err := immutil.K8sListSecret("user=rsyslog")
	if err != nil {
		retErr = err
		return
	}

	for _, sc := range list.Items {
		if sc.Data == nil {
			continue
		}

		certPem, ok := sc.Data["cert"]
		if !ok {
			continue
		}
		
		rsyslogCert, _, err := immutil.ReadCertificate(certPem)
		if err != nil {
			continue
		}

		if rsyslogUsername == rsyslogCert.Subject.CommonName {
			svcName = strings.TrimSuffix(sc.ObjectMeta.Name, "."+s.org)
			return
		}
	}

	retErr = errors.New(rsyslogUsername + " is not rsyslog user")
	return
}

func (s *server) setStorageGrpPerm(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	grpAdminHost := getGrpAdminHost(cert)
	if grpAdminHost == "" {
		retErr = errors.New("permission denied")
		return
	}

	setReq := &immadmin.SetStorageGrpPermReq{}
	err := json.Unmarshal(req.Req, setReq)
	if err != nil {
		retErr = errors.New("invalid request: " + err.Error())
		return
	}

	switch setReq.AccessPermission {
	case immadmin.AccessPermAll:
	case immadmin.AccessPermGrpMember:
	default:
		retErr = errors.New("unsupported storage group permission: " + setReq.AccessPermission)
		return		
	}
	
	configName := grpAdminHost+"-ch"
	retErr = immutil.K8sAppendFilesOnConfig(configName, &map[string]string{"grpHost": grpAdminHost},
		&map[string]string{EXConfigName: StorageGrpPermAttr+setReq.AccessPermission}, nil)
	if retErr != nil {
		return
	}

	return // success
}

func (s *server) getStorageGrpPerm(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	grpAdminHost := getGrpAdminHost(cert)
	if grpAdminHost == "" {
		retErr = errors.New("permission denied")
		return
	}

	configName := grpAdminHost+"-ch"
	reply := &immadmin.GetStorageGrpPermReply{
		AccessPermission: immadmin.AccessPermAll,
	}
	
	accessPermission, err := immutil.K8sReadFileInConfig(configName, EXConfigName)
	if err == nil {
		reply.AccessPermission = strings.TrimPrefix(accessPermission, StorageGrpPermAttr)
	}
	
	rsp, retErr = json.Marshal(reply)
	if retErr != nil {
		retErr = errors.New("failed to marshal permission: " + retErr.Error())
	}
	return	
}

func (s *server) WhoamI(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	username := cert.Subject.CommonName
	defer func() {
		if retErr != nil {
			return
		}

		reply := &immcommon.WhoamIReply{
			Username: username,
			Time: time.Now().Format(time.RFC3339),
		}

		var err error
		rsp, err = json.Marshal(reply)
		if err != nil {
			retErr = errors.New("failed to marshal a username: " + err.Error())
			return
		}
		return // success
	}()
	
	id, retErr := getTempUserID(cert)
	if retErr != nil {
		return
	}
	
	userAttr, err := id.GetIdentity(id.Client.(*cacli.CAClient).UrlBase, username)
	if err == nil {
		if userAttr.MaxEnrollments < 1 &&  userAttr.MaxEnrollments != -1/* unlimited */ {
			retErr =  errors.New("I am disabled")
			return
		}
		return // success
	}

	if strings.HasSuffix(err.Error(), "code=0x47") {
		// authorization failure, but authentication success
		return // success
	}
	retErr= errors.New("authentication failure")
	return
}

func getTempUserID(cert *x509.Certificate) (id *immclient.UserID, retErr error) {
	username := cert.Subject.CommonName
	caName := cert.Issuer.CommonName

	caCli := cacli.NewCAClient("https://"+caName+cacli.DefaultPort)
	id = &immclient.UserID{ Client: caCli, }
	
	adminID, _, err := immutil.GetAdminID(username, caName)
	if err == nil {
		id.Name = adminID.Name
		id.Priv = adminID.Priv
		id.Cert = adminID.Cert
		return // success
	}

	// get my temporary ID
	caPriv, caCert, err := immutil.K8sGetKeyPair(caName)
	if err != nil {
		retErr = errors.New("CA server is not ready")
		return
	}

	id.Name = username	
	id.Priv, id.Cert, err = immutil.CreateTemporaryCert(cert, caPriv, caCert)
	if err != nil {
		retErr = errors.New("unexpected state")
		return
	}

	return // success
}

func (s *server) listKeyInStorageGrp(req *immop.ImmstFuncRequest, cert *x509.Certificate) (rsp []byte, retErr error) {
	reply := &immadmin.ListKeyInStorageGrpReply{}

	storageGrp := storagegrp.GetStorageGrpAttr(cert)
	if storageGrp == "" {
		retErr = errors.New("access denied")
		return
	}
	
	chConf, retErr := readChannelConf(storageGrp)
	if retErr != nil {
		return
	}

	org := cert.Issuer.Organization[0]
	peers, ok := chConf.AnchorPeers[org]
	if !ok {
		retErr = errors.New("unexpected organization in the certificate: " + org)
		return
	}
	storageShortName := strings.SplitN(peers[0], ":", 2)[0]

	cli := couchcli.New("http://"+couchdbHostPrefix+storageShortName+":5984")

	expectDB := strings.ReplaceAll(storageGrp, ".", "$") + "-ch_hl$rsyslog"
	allDBs := &[]string{}
	retErr = cli.Get("/_all_dbs", allDBs)
	if retErr != nil {
		return
	}
	
	for _, db_name := range *allDBs {
		if db_name != expectDB {
			continue
		}
		
		docs_info := &struct{
			Total_rows int
			Rows []struct{Id string}
		}{}

		retErr = cli.Get("/"+db_name +"/_all_docs", docs_info)
		if retErr != nil {
			return
		}
		
		for _, row := range docs_info.Rows {
			reply.Keys = append(reply.Keys, row.Id)
		}
		break
	}

	var err error
	rsp, err = json.Marshal(reply)
	if err != nil {
		retErr = errors.New("failed to marshal a list of keys: " + err.Error())
		return
	}
	return // success
}

