/*
Copyright Hitachi, Ltd. 2020 All Rights Reserved.

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
	"log"
	"net"


	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/credentials"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"fmt"
	"math"
	"math/big"
	"encoding/pem"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha256"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"time"
	"strings"
	"bytes"
	"strconv"
	"os"
	"sync/atomic"
	"sync"
	"gopkg.in/yaml.v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"


	"fabric/protos/msp"
	"fabric/protos/common"
	pp "fabric/protos/peer"
	po "fabric/protos/orderer"

	"fabric/channelconfig"

	"immop"
	"immutil"
	"fabconf"
	"immclient"
	"immcommon"
	"st2mng"
	"cacli"
	"jpkicli"
	"ballotcli"
)

const (
	port = ":50051"
	certPath = "/var/lib/immsrv/keys/server.crt"
	privPath = "/var/lib/immsrv/keys/server.key"

	couchdbHostPrefix = "couchdb"
	grpcProxySvcPrefix = "gproxy"
	
	fabDefaultConfDir = "/etc/hyperledger/fabric"
	
	ordererGenesisFile = "genesis.block"
	ordererGenesisDir = "/var/hyperledger/orderer/block"
	ordererKeyDir = "/var/hyperledger/orderer"
	ordererDataDir = "/var/hyperledger/production/orderer"
	ordererWorkingDir = "/opt/gopath/src/github.com/hyperledger/fabric"

	peerKeyDir = "/var/hyperledger/peer"
	peerDataDir = "/var/hyperledger/production"
	peerWorkingDir = "/opt/gopath/src/github.com/hyperledger/fabric/peer"

	chaincodePath = "/var/lib/immsrv/hlRsyslog"
	defaultCCName = "hlRsyslog"
	pluginSock = "/run/immplugin.sock"

	clearMspCmd = "rm -rf "+fabDefaultConfDir+"/msp"
	ordererEpCmd = clearMspCmd+`&& (cd `+fabDefaultConfDir+`; ln -s `+ordererKeyDir+`/msp .; ln -s `+ordererKeyDir+`/tls .)`
	peerEpCmd = clearMspCmd+`&& (cd `+fabDefaultConfDir+`; ln -s `+peerKeyDir+`/msp .; ln -s `+peerKeyDir+`/tls .)`

	storageAdminAttr = "StorageAdmin"
	grpAdminOU = "StorageGrpAdmin"

	// storageGrpPort = 7050
	storageGrpPort = 443 // equal to the ingress port
	storageGrpPortStr = "443"
	storagePort = 443 // equal to the ingress port
	storagePortStr = "443"
	grpcProxyPort = 50070

	affnJPKIPrefix = "FedJPKI:"
	affnLDAPPrefix = "FedLDAP:"
	affnFEDPrefix = "FedUSER:"
	authJPKIPrefix = "JPKI"
	authLDAPPrefix = "LDAP"
	authCAPrefix = "CA"
	authOAuthPrefix = "OAUTH"
	
	AUTH_Param = "imm.AuthParam"
	ROLE_Prefix = "imm.Role."
)

type signerState struct {
	signature chan []byte
	err chan error
	rsp []byte
	state int32
	stateDesc string
	cert *x509.Certificate
	
	parent *map[string]*signerState
	taskID string
	grpHost string
}

type server struct{
	parentCert *x509.Certificate
	parentCertPem []byte
	org string
	signer map[string]*signerState
	immop.UnimplementedImmOperationServer
}

type ECDSASignature struct {
	R, S *big.Int
}

type channelConf struct {
	ChannelName string `yaml:"ChannelName"`
	OrdererHost string `yaml:"OrdererHost"`
	OrdererTlsCACert string `yaml:"OrdererTlsCACert"`
	AnchorPeers map[string] []string `yaml:"AnchorPeers"`
	TlsCACerts map[string] string `yaml:"TlsCACerts"`
	CACerts map[string] string `yaml:"CACerts"`
	ClientOU string `yaml:"ClientOU"`
	AccessPermission string `yaml:"AccessPermission"`
}

func (s *server) checkCredential(funcName string, reqParam proto.Message) (*x509.Certificate, error) {
	param := proto.Clone(reqParam)
	//	credMsg := proto.MessageReflect(param)
	credMsg := param.ProtoReflect()
	parentMsg := credMsg

	reqFields := credMsg.Descriptor().Fields()
	credField := reqFields.ByName("Cred")
	if credField != nil {
		credMsg = credMsg.Get(credField).Message()
	}
	signatureField := credMsg.Descriptor().Fields().ByName("Signature")
	certField := credMsg.Descriptor().Fields().ByName("Cert")

	reqSignature := credMsg.Get(signatureField).Bytes()
	reqCert := credMsg.Get(certField).Bytes()

	credMsg.Clear(signatureField)
	credMsg.Clear(certField)
	if credField != nil {
		parentMsg.Clear(credField)
	}
	
	paramMsg, err := proto.Marshal(param)
	if err != nil {
		return nil, fmt.Errorf("invalid request parameter")
	}
	msg := []byte(funcName)
	msg = append(msg, paramMsg...)

	certData, _ := pem.Decode(reqCert)
	if certData.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid public key")
	}

	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key")
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, fmt.Errorf("Unexpected algorithm")
	}

	roots := x509.NewCertPool()
	roots.AddCert(s.parentCert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, })
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate: " + err.Error() )
	}

	sign := &ECDSASignature{}
	asn1.Unmarshal(reqSignature, sign)
	digest := sha256.Sum256(msg)
	ok := ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest[:], sign.R, sign.S)

	if !ok {
		return nil, fmt.Errorf("invalid signature")
	}

	// valid credential
	return cert, nil
}

func getStorageAdminHost(cert *x509.Certificate) string {
	org := cert.Issuer.Organization[0]
	
	for _, ext := range cert.Extensions {
		if ! ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}) {
			continue
		}

		attrs := &immclient.Attributes{}
		err := json.Unmarshal(ext.Value, attrs)
		if err != nil {
			continue
		}
		
		hostname, ok := attrs.Attrs[storageAdminAttr]
		if !ok {
			continue
		}

		if strings.Contains(hostname, org) {
			return hostname
		}
	}

	return "" // permission denied
}

func hasStorageAdmin(cert *x509.Certificate) bool {
	return getStorageAdminHost(cert) != ""
}

func getGrpAdminHost(cert *x509.Certificate) string {
	org := cert.Issuer.Organization[0]

	for _, ou := range cert.Subject.OrganizationalUnit {
		hostname := strings.TrimPrefix(ou, grpAdminOU+":")
		if ou == hostname {
			continue
		}

		hostname = strings.ReplaceAll(hostname, ":", ".")
		if strings.Contains(hostname, org) {
			return hostname
		}
	}
	
	return "" // permission denied
}

func hasStorageGrpAdmin(cert *x509.Certificate) bool {
	return getGrpAdminHost(cert) != ""
}

func (s *server) createConfigYaml() []byte {
	yaml := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/`+s.parentCert.Subject.CommonName+`-cert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/`+s.parentCert.Subject.CommonName+`-cert.pem
    OrganizationalUnitIdentifier: peer
`
	return []byte(yaml)
}

func (s *server) setSignatureCh(desc string, cert *x509.Certificate, grpHost string) (*signerState, error) {
	if len(cert.Issuer.Organization) < 1 {
		return nil, fmt.Errorf("invalid user")
	}

	signer := new(signerState)
	taskID, _ := fabconf.GenerateTxID(cert.Raw)
	s.signer[taskID] = signer
	signer.parent = &s.signer
	signer.taskID = taskID
	signer.grpHost = grpHost

	if atomic.CompareAndSwapInt32(&signer.state, 0, 1) == false {
		return nil, fmt.Errorf("busy, %s is running: state=%d", signer.stateDesc, signer.state)
	}
	
	signer.stateDesc = desc
	signer.signature = make(chan []byte, 1)
	signer.err = make(chan error, 1)	
	signer.rsp = nil
	signer.cert = cert

	return signer, nil
}

func (s *server) getSigner(taskID string) (*signerState, error) {
	signer, ok :=  s.signer[taskID]
	if !ok {
		return nil, fmt.Errorf("unknown user")
	}

	return signer, nil
}

func (signer *signerState) waitSignatureCh() (signature []byte, retErr error) {
	for {
		select {
		case signature = <- signer.signature:
			return
		case <- time.After(30 * time.Second):
			err := signer.signatureChDone()
			if err == nil {
				retErr = fmt.Errorf("timeout")
				return
			}
			continue
		}
	}

	return
}

func (signer *signerState) signatureChDone() error {
	if atomic.CompareAndSwapInt32(&signer.state, 1, 3) == false {
		return fmt.Errorf("signatureChDone: unexpected state = %d", signer.state)
	}

	close(signer.signature)
	close(signer.err)
	signer.stateDesc = ""
	signer.state = 0

	delete(*signer.parent, signer.taskID)

	return nil
}

func (s *server) CreateService(ctx context.Context, req *immop.CreateServiceRequest) (retReply *immop.Reply, retErr error) {
	retReply = &immop.Reply{}

	svcItems := map[string] struct{
		hasPrivilege func(cert *x509.Certificate) bool
		createEnv func(hostname, org, tlsPrivFile, tlsCertFile, tlsCAFile string) error
		mspPrefix string
		keyDir string
		label string
	}{
		"orderer": {
			hasPrivilege: hasStorageGrpAdmin,
			createEnv: s.createOrderer,
			mspPrefix: fabconf.OrdererMspIDPrefix,
			keyDir: ordererKeyDir,
			label: "storage-grp",
		},
		"peer": {
			hasPrivilege: hasStorageAdmin,
			createEnv: createPeer,
			mspPrefix: fabconf.MspIDPrefix,
			keyDir: peerKeyDir,
			label: "storage",
		},
	}

	uCert, retErr := s.checkCredential("CreateService", req)
	if retErr != nil {
		return
	}
	
	// read a certificate data
	cert, pubSki, err := immutil.ReadCertificate(req.Cert)
	if err != nil {
		retErr = fmt.Errorf("failed to read a certificate of the specified service: "+err.Error())
		return
	}

	// read a private key 
	privKey, err := immutil.ReadPrivateKey(req.Priv)
	if err != nil {
		retErr = fmt.Errorf("failed to read a private key of the specified service: "+err.Error())
		return
	}

	if pubSki != getPrivSki(privKey) {
		retErr = fmt.Errorf("There is a mismatch between keys")
		return
	}
	
	ouType := cert.Subject.OrganizationalUnit[0]
	svc, ok := svcItems[ouType]
	if ! ok {
		retErr = fmt.Errorf("unsupported type: " + ouType)
		return
	}

	if ! svc.hasPrivilege(uCert) {
		retErr = fmt.Errorf("permission denied")
		return
	}

	log.Printf("CreateService")
	
	userName := uCert.Subject.CommonName
	host := cert.Subject.CommonName
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	shortHost := strings.TrimSuffix(host, "."+org)

	var reservedHost = map[string] bool {
		immutil.TlsCAHostname: true, immutil.ImmsrvHostname: true, immutil.EnvoyHostname: true, immutil.HttpdHostname: true, immutil.CAHostname: true,
	}
	_, ok = reservedHost[shortHost]
	if ok {
		retErr = fmt.Errorf("The specified hostname ("+shortHost+") is reserved.")
		return
	}

	tlsCAPriv, tlsCACert, err := immutil.K8sGetKeyPair(immutil.TlsCAHostname+"."+s.org)
	if err != nil {
		retErr = fmt.Errorf("failed to read a key-pair for TLS CA: " + err.Error())
		return
	}

	// create a key-pair for TLS
	tlsPriv, tlsCert, tlsSki, retErr := createKeyPair(&cert.Subject, tlsCAPriv, tlsCACert, []string{shortHost, "localhost"})
	if retErr != nil {
		return
	}

	retErr = immutil.K8sSetTLSKeyPairOnSecret(host, tlsPriv, tlsCert, true)
	if retErr != nil {
		return
	}
	log.Printf("created a secret: %s\n", host)

	skiStr := hex.EncodeToString(pubSki[:])


	tlsPrivFile := tlsSki+"_sk"
	tlsCertFile := host+"-cert.pem"
	tlsCACertFile := immutil.TlsCAHostname+"."+org+"-cert.pem"

	privMode := int32(0400)
	certMode := int32(0444)
	keyToPath, err := json.Marshal([]corev1.KeyToPath{
		{ Path: /*"tls/"+*/tlsPrivFile, Key: "tls.key", Mode: &privMode},
		{ Path: /*"tls/"+*/tlsCertFile, Key: "tls.crt", Mode: &certMode},
		{ Path: /*"msp/keystore/"+*/skiStr+"_sk", Key: "sign.key", Mode: &privMode},
	})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a slice of VolumeMount: %s", err)
		return
	}
	
	retErr = immutil.K8sAppendFilesOnSecret(host, &map[string][]byte{
		"sign.key": req.Priv,
		"keytopath": keyToPath,
	})
	if retErr != nil {
		return
	}

	// create a configmap
	caCert := s.parentCertPem
	mspID := svc.mspPrefix + org
	configYaml := s.createConfigYaml()
	
	configmapVolMount, err := json.Marshal([]corev1.VolumeMount{
		{ Name: "configmap-vol1", MountPath: svc.keyDir + "/msp/signcerts/"+host+"@"+mspID+"-cert.pem", SubPath: "signcert", }, // req.Cert
		{ Name: "configmap-vol1", MountPath: svc.keyDir + "/msp/cacerts/"+s.parentCert.Subject.CommonName+"-cert.pem", SubPath: "cacert", }, // caCert
		{ Name: "configmap-vol1", MountPath: svc.keyDir + "/msp/admincerts/"+userName+"@"+mspID+"-cert.pem", SubPath: "admincert", }, // req.Cred.Cert
		{ Name: "configmap-vol1", MountPath: svc.keyDir + "/msp/tlscacerts/"+tlsCACertFile, SubPath: "tlscacert", }, // tlsCACert
		{ Name: "configmap-vol1", MountPath: svc.keyDir + "/msp/config.yaml", SubPath: "config.yaml", }, // configYaml
	})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a slice of VolumeMount for a ConfigMap: %s", err)
		return
	}
	
	retErr = immutil.K8sStoreFilesOnConfig(host, &map[string]string{"config": svc.label}, 
		&map[string]string{
			"signcert": string(req.Cert),
			"cacert": string(caCert),
			"admincert": string(req.Cred.Cert),
			"tlscacert": string(tlsCACert),
			"config.yaml": string(configYaml),
			"volmount": string(configmapVolMount),
		}, nil)
	if retErr != nil {
		return
	}

	log.Printf("created a ConfigMap: %s\n", host)
	
	// create an enviroment
	retErr = svc.createEnv(host, org, tlsPrivFile, tlsCertFile, tlsCACertFile)
	
	return
}

func getVolMountList(name string) (tlsSecretPath, signKeyPath []corev1.KeyToPath, configVolMount []corev1.VolumeMount, retErr error) {
	keyToPathData, err := immutil.K8sReadFileInSecret(name, "keytopath")
	if err != nil {
		retErr = fmt.Errorf("unexpected secret: %s", err)
		return
	}
	
	var keyToPath []corev1.KeyToPath
	err = json.Unmarshal(keyToPathData, &keyToPath)
	if err != nil {
		retErr = fmt.Errorf("unexpected secret: %s", err)
		return
	}
	
	if len(keyToPath) != 3 {
		retErr = fmt.Errorf("unexpected data in a secret")
	}
	tlsSecretPath = keyToPath[0:2]
	signKeyPath = keyToPath[2:]
	
	
	volMountData, err := immutil.K8sReadFileInConfig(name, "volmount")
	if err != nil {
		retErr = fmt.Errorf("unexpected ConfigMap: %s", err)
		return
	}

	err = json.Unmarshal([]byte(volMountData), &configVolMount)
	if err != nil {
		retErr = fmt.Errorf("unexpected ConfigMap: %s", err)
		return
	}

	return // success
}


func (s *server) createOrderer(hostname, org, tlsPrivFile, tlsCertFile, tlsCAFile string) error {
	mspID := fabconf.OrdererMspIDPrefix + org
	port := storageGrpPortStr

	err := immutil.K8sStoreFilesOnConfig(hostname+"-env", &map[string]string{"app": "orderer"}, 
		&map[string]string{
			"ORDERER_GENERAL_LOGLEVEL": "DEBUG",
			"ORDERER_GENERAL_LISTENADDRESS": "0.0.0.0",
			"ORDERER_GENERAL_LISTENPORT": port,
			"ORDERER_GENERAL_GENESISMETHOD": "file",
			"ORDERER_GENERAL_GENESISFILE": ordererGenesisDir+"/"+ordererGenesisFile,
			"ORDERER_GENERAL_LOCALMSPID": mspID,
			"ORDERER_GENERAL_LOCALMSPDIR": ordererKeyDir+"/msp",
			"ORDERER_GENERAL_TLS_ENABLED": "true",
			"ORDERER_GENERAL_TLS_PRIVATEKEY": ordererKeyDir+"/tls/"+tlsPrivFile,
			"ORDERER_GENERAL_TLS_CERTIFICATE": ordererKeyDir+"/tls/"+tlsCertFile,
			"ORDERER_GENERAL_TLS_ROOTCAS": "["+ordererKeyDir+"/msp/tlscacerts/"+tlsCAFile+"]",
		}, nil )

	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for orderer enviriment variable: " + err.Error())
	}
	
	return nil
}

func startOrderer(serviceName string) (retErr error) {
	podPortName := strings.SplitN(serviceName, ":", 2)
	podName := podPortName[0]
	port := storageGrpPort

	tmpStrs := strings.SplitN(podName, ".", 2)
	shortName := tmpStrs[0]
	org := tmpStrs[1]
	podLabel := "app="+shortName 
	
	podState, stateVer, err := immutil.K8sGetPodState(podLabel, podName)
	if err != nil {
		retErr = err
		return
	}

	switch podState {
	case immutil.Ready:
		return
	case immutil.NotReady:
		return
	case immutil.NotExist:
		// nothing
	default:
		immutil.K8sDeleteDeploy(podName)
		immutil.K8sDeleteService(podName)
		podState, stateVer, _ = immutil.K8sGetPodState(podLabel, podName)
		if stateVer != immutil.NotExist {
			immutil.K8sWaitPodDeleted(stateVer, podLabel, podName)
		}
	}
	
	ordererEnv := []corev1.EnvFromSource{
		{ ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{ Name: podName+"-env",},},},
	}

	workVol, err := immutil.K8sGetOrgWorkVol(org)
	if err != nil {
		retErr = err
		return
	}

	pullRegAddr, err := immutil.GetPullRegistryAddr(org)
	if err == nil {
		pullRegAddr += "/"
	}
	
	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		retErr = err
		return
	}

	tlsSecretPath, signKeyPath, configVolMount, retErr := getVolMountList(podName)
	if retErr != nil {
		return
	}
	
	volumes := []corev1.Volume{
		{ Name: "data-vol", VolumeSource: *workVol,	},
		{ Name: "secret-tls", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: podName,
				Items: tlsSecretPath,
			}, }, },
		{ Name: "secret-signkey", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: podName,
				Items: signKeyPath,
			}, }, },						
		{ Name: "configmap-vol1", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: podName,
				}, }, }, },
	}
	
	volMount := append(configVolMount,
		corev1.VolumeMount{Name: "data-vol", MountPath: ordererDataDir, SubPath: podName+"/data", },
		corev1.VolumeMount{Name: "secret-tls", MountPath: ordererKeyDir+"/tls", },
		corev1.VolumeMount{Name: "secret-signkey", MountPath: ordererKeyDir+"/msp/keystore", },
		corev1.VolumeMount{Name: "configmap-vol1", MountPath: ordererGenesisDir+"/"+ordererGenesisFile, SubPath: ordererGenesisFile, },)
	
	repn := int32(1)
	ndots := "1"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:&repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string] string{
					"app": shortName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": shortName,
					},
					Name: podName,
				},
				Spec: corev1.PodSpec{
					Volumes: volumes,
					Hostname: shortName,
					Subdomain: immutil.K8sSubDomain,
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Containers: []corev1.Container{
						{
							Name: shortName,
							Image: pullRegAddr + immutil.OrdererImg,
							VolumeMounts: volMount,
							EnvFrom: ordererEnv,
							WorkingDir: ordererWorkingDir,
							Command: []string{"sh", "-c", ordererEpCmd+"&& orderer"},
							Ports: []corev1.ContainerPort{
								{
									Name: "grpc",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: int32(port),
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := deployClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("Could not create a container in a pod: %s\n", err)
	}
	log.Printf("Create deployment %q.\n", result.GetObjectMeta().GetName())

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
		immutil.K8sDeleteDeploy(deployment.Name)
	})
	
	// create a service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: shortName,
			Labels: map[string]string{
				"type": "storageGrp",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": shortName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port: int32(port),
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: int32(port),
					},
				},
			},
		},
	}

	serviceClient, err := immutil.K8sGetServiceClient()
	if err != nil {
		retErr = err
		return
	}
	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		retErr = err
		return
	}
	log.Printf("Create service %q.\n", resultSvc.GetObjectMeta().GetName())
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(service.Name)
	})

	retErr = immutil.K8sCreateIngressWithTLS(shortName, podName, org, storageGrpPort, "GRPCS",
		[]netv1.IngressTLS{{
			Hosts: []string{podName},
			SecretName: podName,
		}})
	if retErr != nil {
		return
	}

	return // success
}

func createPeer(hostname, org, tlsPrivFile, tlsCertFile, tlsCAFile string) error {
	mspID := fabconf.MspIDPrefix + org
	
	err := immutil.K8sStoreFilesOnConfig(hostname+"-env",	&map[string]string{"app": "peer"},
		&map[string]string{
			"CORE_VM_ENDPOINT": "tcp://localhost:2376",
			//"CORE_VM_DOCKER_TLS_ENABLED": "true",
			//"CORE_VM_DOCKER_TLS_CERT_FILE": "/certs/client/cert.pem",
			//"CORE_VM_DOCKER_TLS_KEY_FILE": "/certs/client/key.pem",
			//"CORE_VM_DOCKER_TLS_CA_FILE": "/certs/client/ca.pem",
			"CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE": "bridge", //netName
			//"CORE_LOGGING_LEVEL": "INFO",
			//"CORE_LOGGING_LEVEL": "DEBUG",
			"FABRIC_LOGGING_SPEC": "debug,shim=debug",
			"CORE_LOGGING_PEER": "debug",
			"CORE_CHAINCODE_LOGGING_LEVEL": "DEBUG",
			"CORE_CHAINCODE_LOGGING_SHIM": "DEBUG",
			"CORE_CHAINCODE_BUILDER": immutil.ContRuntimeImg,
			"CORE_CHAINCODE_GOLANG_RUNTIME": immutil.ContRuntimeImg,
			"CORE_PEER_CHAINCODELISTENADDRESS": "0.0.0.0:7052",
			"CORE_PEER_TLS_ENABLED": "true",
			"CORE_PEER_GOSSIP_USELEADERELECTION": "true",
			"CORE_PEER_GOSSIP_ORGLEADER": "false",
			"CORE_PEER_PROFILE_ENABLED": "true",
			"CORE_PEER_TLS_CERT_FILE": peerKeyDir+"/tls/"+tlsCertFile,
			"CORE_PEER_TLS_KEY_FILE": peerKeyDir+"/tls/"+tlsPrivFile,
			"CORE_PEER_TLS_ROOTCERT_FILE": peerKeyDir+"/msp/tlscacerts/"+tlsCAFile,
			"CORE_PEER_ID": hostname,
			//			"CORE_PEER_ADDRESS": "localhost:7051",
			//"CORE_PEER_ADDRESS": hostname+":7051",
			"CORE_PEER_ADDRESS": hostname+":"+storagePortStr,
			"CORE_PEER_LISTENADDRESS": "0.0.0.0:"+storagePortStr,
			"CORE_PEER_GOSSIP_BOOTSTRAP": "localhost:"+storagePortStr,
			//"CORE_PEER_GOSSIP_EXTERNALENDPOINT": "localhost:7051",
			//"CORE_PEER_GOSSIP_EXTERNALENDPOINT": hostname+":7051",
			"CORE_PEER_GOSSIP_EXTERNALENDPOINT": hostname+":"+storagePortStr,
			"CORE_PEER_LOCALMSPID": mspID,
			"CORE_PEER_LOCALMSPDIR": peerKeyDir+"/msp",
			"CORE_LEDGER_STATE_STATEDATABASE": "CouchDB",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS": "localhost:5984",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME": "",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD": "",
		}, nil)
	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for peer environment variable: " + err.Error())
	}
	
	err = immutil.K8sStoreFilesOnConfig(couchdbHostPrefix+hostname+"-env", &map[string]string{"app": "couchdb"},
		&map[string]string{
			"COUCHDB_USER": "",
			"COUCHDB_PASSWORD": "",
		}, nil)
	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for couchDB environment variable: " + err.Error())
	}	

	return nil // success
}

func startPeer(podName string) (state, resourceVersion string, retErr error) {
	tmpStrs := strings.SplitN(podName, ".", 2)
	shortName := tmpStrs[0]
	org := tmpStrs[1]
	
	podLabel := "app="+shortName
	podState, resourceVersion, retErr := immutil.K8sGetPodState(podLabel, podName)
	if retErr != nil {
		return
	}

	switch podState {
	case immutil.Ready:
		state = podState
		return
	case "Failed":
		retErr = immutil.K8sDeleteDeploy(podName)
		if retErr != nil {
			return
		}
		retErr = immutil.K8sDeleteService(podName)
		if retErr != nil {
			return
		}
		immutil.K8sWaitPodDeleted(resourceVersion, podLabel, podName)
	case immutil.NotReady:
		state = podState
		return
	case "Succeeded":
		state = podState
		return
	}
	state = immutil.NotReady


	// deploy a pod
	peerEnv := []corev1.EnvFromSource{
		{ ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{ Name: podName+"-env", }, }, },
	}
	couchDBEnv := []corev1.EnvFromSource{
		{ ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{ Name: couchdbHostPrefix+podName+"-env",},},},
	}

	workVol, retErr := immutil.K8sGetOrgWorkVol(org)
	if retErr != nil {
		return
	}

	pullRegAddr, err := immutil.GetPullRegistryAddr(org)
	if err == nil {
		pullRegAddr += "/"
	}
	
	deployClient, retErr := immutil.K8sGetDeploymentClient()
	if retErr != nil {
		return
	}

	tlsSecretPath, signKeyPath, configVolMount, retErr := getVolMountList(podName)
	if retErr != nil {
		return
	}
	
	volumes := []corev1.Volume{
		{ Name: "data-vol", VolumeSource: *workVol, },
		{ Name: "secret-tls", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: podName,
				Items: tlsSecretPath,
			}, }, },
		{ Name: "secret-signkey", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: podName,
				Items: signKeyPath,
			}, }, },
		{ Name: "secret-keys", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: podName,
			}, }, },
		{ Name: "configmap-vol1", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: podName,
				}, }, }, },
		{ Name: "plugin-config-vol", VolumeSource: corev1.VolumeSource{ EmptyDir: &corev1.EmptyDirVolumeSource{},},},		
	}
	
	storageVolMount := append(configVolMount,
		corev1.VolumeMount{Name: "data-vol", MountPath: peerDataDir, SubPath: podName+"/data", },
		corev1.VolumeMount{Name: "secret-tls", MountPath: peerKeyDir+"/tls", },
		corev1.VolumeMount{Name: "secret-signkey", MountPath: peerKeyDir+"/msp/keystore", }, )

	repn := int32(1)
	ndots := "1"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:&repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string] string{
					"app": shortName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": shortName,
					},
				},
				Spec: corev1.PodSpec{
					Volumes: volumes,
					Hostname: shortName,
					Subdomain: immutil.K8sSubDomain,
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					HostAliases: []corev1.HostAlias{
						{ IP: "127.0.0.1", Hostnames: []string{podName, }, },
					},
					Containers: []corev1.Container{
						{
							Name: couchdbHostPrefix+shortName,
							Image: pullRegAddr + immutil.CouchDBImg,
							EnvFrom: couchDBEnv,
							Ports: []corev1.ContainerPort{
								{
									Name: "db",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 5984,
								},
							},
						},
						{
							Name: shortName,
							Image: pullRegAddr + immutil.PeerImg,
							VolumeMounts: storageVolMount,
							EnvFrom: peerEnv,
							WorkingDir: peerWorkingDir,
							Command: []string{"sh", "-c", peerEpCmd+"&& env && peer node start"},
							Ports: []corev1.ContainerPort{
								{
									Name: "peer",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: storagePort,
								},
								{
									Name: "chaincode",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 7052,
								},

							},
						},
						{
							Name: "imm-pluginsrv",
							Image: pullRegAddr + immutil.ImmPluginSrvImg,
							Env: []corev1.EnvVar{
								{ Name: "IMMS_ORG", Value: org, },
								{ Name: "IMMS_POD_NAME", Value: podName, },
							},
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "plugin-config-vol", MountPath: "/var/lib/immconfig", },
							},
							Command: []string{"sh", "-c", "mkdir -p "+StorageGrpPermDir+" && /var/lib/immpluginsrv"},
							StartupProbe: &corev1.Probe{
								ProbeHandler:  corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{"test", "-S", pluginSock},
									},
								},
								InitialDelaySeconds: int32(5),
								PeriodSeconds: int32(3),
								FailureThreshold: int32(20),
							},
							ImagePullPolicy: corev1.PullAlways,
						},
						{
							Name: "grpcproxy",
							Image: pullRegAddr + immutil.ImmGRPCProxyImg,
							Env: []corev1.EnvVar{
								{ Name: "BACKEND_HOST", Value: "localhost:"+storagePortStr },
							},
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "secret-keys", MountPath: "/etc/keys/tls", },
								{ Name: "configmap-vol1", MountPath: "/etc/keys/certs/tlsca.crt", SubPath: "tlscacert" },
								{ Name: "configmap-vol1", MountPath: "/etc/keys/certs/sign.crt", SubPath: "signcert", },
							},
							Command: []string{"/var/lib/grpcProxy"},
							Ports: []corev1.ContainerPort{
								{
									Name: "grpcproxy",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: grpcProxyPort,
								},
							},
							ImagePullPolicy: corev1.PullAlways,
						},
					},
				},
			},
		},
	}

	createdDep, err := deployClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("Could not create a container in a pod: %s\n", err)
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
		immutil.K8sDeleteDeploy(deployment.Name)
	})

	// create services
	serviceClient, retErr := immutil.K8sGetServiceClient()
	if retErr != nil {
		return
	}
	
	svcCouchDB := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: couchdbHostPrefix+shortName,
			Labels: map[string]string{
				"app" : "couchdb",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": shortName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "db",
					Port: 5984,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 5984,
					},
				},
			},
		},
	}

	resultSvc, err := serviceClient.Create(context.TODO(), svcCouchDB, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a service for CouchDB: %s", err)
		return
	}
	log.Printf("Create a service: %q", resultSvc.GetObjectMeta().GetName())
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(svcCouchDB.Name)
	})
	
	svcStorage := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: shortName,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": shortName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "storage",
					Port: storagePort,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: storagePort,
					},
				},
			},
		},
	}

	resultSvc, err = serviceClient.Create(context.TODO(), svcStorage, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a service for a peer: %s", err)
		return
	}
	log.Printf("Create a service: %q\n", resultSvc.GetObjectMeta().GetName())
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(svcStorage.Name)
	})

	svcStorageExport := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: grpcProxySvcPrefix+shortName,
			Labels: map[string]string{
				"proxy": "grpc",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": shortName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "grpcproxy",
					Port: grpcProxyPort,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: grpcProxyPort,
					},
				},
			},
		},		
	}

	resultSvc, err = serviceClient.Create(context.TODO(), svcStorageExport, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a service for a peer: %s", err)
		return
	}
	log.Printf("Create a service: %q\n", resultSvc.GetObjectMeta().GetName())
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(svcStorageExport.Name)
	})
	
	retErr = immutil.K8sCreateIngressWithTLS(svcStorageExport.Name, podName, org, grpcProxyPort, "GRPC",
		[]netv1.IngressTLS{{
			Hosts: []string{podName},
			SecretName: podName,
		}})
	if retErr != nil {
		return
	}
	
	resourceVersion = createdDep.GetObjectMeta().GetResourceVersion()
	return // success
}

func createKeyPair(pubSubj *pkix.Name, caPrivPem, caCertPem []byte, dnsNames []string) (privPem, certPem []byte, skiStr string, retErr error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		retErr = fmt.Errorf("Failed to generate a private key: %s", err)
		return
	}

	privAsn1, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		retErr = fmt.Errorf("Failed to marshal an ecdsa private key into ASN.1 DEF format: %s", err)
		return
	}
	privPem = pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )

	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )
	skiStr = hex.EncodeToString(ski[:])

	// set certificate parameters
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	nowT := time.Now().UTC()
	certTempl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore: nowT,
		NotAfter: nowT.Add(365*10*24*time.Hour).UTC(),
		BasicConstraintsValid: true,
		IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		Subject: *pubSubj,
	}

	if certTempl.Subject.CommonName != "" {
		certTempl.DNSNames = append(certTempl.DNSNames, certTempl.Subject.CommonName)
	}
	if dnsNames != nil {
		certTempl.DNSNames = append(certTempl.DNSNames, dnsNames...)
	}

	certPem, retErr = immutil.CreateCertWithParameters(&privKey.PublicKey, pubSubj, caPrivPem, caCertPem, certTempl)
	if retErr != nil {
		return
	}
	return // success
}

func getPrivSki(privKey *ecdsa.PrivateKey) (privSki [sha256.Size]byte) {
	privSki = sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y) )
	return
}

func readCertificateFile(certPath string) (*x509.Certificate, error) {
	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("could not read " + certPath+ ": " + err.Error())
	}
	certData, _ := pem.Decode(certPem)
	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unexpected format " + certPath)
	}
	
	return cert, nil
}

func (s *server) ExportService(ctx context.Context, req *immop.ExportServiceRequest) (reply *immop.ExportServiceReply, retErr error) {
	reply = &immop.ExportServiceReply{}
	
	uCert, retErr := s.checkCredential("ExportService", req)
	if retErr != nil {
		return
	}
	
	if ! hasStorageAdmin(uCert) {
		retErr = fmt.Errorf("permission denied")
		return
	}

	secretName := req.Hostname
	caCert, retErr := immutil.K8sReadFileInConfig(secretName, "cacert")
	if retErr != nil {
		return
	}
	adminCert, retErr := immutil.K8sReadFileInConfig(secretName, "admincert")
	if retErr != nil {
		return
	}
	tlsCACert, retErr := immutil.K8sReadFileInConfig(secretName, "tlscacert")
	if retErr != nil {
		return
	}

	// success
	reply.CACert = []byte(caCert)
	reply.AdminCert = []byte(adminCert)
	reply.TlsCACert = []byte(tlsCACert)
	reply.Hostname = secretName
	reply.Port = storagePortStr
	return
}

func (s *server) ListService(ctx context.Context, req *immop.ListServiceRequest) (reply *immop.ListServiceReply, retErr error) {
	reply = &immop.ListServiceReply{}
	
	_, retErr = s.checkCredential("ListService", req)
	if retErr != nil {
		return
	}

	reply.Service, retErr = listService()
	return
}

func (s *server) CreateChannel(ctx context.Context, req *immop.CreateChannelRequest) (reply *immop.Reply, retErr error) {
	reply = &immop.Reply{}
	
	uCert, err := s.checkCredential("CreateChannel", req)
	if err != nil {
		retErr = err
		return
	}
	grpAdminHost := getGrpAdminHost(uCert)
	if grpAdminHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	ordererName := grpAdminHost

	anchorPeers, err := listImportedService(grpAdminHost) 
	if err != nil {
		retErr = err
		return
	}
	
	if req.ChannelID != grpAdminHost + "-ch" {
		retErr = fmt.Errorf("Requested channel ID is unexpected")
		return
	}

	port := storageGrpPortStr
	serviceName := ordererName+":"+port
	genesisBlock, err := fabconf.CreateGenesisBlock(req.ChannelID, serviceName, anchorPeers)
	if err != nil {
		retErr = fmt.Errorf("failed to create genesis block: %s", err)
		return
	}
	
	retErr = immutil.K8sAppendFilesOnConfig(ordererName, &map[string]string{"config": "storage-grp"}, nil,
		&map[string][]byte{ordererGenesisFile: genesisBlock})
	if retErr != nil {
		return
	}

	retErr = startOrderer(serviceName)
	if retErr != nil {
		return
	}

	return // success
}

func (s *server) ImportService(ctx context.Context, req *immop.ImportServiceRequest) (reply *immop.Reply, retErr error) {
	reply = &immop.Reply{}

	uCert, err := s.checkCredential("ImportService", req)
	if err != nil {
		retErr = err
		return
	}
	
	grpAdminHost := getGrpAdminHost(uCert)
	if grpAdminHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	certs := [][]byte{req.Service.CACert, req.Service.AdminCert, req.Service.TlsCACert,}
	for _, cert := range certs {
		_, _, err = immutil.ReadCertificate(cert)
		if err != nil {
			retErr = fmt.Errorf("failed to read a certificate: " + err.Error()) // invalid certificate
			return
		}
	}
		
	if req.Service.Hostname == "" {
		retErr = fmt.Errorf("Requested hostname is invalid")
		return
	}


	serviceData, err := proto.Marshal(req.Service)
	if err != nil {
		retErr = err
		return
	}	
	chName := grpAdminHost+"-ch"
	
	retErr = immutil.K8sAppendFilesOnConfig(chName, &map[string]string{"grpHost": grpAdminHost}, nil,
		&map[string][]byte{req.Service.Hostname+"."+req.Service.Port: serviceData})
	if retErr != nil {
		return
	}
		
	return // success
}

func (s *server) RemoveServiceFromCh(ctx context.Context, req *immop.RemoveServiceRequest) (reply *immop.Reply, retErr error) {
	reply = &immop.Reply{}

	uCert, err := s.checkCredential("RemoveServiceFromCh", req)
	if err != nil {
		retErr = err
		return
	}
	grpAdminHost := getGrpAdminHost(uCert)
	if grpAdminHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}

	chName := grpAdminHost+"-ch"
	key := req.Peer.Hostname + "." + req.Peer.Port
	err = immutil.K8sRemoveFilesOnConfig(chName, nil, []string{key})
	if err != nil {
		retErr = fmt.Errorf("failed to remove specified service: " + err.Error())
		return
	}

	return
}

func (s *server) ListImportedService(ctx context.Context, req *immop.ListImportedServiceRequest) (reply *immop.ListImportedServiceSummary, retErr error) {
	reply = &immop.ListImportedServiceSummary{}

	uCert, err := s.checkCredential("ListImportedService", req)
	if err != nil {
		retErr = err
		return
	}

	grpAdminHost := getGrpAdminHost(uCert)
	if grpAdminHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}

	peers, retErr := listImportedService(grpAdminHost)
	if retErr != nil {
		return
	}
	
	reply.Peer = make([]*immop.ServiceSummary, len(peers))
	for i, peer := range peers {
		reply.Peer[i] = &immop.ServiceSummary{Hostname: peer.Hostname, Port: peer.Port}
	}

	return
}

func listImportedService(grpAdminHost string) (peers []*immop.ExportServiceReply, retErr error) {
	peers = make([]*immop.ExportServiceReply, 0)

	confMapClient, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}
	
	chName := grpAdminHost+"-ch"
	chMap, err := confMapClient.Get(context.TODO(), chName, metav1.GetOptions{})
	if err != nil || chMap.BinaryData == nil {
		return // not found
	}

	for _, serviceData := range chMap.BinaryData {
		peer := &immop.ExportServiceReply{}
		err = proto.Unmarshal(serviceData, peer)
		if err != nil {
			continue
		}
		peers = append(peers, peer)
	}

	return
}

func listActiveService() (service []*immop.ServiceAttribute, retErr error) {
	listSvc := map[string] *struct{list []corev1.Pod; img string}{
		"orderer": {img: immutil.OrdererImg},
		"peer": {img: immutil.PeerImg},
	}
	listSvcN := 0
	for svcName, podList := range listSvc {
		list, err := immutil.K8sListPod("app="+svcName)
		if err != nil {
			retErr = fmt.Errorf("failed to get a list of "+svcName+": "+err.Error())
			return
		}
		podList.list = list.Items
		listSvcN += len(list.Items)
	}
	service = make([]*immop.ServiceAttribute, listSvcN)

	i := 0
	for svcName, podList := range listSvc {
		for _, pod := range podList.list {
			for _, cont := range pod.Spec.Containers {
				if cont.Image != podList.img {
					continue
				}
				
				serviceAttr := &immop.ServiceAttribute{}
				serviceAttr.Hostname = cont.Name
				serviceAttr.Type = svcName
				service[i] = serviceAttr
				i++
			}
		}
	}
	
	return
}

func listService() (service []*immop.ServiceAttribute, retErr error) {
	svcMap := map[string] *struct{list []corev1.ConfigMap; key string; testValue string}{
		"orderer": {key: "ORDERER_GENERAL_LOCALMSPDIR", testValue: ordererKeyDir+"/msp"},
		"peer": {key: "CORE_PEER_LOCALMSPDIR", testValue: peerKeyDir+"/msp"},
	}
	svcN := 0
	for svcName, configList := range svcMap {
		list, err := immutil.K8sListConfigMap("app="+svcName)
		if err != nil {
			retErr = fmt.Errorf("failed to get a list of "+svcName+": "+err.Error())
			return
		}
		configList.list = list.Items
		svcN += len(list.Items)
	}
	service = make([]*immop.ServiceAttribute, svcN)

	i := 0
	for svcName, confMap := range svcMap {
		for _, conf := range confMap.list {
			if conf.Data == nil {
				continue
			}
			
			item, ok := conf.Data[confMap.key]
			if !ok || item != confMap.testValue {
				continue
			}
			
			serviceAttr := &immop.ServiceAttribute{}
			serviceAttr.Hostname = strings.TrimSuffix(conf.ObjectMeta.Name, "-env")
			serviceAttr.Type = svcName
			service[i] = serviceAttr
			i++
		}
	}
	
	return
}

func getOrdererName() (string, error) {
	list, err := listService()
	if err != nil {
		return "", err
	}

	for _, ordererAttr := range list {
		if ordererAttr.Type == "orderer" {
			return ordererAttr.Hostname, nil
		}
	}

	return "", fmt.Errorf("There is no orderer service in this machine")
}

func getPeerName() (string, error) {
	list, err := listService()
	if err != nil {
		return "", err
	}

	for _, serviceAttr := range list {
		if serviceAttr.Type == "peer" {
			return serviceAttr.Hostname, nil
		}
	}

	return "", fmt.Errorf("There is no peer service in this machine")
}

func (s *server) ListChannelInPeer(ctx context.Context, req *immop.Credential) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	
	cert, retErr := s.checkCredential("ListChannelInPeer", req)
	if retErr != nil {
		return
	}
	storageHost := getStorageAdminHost(cert)
	if storageHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	
	invocation := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Name: "cscc"},
			Input: &pp.ChaincodeInput{
				Args: [][]byte{[]byte("GetChannels")},
			},
		},
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal ID: " + err.Error())
		return
	}

	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}

	signer, retErr := s.setSignatureCh("ListChannelInPeer", cert, "")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		listCh := &immop.ListChannelReply{}
		listCh.ChName = make([]string, 0)
		
		peerName := storageHost
		label := "app=" + strings.SplitN(peerName, ".", 2)[0]
		podState, _, err := immutil.K8sGetPodState(label,  peerName)
		if err != nil {
			signer.err <- err
			return
		}
		if podState != immutil.Ready {
			signer.rsp, err = proto.Marshal(listCh)
			signer.err <- err
			return
		}

		conn, err := connectPeerWithName(peerName)
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to peer: %s", err)
			return
		}
		defer conn.Close()

		cli := pp.NewEndorserClient(conn)
		propRsp, err := cli.ProcessProposal(context.Background(), &pp.SignedProposal{ProposalBytes: reply.Proposal, Signature: signature})
		if err != nil {
			signer.err <- fmt.Errorf("got error response: %s", err)
			return
		}

		if propRsp == nil {
			signer.err <- fmt.Errorf("nil proposal response")
			return
		}

		if propRsp.Response.Status != 0 && propRsp.Response.Status != 200 {
			signer.err <- fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
			return
		}

		chListRsp := &pp.ChannelQueryResponse{}
		err = proto.Unmarshal(propRsp.Response.Payload, chListRsp)
		if err != nil {
			signer.err <- fmt.Errorf("unexpected response: " + err.Error())
			return
		}

		for _, chID := range chListRsp.Channels {
			listCh.ChName = append(listCh.ChName, chID.ChannelId)
		}

		signer.rsp, err = proto.Marshal(listCh)
		signer.err <- err
		return
	}()
	
	return
}

func compareStorageGrpConf(chConf *channelConf) (retErr error) {
	storageGrp := strings.TrimSuffix(chConf.ChannelName, "-ch")
	curChConf, retErr := readChannelConf(storageGrp)
	if retErr != nil {
		return
	}

	if curChConf.OrdererTlsCACert != chConf.OrdererTlsCACert {
		retErr = fmt.Errorf("different configuration")
	}

	for org, storageHosts := range chConf.AnchorPeers {
		curStorageHosts, ok := curChConf.AnchorPeers[org]
		if !ok {
			retErr = fmt.Errorf("unknown organization: %s", org)
			return
		}

		for _, storageHost := range storageHosts {
			i := 0
			for ; i < len(curStorageHosts); i++ {
				if curStorageHosts[i]  == storageHost {
					break
				}
			}
			if i == len(curStorageHosts) {
				retErr = fmt.Errorf("unknown storage host: %s", storageHost)
				return
			}
		}
	}

	return // same configuration
}

func (s *server) ActivateChannel(ctx context.Context, req *immop.ActivateChannelReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	
	cert, retErr := s.checkCredential("ActivateChannel", req)
	if retErr != nil {
		return
	}
	storageHost := getStorageAdminHost(cert)
	if storageHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	
	invocation := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Name: "cscc"},
			Input: &pp.ChaincodeInput{
				Args: [][]byte{[]byte("GetConfigBlock"), []byte(req.ChannelID)},
			},
		},
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal ID: " + err.Error())
		return
	}

	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}

	signer, retErr := s.setSignatureCh("ActivateChannel", cert,"")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		peerName := storageHost
		label := "app=" + strings.SplitN(peerName, ".", 2)[0]
		
		podState, _, err := immutil.K8sGetPodState(label, peerName)
		if err != nil {
			signer.err <- err
			return
		}
		if podState != immutil.Ready {
			signer.err <- fmt.Errorf("Unexpected state")
			return
		}

		conn, err := connectPeerWithName(peerName)
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to peer: %s", err)
			return
		}
		defer conn.Close()

		cli := pp.NewEndorserClient(conn)
		propRsp, err := cli.ProcessProposal(context.Background(), &pp.SignedProposal{ProposalBytes: reply.Proposal, Signature: signature})
		if err != nil {
			signer.err <- fmt.Errorf("failed to get ConfigBlock")
			return
		}
		if propRsp == nil {
			signer.err <- fmt.Errorf("nil proposal response")
			return
		}
		
		if propRsp.Response.Status != 0 && propRsp.Response.Status != 200 {
			signer.err <- fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
			return
		}

		chConf, _, err := getConfigFromBlock(propRsp.Response.Payload)
		if err != nil {
			signer.err <- err
			return
		}

		err = compareStorageGrpConf(chConf)
		signer.err <- err
		return
	}()

	return
}

func encodeUint32(val uint32) ([]byte) {
	// little endian
	return []byte{byte(val&0xff), byte(val&0xff00>>8), byte(val&0xff0000>>16), byte(val&0xff000000>>24)}
}

func decodeUint32(data []byte) (uint32) {
	// little endian	
	return  uint32(data[0])|uint32(data[1])<<8|uint32(data[2])<<16|uint32(data[3])<<24
}

func (s *server) GetConfigBlock(ctx context.Context, req *immop.GetConfigBlockReq) (reply *immop.Block, retErr error) {
	reply = &immop.Block{}
	cert, err := s.checkCredential("GetConfigBlock", req)
	if err != nil {
		retErr = err
		return
	}
	grpHost := getGrpAdminHost(cert)
	if grpHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}

	genesisData, err:= immutil.K8sReadBinaryFileInConfig(grpHost, ordererGenesisFile)
	if err != nil {
		retErr = fmt.Errorf("could not get a genesis.block: " + err.Error())
		return
	}

	// read access permission
	exconfigStr, err := immutil.K8sReadFileInConfig(grpHost+"-ch", EXConfigName)
	if err != nil {
		exconfigStr = DefaultEXConfig
	}
	exconfig := []byte(exconfigStr)

	configData := encodeUint32(uint32(len(genesisData)))
	configData = append(configData, genesisData...)
	configData = append(configData, encodeUint32(uint32(len(exconfig)))...)
	configData = append(configData, exconfig...)
	
	reply.Body = configData

	return // success
}

func connectPeerWithName(peerName string) (*grpc.ClientConn, error) {
	tlsCACert, err := immutil.K8sReadFileInConfig(peerName, "tlscacert")
	if err != nil {
		return nil, err
	}
	return connectPeer(peerName+":"+storagePortStr, []byte(tlsCACert))
}

func connectPeer(peerAddr string, tlsCACert []byte) (*grpc.ClientConn, error) {
	cert, _, err := immutil.ReadCertificate(tlsCACert)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("did not connect to %s: %s", peerAddr, err)
	}

	return conn, nil	
}

func (s *server) JoinChannel(ctx context.Context, req *immop.PropReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("JoinChannel", req)
	if err != nil {
		retErr = err
		return
	}
	storageHost := getStorageAdminHost(cert)
	if storageHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org

	chConf, configBlock, err := getConfigFromBlock(req.Msg)
	if err != nil {
		retErr = err
		return
	}
	grpHost := chConf.OrdererHost

	spec := &pp.ChaincodeSpec{
		Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
		ChaincodeId: &pp.ChaincodeID{Name: "cscc"},
		Input: &pp.ChaincodeInput{
			Args: [][]byte{[]byte("JoinChain"), configBlock},
		},
	}
	
	invocation := &pp.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = err
		return
	}

	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("Error creating proposal for join %s", err)
		return
	}

	signer, retErr := s.setSignatureCh("JoinChannel", cert, grpHost)
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		var signature []byte
		peerName := storageHost
		signer, signature, err = s.waitPeerReady(signer, peerName)
		if err != nil {
			return
		}
		
		conn, err := connectPeerWithName(peerName)
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to peer: %s", err)
			return
		}
		defer conn.Close()

		cli := pp.NewEndorserClient(conn)
		var propRsp *pp.ProposalResponse
		for retryC := 0; retryC < 5; retryC++ {
			propRsp, err = cli.ProcessProposal(context.Background(), &pp.SignedProposal{ProposalBytes: reply.Proposal, Signature: signature})
			if err == nil {
				break // success
			}
			
			if gstatus.Code(err) == codes.Unavailable {
				time.Sleep(5*time.Second) // sleep 5s
				log.Printf("retry process proposal\n")
				continue // retry
			}

			// failure
			signer.err <- fmt.Errorf("got error response: %s", err)
			return
		}

		if propRsp == nil {
			signer.err <- fmt.Errorf("nil proposal response")
			return
		}

		if propRsp.Response.Status != 0 && propRsp.Response.Status != 200 {
			signer.err <- fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
			return
		}

		writeChannelConf(storageHost, chConf)

		log.Printf("Successfully submitted proposal to join channel\n")
		signer.err <- nil
		return
	}()

	return
}

func (s *server) waitPeerReady(signer *signerState, peerName string) (retSigner *signerState, signature []byte, retErr error) {
	peerState, ver, peerErr := startPeer(peerName)
	signature, err := signer.waitSignatureCh() // wait SendSignedProp request
	if err != nil {
		return nil, nil, err
	}
	if peerErr != nil {
		signer.err <- peerErr
		return nil, nil, peerErr
	}
	
	if peerState != immutil.NotReady {
		return signer, signature, nil
	}

	// not ready
	for retryC := 1; ; retryC++ {
		label := "app=" + strings.SplitN(peerName, ".", 2)[0]
		err = immutil.K8sWaitPodReady(ver, label, peerName)
		if err == nil {
			break// success
		}
		
		if err.Error() != immutil.NotReady {
			signer.err <- err
			return nil, nil, err
		}
		
		prevSigner := signer
		signer, err = s.setSignatureCh("RetryWaitPeerState_"+strconv.Itoa(retryC), signer.cert, signer.grpHost)
		if err != nil {
			prevSigner.err <- err
			return nil, nil, err
		}
		
		retryRsp := &immop.Reply{
			NotReadyF: true,
			TaskID: signer.taskID,
		}
		prevSigner.rsp, err = proto.Marshal(retryRsp)
		if err != nil {
			signer.signatureChDone()
			err = fmt.Errorf("failed to marshal a reply: %s", err)
			prevSigner.err <- err
			return nil, nil, err
		}
		
		prevSigner.err <- nil
		_, err = signer.waitSignatureCh()
		if err != nil {
			return nil, nil, err
		}
	}

	return signer, signature, nil // success
}

func readBlock(inB []byte) (block *common.Block, blockRaw []byte, retErr error) {
	if len(inB) < 4 {
		retErr = fmt.Errorf("unexpected block data")
		return
	}

	block = &common.Block{}
	blockSize := uint32(len(inB))
	for readP := uint32(0); len(inB) >= int(readP+blockSize); {
		blockRaw = inB[readP:readP+blockSize]
		err := proto.Unmarshal(blockRaw, block)
		if err == nil {
			return // success
		}

		fmt.Printf("%s\n", err)
		
		if readP == uint32(0) {
			readP = 4
			blockSize = uint32(inB[0])|uint32(inB[1])<<8|uint32(inB[2])<<16|uint32(inB[3])<<24
			continue // retry
		}
		retErr = fmt.Errorf("failed to unmarshal: " + err.Error())
		return // error
	}

	return
}

func getConfigFromBlock(blockRaw []byte) (chConf *channelConf, configBlock []byte, retErr error) {
	block, configBlock, retErr := readBlock(blockRaw)
	if retErr != nil {
		return
	}

	bEnvelope := &common.Envelope{}
	payload := &common.Payload{}
	confEnvelope := &common.ConfigEnvelope{}

	if len(block.Data.Data) <= 0 {
		retErr = fmt.Errorf("unexpected block")
		return
	}

	err := proto.Unmarshal(block.Data.Data[0], bEnvelope)
	if err != nil {
		retErr = err
		return
	}
	err = proto.Unmarshal(bEnvelope.Payload, payload)
	if err != nil {
		retErr = fmt.Errorf("unexpected block payload: " + err.Error())
		return
	}

	chHeader := &common.ChannelHeader{}
	err = proto.Unmarshal(payload.Header.ChannelHeader, chHeader)
	if err != nil {
		retErr = fmt.Errorf("could not get channel ID: " + err.Error())
		return
	}
	chID := chHeader.ChannelId

	err = proto.Unmarshal(payload.Data, confEnvelope)
	if err != nil {
		retErr = fmt.Errorf("unexpected config envelope: " + err.Error())
		return
	}

	chGr := confEnvelope.Config.ChannelGroup
	ordererAddr := &common.OrdererAddresses{}
	value, ok := chGr.Values[channelconfig.OrdererAddressesKey]
	if !ok {
		retErr = fmt.Errorf("could not get an address of orderer")
		return
	}
	err = proto.Unmarshal(value.Value, ordererAddr)
	if (err != nil) || (len(ordererAddr.Addresses) <= 0) {
		retErr = fmt.Errorf("could not get an address of orderer" + err.Error())
		return
	}

	ordererHost := ordererAddr.Addresses[0]

	ordererGr, ok := chGr.Groups[channelconfig.OrdererGroupKey]
	if !ok {
		retErr = fmt.Errorf("could not get orderer group key: " + err.Error())
		return
	}

	if len(ordererGr.Groups) <= 0 {
		retErr = fmt.Errorf("could not get orderer group")
		return
	}

	var gr *common.ConfigGroup
	for _, gr = range ordererGr.Groups {
		break
	}

	val, ok := gr.Values["MSP"]
	if !ok {
		retErr = fmt.Errorf("could not get certificates")
		return
	}
	mspConf := &msp.MSPConfig{}
	err = proto.Unmarshal(val.Value, mspConf)
	if err != nil {
		retErr = fmt.Errorf("could not get certificates: " + err.Error())
		return
	}
	fmspconfig := &msp.FabricMSPConfig{}
	err = proto.Unmarshal(mspConf.Config, fmspconfig)
	if err != nil {
		retErr = fmt.Errorf("could not get fabric MSP: " + err.Error())
		return
	}

	tlsCA := fmspconfig.TlsRootCerts[0]

	appGr, ok := chGr.Groups[channelconfig.ApplicationGroupKey]
	if !ok {
		retErr = fmt.Errorf("Application group was not found in this block")
		return
	}

	peers := make(map[string][]string)
	tlsCACerts := make(map[string]string)
	CACerts := make(map[string]string)
	clientOU := ""
	for orgName, gr := range appGr.Groups {
		value, ok := gr.Values[channelconfig.AnchorPeersKey]
		if !ok {
			continue
		}

		anchorPeers := &pp.AnchorPeers{}
		err = proto.Unmarshal(value.Value, anchorPeers)
		if err != nil {
			retErr = fmt.Errorf("failed to marshal peers: " + err.Error())
			return
		}

		if len(anchorPeers.AnchorPeers) < 1 {
			continue
		}

		for _, anchor := range anchorPeers.AnchorPeers {
			peers[orgName] = append(peers[orgName], fmt.Sprintf("%s:%d", anchor.Host, anchor.Port))
		}

		mspRaw, ok := gr.Values["MSP"]
		if !ok {
			continue
		}
		
		mspConf := &msp.MSPConfig{}
		err = proto.Unmarshal(mspRaw.Value, mspConf)
		if err != nil {
			retErr = fmt.Errorf("could not unmarshal MSPConfig: %s", err)
			return
		}

		fabricMspConf := &msp.FabricMSPConfig{}
		err = proto.Unmarshal(mspConf.Config, fabricMspConf)
		if err != nil {
			retErr = fmt.Errorf("could not unmarshal Fabirc MSPConfig: %s", err)
			return
		}
		
		tlsCACerts[orgName] = string(fabricMspConf.TlsRootCerts[0])
		CACerts[orgName] = string(fabricMspConf.RootCerts[0])
		if fabricMspConf.FabricNodeOus != nil && fabricMspConf.FabricNodeOus.ClientOuIdentifier != nil {
			clientOU = fabricMspConf.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier
		}
	}

	chConf = &channelConf{
		ChannelName: chID,
		OrdererHost: ordererHost,
		OrdererTlsCACert: string(tlsCA),
		AnchorPeers: peers,
		TlsCACerts: tlsCACerts,
		CACerts: CACerts,
		ClientOU: clientOU,
	}

	// set access permission for this storage group
	blockSize := len(configBlock)
	if blockSize == len(blockRaw) {
		chConf.AccessPermission = "0666" // all users can read and write blocks in this storage group
		return  // success
	}

	permData := blockRaw[4+blockSize:]
	if len(permData) < 4 {
		retErr = fmt.Errorf("unexpected format for access permission")
		return
	}

	permDataSize := decodeUint32(permData[:4])
	if permDataSize != uint32(22) {
		retErr = fmt.Errorf("unexpected data size (%d) for access permission", permDataSize)
		return
	}

	chConfExt := &channelConf{}
	err = yaml.Unmarshal(permData[4:], chConfExt)
	if err != nil {
		retErr = fmt.Errorf("failed to unmarshal a data: " + err.Error())
		return
	}
	chConf.AccessPermission = chConfExt.AccessPermission

	return // success
}

func (s *server) sendSignedPropInternal(funcName string, req *immop.PropReq) (*signerState, error) {
	_, err := s.checkCredential(funcName, req)
	if err != nil {
		return nil, err
	}

	signer, err := s.getSigner(req.TaskID)
	if err != nil {
		return nil, err
	}

	if atomic.CompareAndSwapInt32(&signer.state, 1, 2) == false {
		return nil, fmt.Errorf("unexpected state = %d", signer.state)
	}

	signer.signature <- req.Msg
	err = <- signer.err

	close(signer.signature)
	close(signer.err)
	signer.stateDesc = ""
	signer.state = 0

	delete(*signer.parent, signer.taskID)
	
	//	fmt.Printf("log: signedProp:\n%s\n", hex.Dump(req.Msg))
	return signer, err
}

func (s *server) SendSignedProp(ctx context.Context, req *immop.PropReq) (reply *immop.Reply, retErr error) {
	reply = &immop.Reply{}
	signer, retErr := s.sendSignedPropInternal("SendSignedProp", req)
	if retErr != nil {
		return
	}
	
	if signer.rsp != nil {
		retErr = proto.Unmarshal(signer.rsp, reply)
	}
	return
}

func (s *server) SendSignedPropAndRspDone(ctx context.Context, req *immop.PropReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	signer, retErr := s.sendSignedPropInternal("SendSignedPropAndRspDone", req)
	if signer != nil {
		reply.Proposal = signer.rsp
	}
	return
}

func (s *server) SendSignedPropAndRsp(ctx context.Context, req *immop.PropReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	signer, retErr := s.sendSignedPropAndRspInternal("SendSignedPropAndRsp", req)
	if signer != nil {
		reply.Proposal = signer.rsp
	}
	return
}

func (s *server) sendSignedPropAndRspInternal(funcName string, req *immop.PropReq) (*signerState, error) {
	_, err := s.checkCredential(funcName, req)
	if err != nil {
		return nil, err
	}

	signer, err := s.getSigner(req.TaskID)
	if err != nil {
		return nil, err
	}

	if atomic.CompareAndSwapInt32(&signer.state, 1, 4) == false {
		return nil, fmt.Errorf("unexpected state = %d", signer.state)
	}

	signer.signature <- req.Msg
	err = <- signer.err

	if err != nil {
		close(signer.signature)
		close(signer.err)
		signer.stateDesc = ""
		signer.state = 0
		delete(*signer.parent, signer.taskID)
	}else{
		signer.state = 1
	}

	return signer, err
}

func (s *server) SendSignedPropOrderer(ctx context.Context, req *immop.PropReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	signer, retErr := s.sendSignedPropAndRspInternal("SendSignedPropOrderer", req)
	if retErr != nil {
		return
	}
	
	if signer.rsp != nil {
		err := proto.Unmarshal(signer.rsp, reply)
		
		if retErr != nil {
			signer.signatureChDone()
			retErr = fmt.Errorf("failed to unmarshal a response: %s", err)
			return 
		}

		if reply.NotReadyF {
			signer.signatureChDone()
			return // need to retry
		}
	}

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		envelope := &common.Envelope{Payload: reply.Proposal, Signature: signature}

		if signer.grpHost == "" {
			signer.err <- fmt.Errorf("unexpected storage group hostname")
			return
		}
		chConf, err := readChannelConf(signer.grpHost)
		if err != nil {
			signer.err <- err
			return
		}

		caTlsCertRaw := []byte(chConf.OrdererTlsCACert)
		caTlsCert, _, err := immutil.ReadCertificate(caTlsCertRaw)
		if err != nil {
			signer.err <- fmt.Errorf("could not read a certificate: " + err.Error())
			return
		}
		certPool := x509.NewCertPool()
		certPool.AddCert(caTlsCert)
		creds := credentials.NewClientTLSFromCert(certPool, "")
		log.Printf("connect to %s\n", chConf.OrdererHost)
		conn, err := grpc.Dial(chConf.OrdererHost, grpc.WithTransportCredentials(creds), grpc.WithBlock())
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to orderer: %s", err)
			return
		}
		defer conn.Close()

		ordererClient, err := po.NewAtomicBroadcastClient(conn).Broadcast(context.TODO())
		if err != nil {
			signer.err <- fmt.Errorf("failed connecting to orderer service: %s", err)
			return
		}

		eventCh := make(chan error, 1)
		defer close(eventCh)
		err = signer.eventHandler(eventCh, chConf, req, envelope)
		if err != nil {
			if signer.state == 0 {
				return
			}
			
			signer.err <- err
			return
		}

		err = ordererClient.Send(envelope)
		err2 := <- eventCh
		if signer.state != 2 {
			log.Printf("unexpected state: %d\n", signer.state)
			return
		}

		if err != nil {
			signer.err <- fmt.Errorf("send error: %s", err)
			return
		}

		ordererRsp, err := ordererClient.Recv()
		if err != nil || ordererRsp.Status != common.Status_SUCCESS {
			log.Printf("failed to boradcast: status = %s err=%s\n", ordererRsp.Status.String(), err)
			ordererClient.CloseSend()
			signer.err <- err
			return
		}
		
		err = ordererClient.CloseSend()
		if err == nil {
			err = err2
		}
		signer.err <- err
		return
	}()

	return
}

func (signer *signerState) eventHandler(eventCh chan error, chConf *channelConf, req *immop.PropReq, envelopeOrderer *common.Envelope) (error) {
	if !req.WaitEventF {
		eventCh <- nil
		return nil
	}

	oPayload := &common.Payload{}
	err := proto.Unmarshal(envelopeOrderer.Payload, oPayload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal a payload: %s", err)
	}
	
	oChHeader := &common.ChannelHeader{}
	err = proto.Unmarshal(oPayload.Header.ChannelHeader, oChHeader)
	if err != nil {
		return fmt.Errorf("failed to unmarshal a header: %s", err)
	}
	TxId := oChHeader.TxId

	srvCert, _ := readCertificateFile(certPath)
	tlsSubj := &pkix.Name{
		Country: srvCert.Subject.Country,
		Organization: srvCert.Subject.Organization,
		Locality: srvCert.Subject.Locality,
		Province: srvCert.Subject.Province,
		CommonName: immutil.ImmsrvHostname + "." + srvCert.Subject.Organization[0],
	}
	privPem, certPem, _, err := immutil.GenerateKeyPair(tlsSubj, nil)
	tlsCert, err := tls.X509KeyPair(certPem, privPem)
	if err != nil {
		return  err
	}
	certHash := sha256.Sum256(tlsCert.Certificate[0])

/*
	creds :=  credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	})
*/

	payloadChHeader := &common.ChannelHeader{
		Type: int32(common.HeaderType_DELIVER_SEEK_INFO),
		Version: int32(0),
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos: 0,
		},
		ChannelId: chConf.ChannelName,
		Epoch: uint64(0),
	}
	payloadChHeader.TlsCertHash = certHash[:]
	payloadChHeaderRaw, err := proto.Marshal(payloadChHeader)
	if err != nil {
		return fmt.Errorf("failed to marshal Channel Header: %s", err)
	}

	seekInfo := &po.SeekInfo{
		Start: &po.SeekPosition{
			Type: &po.SeekPosition_Newest{Newest: &po.SeekNewest{}},
		},
		Stop: &po.SeekPosition{
			Type: &po.SeekPosition_Specified{Specified: &po.SeekSpecified{Number: math.MaxUint64}},
		},
		Behavior: po.SeekInfo_BLOCK_UNTIL_READY,
	}
	seekInfoRaw, err := proto.Marshal(seekInfo)
	if err != nil {
		return err
	}

	signatureHdr, err := fabconf.NewSignatureHeader(req.Cred.Cert, fabconf.MspIDPrefix)
	if err != nil {
		return err
	}

	header := &common.Header{
		ChannelHeader: payloadChHeaderRaw,
		SignatureHeader: signatureHdr,
	}
	payload := &common.Payload{
		Header: header,
		Data: seekInfoRaw,
	}
	payloadRaw, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not create a payload")
	}

	if signer.state != 4 {
		return fmt.Errorf("unexpected state: %d\n", signer.state)
	}

	signer.rsp = payloadRaw
	signer.err <- nil

	signature, err := signer.waitSignatureCh()
	if err != nil {
		return err
	}

	envl := &common.Envelope{Payload: payloadRaw, Signature: signature}


	org := signer.cert.Issuer.Organization[0]
	peers, ok := chConf.AnchorPeers[org]
	if !ok {
		return fmt.Errorf("unexpected organization %s\n", org)
	}
	tlsCACertStr, ok := chConf.TlsCACerts[org]
	if !ok {
		return fmt.Errorf("TLS CA cert for %s was not found\n", org)
	}
	tlsCACertRaw := []byte(tlsCACertStr)
	tlsCACert, _, err := immutil.ReadCertificate(tlsCACertRaw)
	if err != nil {
		return err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCACert)
	creds := credentials.NewClientTLSFromCert(certPool, "")
	
//	conn, err := grpc.Dial(peers[0], grpc.WithTransportCredentials(creds))
	conn, err := grpc.DialContext(context.Background(), peers[0], grpc.WithBlock(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("did not connect to peer: %s", err)
	}

	client := pp.NewDeliverClient(conn)
	stream, err := client.Deliver(context.Background())
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to make stream for DeliverClient: %s", err)
	}
	err = stream.Send(envl)
	if err != nil {
		conn.Close()
		return fmt.Errorf("could not send envelope: %s", err)
	}

	go func() {
		defer conn.Close()

		bEnvelope := &common.Envelope{}
		bPayload := &common.Payload{}
		chHdr := &common.ChannelHeader{}

		for {
			recv, err := stream.Recv()
			if err != nil {
				eventCh <- fmt.Errorf("could not receive a message for deliver client: " + err.Error())
				return
			}

			block := recv.GetBlock()
			if block == nil {
				continue
			}

			for _, blockData := range block.Data.Data {
				err = proto.Unmarshal(blockData, bEnvelope)
				if err != nil {
					continue
				}

				err = proto.Unmarshal(bEnvelope.Payload, bPayload)
				if err != nil {
					continue
				}

				err = proto.Unmarshal(bPayload.Header.ChannelHeader, chHdr)
				if err != nil {
					continue
				}

				if chHdr.TxId == TxId {
					log.Printf("got an event ( TxId=0x%x )\n", TxId)
					eventCh <- nil
					return
				}
			}
		}
		eventCh <- nil	
	}()

	return nil
}

func sendProcessProp(proposal, signature []byte, conn *grpc.ClientConn) (*pp.ProposalResponse, error) {
	defer conn.Close()
	
	cli := pp.NewEndorserClient(conn)
	propRsp, err := cli.ProcessProposal(context.Background(), &pp.SignedProposal{ProposalBytes: proposal, Signature: signature})
	if err != nil {
		return nil, fmt.Errorf("got error response: %s", err)
	}

	if propRsp == nil {
		return nil, fmt.Errorf("nil proposal response")
	}
	
	if propRsp.Response.Status != int32(common.Status_SUCCESS) {
		return nil, fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
	}
	
	log.Printf("Successfully submitted proposal\n")
	return propRsp, nil
}

func (s *server) InstallChainCode(ctx context.Context, req *immop.InstallCC) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("InstallChainCode", req)
	if err != nil {
		retErr = err
		return
	}
	storageHost := getStorageAdminHost(cert)
	if storageHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org

	if (req.Cds != nil) || (len(req.Cds) != 0) {
		retErr = fmt.Errorf("unsupported custom chaincode")
		return
	}
	codePkgRaw, err := os.ReadFile(chaincodePath)
	if err != nil {
		retErr = fmt.Errorf("could not read user chaincode")
		return
	}

	cds, err := proto.Marshal(&pp.ChaincodeDeploymentSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Path: "hlRsyslog/go", Name: defaultCCName, Version: "5.0"},
			Input: &pp.ChaincodeInput{},
		},
		CodePackage: codePkgRaw,
	})
	if err != nil {
		retErr = fmt.Errorf("failed to make a ChaincodeDeploymentSpec: %s", err)
		return
	}

	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to make a creator")
		return
	}

	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG,
			ChaincodeId: &pp.ChaincodeID{Name: "lscc"},
			Input: &pp.ChaincodeInput{Args: [][]byte{[]byte("install"), cds}},
		},
	}
	
	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, "", cis, creator)
	if err != nil {
		retErr = fmt.Errorf("could not create a proposal: %s", err)
		return
	}

	signer, retErr := s.setSignatureCh("InstallChainCode", cert, "")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		conn, err := connectPeerWithName(storageHost)
		if err != nil {
			signer.err <- err
			return
		}
		_, err = sendProcessProp(reply.Proposal, signature, conn)
		signer.err <- err
		return
	}()

	return
}

func (s *server) Instantiate(ctx context.Context, req *immop.InstantiateReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	
	cert, err := s.checkCredential("Instantiate", req)
	if err != nil {
		retErr = err
		return
	}
	storageHost := getStorageAdminHost(cert)
	if storageHost == "" {
		retErr = fmt.Errorf("permission denied")
		return
	}
	
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = err
		return
	}

	grpHost := strings.TrimSuffix(req.ChannelID, "-ch")
	chConf, err := readChannelConf(grpHost)
	if err != nil {
		retErr = err
		return
	}
	
	//	policyStr := req.Policy
	var policies []*common.SignaturePolicy
	var principals []*msp.MSPPrincipal
	memberN := len(chConf.CACerts)
	i := 0
	for orgName, _ := range chConf.CACerts {
		policies = append(policies, &common.SignaturePolicy{
			Type: &common.SignaturePolicy_SignedBy{
				SignedBy: int32(i),
			},
		})

		principal, err := proto.Marshal(&msp.MSPRole{MspIdentifier: fabconf.MspIDPrefix+orgName, Role: msp.MSPRole_MEMBER})
		if err != nil {
			retErr = err
			return
		}
		
		principals = append(principals, &msp.MSPPrincipal{
			PrincipalClassification: msp.MSPPrincipal_ROLE,
			Principal: principal,
		})
		i++
	}
	
	policy := &common.SignaturePolicyEnvelope{
		Version: 0,
		Identities: principals,
		Rule: &common.SignaturePolicy{
			Type: &common.SignaturePolicy_NOutOf_{
				NOutOf: &common.SignaturePolicy_NOutOf{
					N: int32(memberN),
					Rules: policies,
				},
			},
		},
	}
	
	policyRaw, err := proto.Marshal(policy)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal policy")
		return
	}

	var codePkgRaw []byte
	cds, err := proto.Marshal(&pp.ChaincodeDeploymentSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Path: "hlRsyslog/go", Name: defaultCCName, Version: "5.0"},
			Input: &pp.ChaincodeInput{},
		},
		CodePackage: codePkgRaw,
	})
	if err != nil {
		retErr = fmt.Errorf("failed to make a ChaincodeDeploymentSpec: %s", err)
		return
	}

	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG,
			ChaincodeId: &pp.ChaincodeID{Name: "lscc"},
			Input: &pp.ChaincodeInput{
				Args: [][]byte{[]byte("deploy"), []byte(chConf.ChannelName), cds, policyRaw, []byte("escc"), []byte("vscc")},
			},
		},
	}
	
	var proposal *pp.Proposal
	reply.Proposal, proposal, err = fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chConf.ChannelName, cis, creator)
	if err != nil {
		retErr = fmt.Errorf("error creating proposal: %s", err)
		return
	}

	signer, retErr := s.setSignatureCh("Instantiate", cert, grpHost)
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		conn, err := connectPeerWithName(storageHost)
		if err != nil {
			signer.err <- err
			return
		}

		var errCh chan error
		errCh = make(chan error, 1)
		var propRsp *pp.ProposalResponse
		go func() {
			var errRsp error
			propRsp, errRsp = sendProcessProp(reply.Proposal, signature, conn)
			errCh <- errRsp
		}()
		
		func() {
			for retryC := 1; ; retryC++ {
				select {
				case err = <- errCh:
					if err != nil {
						signer.err <- err
					}
					return
				case <- time.After(30 * time.Second):
					{
						prevSigner := signer
						signer, err = s.setSignatureCh("Instantiate:Retry"+strconv.Itoa(retryC), cert, grpHost)
						if err != nil {
							prevSigner.err <- err
							return
						}

						retryRsp := &immop.Prop{
							NotReadyF: true,
							TaskID: signer.taskID,
						}
						prevSigner.rsp, err = proto.Marshal(retryRsp)
						if err != nil {
							prevSigner.err <- fmt.Errorf("failed to marshal a reply")
							signer.signatureChDone()
							return
						}
						prevSigner.err <- nil

						_, err = signer.waitSignatureCh()
						if err != nil {
							return
						}
					}
				}
			}
		}()
		if err != nil {
			return
		}
					

		endorsements := make([]*pp.Endorsement, 1)
		endorsements[0] = propRsp.Endorsement
		
		hdr := &common.Header{}
		err = proto.Unmarshal(proposal.Header, hdr)
		if err != nil {
			signer.err <- fmt.Errorf("could not get a header: " + err.Error())
			return
		}

		chPropPayload := &pp.ChaincodeProposalPayload{}
		err = proto.Unmarshal(proposal.Payload, chPropPayload)
		if err != nil {
			signer.err <- fmt.Errorf("could not get channel proposal payload: " + err.Error())
			return
		}

		cea := &pp.ChaincodeEndorsedAction{ProposalResponsePayload: propRsp.Payload, Endorsements: endorsements}
		propPayloadBytes, err := proto.Marshal(&pp.ChaincodeProposalPayload{Input: chPropPayload.Input,})
		if err != nil {
			signer.err <- err
			return
		}

		cap := &pp.ChaincodeActionPayload{ChaincodeProposalPayload: propPayloadBytes, Action: cea}
		capBytes, err := proto.Marshal(cap)
		if err != nil {
			signer.err <- err
			return
		}

		tranAction := &pp.TransactionAction{Header: hdr.SignatureHeader, Payload: capBytes}
		tranActions := make([]*pp.TransactionAction, 1)
		tranActions[0] = tranAction
		tx := &pp.Transaction{Actions: tranActions}
		
		txRaw, err := proto.Marshal(tx)
		if err != nil {
			signer.err <- err
			return
		}
		payload := &common.Payload{Header: hdr, Data: txRaw}
		payloadRaw, err := proto.Marshal(payload)
		if err != nil {
			signer.err <- err
			return
		}
		
		signer.rsp, err = proto.Marshal(&immop.Prop{Proposal: payloadRaw})
		if err != nil {
			signer.err <- fmt.Errorf("failed to marshal a payload: %s", err)
			return
		}
		signer.err <- nil
		return
	}()

	return
}

func (s *server) ListChainCode(ctx context.Context, req *immop.ListChainCodeReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("ListChainCode", req)
	if err != nil {
		retErr = err
		return
	}
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org

	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to create an identity: " + err.Error())
		return
	}

	spec := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG,
			ChaincodeId: &pp.ChaincodeID{Name: "lscc"},
		},
	}
	peerName := ""
	chName := ""
	var tlsCACert string
	
	if req.Option == "installed" {
		spec.ChaincodeSpec.Input = &pp.ChaincodeInput{Args: [][]byte{[]byte("getinstalledchaincodes")}}
		
		peerName = getStorageAdminHost(cert)
		if peerName == "" {
			retErr = fmt.Errorf("storage host was not determined")
			return
		}
		tlsCACert, retErr = immutil.K8sReadFileInConfig(peerName, "tlscacert")
		if retErr != nil {
			return
		}

		peerName += ":"+storagePortStr
	} else if strings.HasPrefix(req.Option, "enabled:"){
		spec.ChaincodeSpec.Input = &pp.ChaincodeInput{Args: [][]byte{[]byte("getchaincodes")}}
		
		chName = strings.TrimPrefix(req.Option, "enabled:")
		grpHost := strings.TrimSuffix(chName, "-ch")
		chConf, err := readChannelConf(grpHost)
		if err != nil {
			retErr = err
			return
		}
		peers, ok := chConf.AnchorPeers[org]
		if !ok {
			retErr = fmt.Errorf("not found")
			return
		}
		peerName = peers[0]

		tlsCACert, ok = chConf.TlsCACerts[org]
		if !ok {
			retErr = fmt.Errorf("CA certificate is not found")
			return
		}
	} else {
		retErr = fmt.Errorf("invalid option")
		return
	}

	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chName, spec, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}

	signer, retErr := s.setSignatureCh("ListChainCode", cert, "")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID
	
	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		conn, err := connectPeer(peerName, []byte(tlsCACert))
		if err != nil {
			signer.err <- err
			return
		}
		propRsp, err := sendProcessProp(reply.Proposal, signature, conn)
		if err != nil {
			signer.err <- err
			return
		}

		log.Printf("payload:\n%s\n", hex.Dump(propRsp.Payload))
		log.Printf("response.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))

		queryRsp := &pp.ChaincodeQueryResponse{}
		err = proto.Unmarshal(propRsp.Response.Payload, queryRsp)
		if err != nil {
			signer.err <- fmt.Errorf("unexpected response: " + err.Error())
			return
		}
		
		listRsp := &immop.ListChainCodeReply{}
		listRsp.CodeName = make([]string, 0)
		for _, ccInfo := range queryRsp.Chaincodes {
			listRsp.CodeName = append(listRsp.CodeName, ccInfo.Name)
		}
		signer.rsp, err = proto.Marshal(listRsp)
		signer.err <- err
		return
	}()

	return
}

func writeChannelConf(storageHost string, chConf *channelConf) error {
	confData, err := yaml.Marshal(chConf)
	if err != nil {
		return fmt.Errorf("invalid configuration for storage group: %s", err)
	}
	
	confMapName := storageHost+"-ch"
	err = immutil.K8sAppendFilesOnConfig(confMapName, &map[string]string{"config": "channel"}, nil,
		&map[string][]byte{chConf.ChannelName: confData})
	if err != nil {
		return err
	}

	err = writeChannelPerm(storageHost, chConf)
	if err != nil {
		return err
	}
	
	return nil // success
}

func writeChannelPerm(storageHost string, chConf *channelConf) (retErr error) {
	permBuf := bytes.NewBuffer([]byte(chConf.AccessPermission))
	permFile := strings.TrimSuffix(chConf.ChannelName, "-ch")
	svcName := strings.SplitN(storageHost, ".", 2)[0]

	podName, retErr := immutil.K8sWaitPodReadyAndGetPodName("app="+svcName, storageHost)
	if retErr != nil {
		return
	}
	
	retErr = immutil.K8sExecCmd(podName, "imm-pluginsrv",
		[]string{"sh", "-c", "tee "+StorageGrpPermDir+permFile}, permBuf, nil, nil)
	if retErr != nil {
		return
	}

	return // success
}

func readChannelConf(grpHost string) (*channelConf, error){
	list, err := immutil.K8sListConfigMap("config=channel")
	if err != nil {
		return nil, fmt.Errorf("There is no ConfigMap for channel on this machine: " + err.Error())
	}

	var chConfData  []byte
	var ok bool
	chName := grpHost+"-ch"
	for _, chMap := range list.Items {
		if chMap.BinaryData == nil {
			continue
		}
		
		chConfData, ok = chMap.BinaryData[chName]
		if ok {
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("Storage group was not found")
	}
	
	chConf := &channelConf{}
	err = yaml.Unmarshal(chConfData, chConf)	
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal a configuration for channel" + err.Error())
	}

	return chConf, nil
}

func (s *server) ListChannelInMyOU(ctx context.Context, req *immop.Credential) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	
	cert, retErr := s.checkCredential("ListChannelInMyOU", req)
	if retErr != nil {
		return
	}

	list, err := immutil.K8sListConfigMap("config=channel")
	if err != nil {
		retErr = fmt.Errorf("There is no ConfigMap for channel on this machine: " + err.Error())
		return
	}

	listCh := &immop.ListChannelReply{}
	listCh.ChName = make([]string, 0)
	for _, chMap := range list.Items {
		if chMap.BinaryData == nil {
			continue
		}
		
		for chName, chConfData := range chMap.BinaryData {
			chConf := &channelConf{}
			err = yaml.Unmarshal(chConfData, chConf)
			if err != nil {
				continue
			}

			chOU := chConf.ClientOU
			for _, ou := range cert.Subject.OrganizationalUnit {
				ou = strings.TrimPrefix(ou, "client:")
				if ou != chOU {
					continue
				}

				listCh.ChName = append(listCh.ChName, chName)
				break
			}
		}
	}

	reply.Proposal, retErr = proto.Marshal(listCh)
	return
}

func (s *server) RecordLedger(ctx context.Context, req *immop.RecordLedgerReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("RecordLedger", req)
	if err != nil {
		retErr = err
		return
	}
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	creator := &msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert}
	creatorData, err := proto.Marshal(creator)
	if err != nil {
		retErr = fmt.Errorf("failed to make a creator")
		return
	}

	chConf, err := readChannelConf(req.StorageGroup)
	if err != nil {
		retErr = err
		return
	}

	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: defaultCCName},
			Input: &pp.ChaincodeInput{Args: [][]byte{[]byte("addLog"), []byte(req.Key), []byte(req.Format), []byte(req.Log)}},
		},
	}

	var proposal *pp.Proposal
	reply.Proposal, proposal, err = fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chConf.ChannelName, cis, creatorData)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: %s", err)
		return
	}
	
	signer, retErr := s.setSignatureCh("RecordLedger", cert, req.StorageGroup)
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		var wg sync.WaitGroup
		i := 0
		propRsps := make([]*pp.ProposalResponse, len(chConf.AnchorPeers))
		errRsps := make([]error, len(chConf.AnchorPeers))
		for org, peers := range chConf.AnchorPeers {
			tlsCACert, ok := chConf.TlsCACerts[org]
			if !ok {
				continue
			}

			conn, err := connectPeer(peers[0], []byte(tlsCACert))
			if err != nil {
				errRsps[i] = err
				break
			}

			wg.Add(1)
			go func(peerConn *grpc.ClientConn, propRsp **pp.ProposalResponse, err *error) {
				defer wg.Done()
				*propRsp, *err = sendProcessProp(reply.Proposal, signature, peerConn)
				
				if *err != nil {
					return
				}
                                                                                     
				if (*propRsp).Response.Status < int32(common.Status_SUCCESS) || (*propRsp).Response.Status >= int32(common.Status_BAD_REQUEST) {
					*err = fmt.Errorf("bad proposal response %d: %s", (*propRsp).Response.Status, (*propRsp).Response.Message)
				}
			}(conn, &propRsps[i], &errRsps[i])
			i++
		}

		wg.Wait()

		for j, errRsp := range errRsps {
			if errRsp != nil {
				signer.err <- errRsp
				return
			}

			if !bytes.Equal(propRsps[0].Payload, propRsps[j].Payload) ||
				!bytes.Equal(propRsps[0].Response.Payload, propRsps[j].Response.Payload) {
				signer.err <- fmt.Errorf("payload do not match")
				return
			}

			err = chConf.verifyEndorser(propRsps[j])
			if err != nil {
				signer.err <- err
				return
			}
		}

		transPayload, err := createTransactionPayload(proposal, propRsps)
		if err != nil {
			signer.err <- fmt.Errorf("failed to create a transaction payload: " + err.Error())
			return
		}
		signer.rsp, err = proto.Marshal(&immop.Prop{Proposal: transPayload})
		signer.err <- err
		return
	}()

	return
}

func (chConf *channelConf) verifyEndorser(propRsp *pp.ProposalResponse) error {
	endorser := &msp.SerializedIdentity{}
	err := proto.Unmarshal(propRsp.Endorsement.Endorser, endorser)
	if err != nil {
		return fmt.Errorf("could not get endorser: %s", err)
	}
	
	endorserCert, _, err := immutil.ReadCertificate(endorser.IdBytes)
	if err != nil {
		return fmt.Errorf("failed to read a certificate of an endorser: " + err.Error())
	}
	
	if time.Now().UTC().Before(endorserCert.NotBefore) {
		return fmt.Errorf("This certificate of an endorser is not vaild until later date")
	}
	if time.Now().UTC().After(endorserCert.NotAfter) {
		return fmt.Errorf("This certificate of an endorser has expired")
	}
	
	if len(endorserCert.Issuer.Organization) < 1 {
		return fmt.Errorf("This certificate does not belong to any organization")
	}
	
	org := endorserCert.Issuer.Organization[0]
	
	CACertStr, ok := chConf.CACerts[org]
	if !ok {
		return fmt.Errorf("There is no CA certificate for %s in current config-block", org)
	}

	caRoots := x509.NewCertPool()
	ok = caRoots.AppendCertsFromPEM([]byte(CACertStr))
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}
	verifyOpts := x509.VerifyOptions{
		Roots: caRoots,
	}
	
	_, err = endorserCert.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("failed to verify certificate: " + err.Error())
	}

	sign := &ECDSASignature{}
	asn1.Unmarshal(propRsp.Endorsement.Signature, sign)
	msg := append(propRsp.Payload, propRsp.Endorsement.Endorser...)
	digest := sha256.Sum256(msg)
	ok = ecdsa.Verify(endorserCert.PublicKey.(*ecdsa.PublicKey), digest[:], sign.R, sign.S)
	if !ok {
		return fmt.Errorf("unexpected endorser")
	}

	return nil
}

func createTransactionPayload(proposal *pp.Proposal, propRsps []*pp.ProposalResponse) ([]byte, error) {
	hdr := &common.Header{}
	err := proto.Unmarshal(proposal.Header, hdr)
	if err != nil {
		return nil, fmt.Errorf("could not get a header: " + err.Error())
	}

	chPropPayload := &pp.ChaincodeProposalPayload{}
	err = proto.Unmarshal(proposal.Payload, chPropPayload)
	if err != nil {
		return nil, fmt.Errorf("could not get channel proposal payload: " + err.Error())
	}

	endorsements := make([]*pp.Endorsement, len(propRsps))
	for i, propRsp := range propRsps {
		endorsements[i] = propRsp.Endorsement
	}

	cea := &pp.ChaincodeEndorsedAction{ProposalResponsePayload: propRsps[0].Payload, Endorsements: endorsements}
	propPayloadBytes, err := proto.Marshal(&pp.ChaincodeProposalPayload{Input: chPropPayload.Input,})
	if err != nil {
		return nil, err
	}
	
	cap := &pp.ChaincodeActionPayload{ChaincodeProposalPayload: propPayloadBytes, Action: cea}
	capBytes, err := proto.Marshal(cap)
	if err != nil {
		return nil, err
	}
	
	tranAction := &pp.TransactionAction{Header: hdr.SignatureHeader, Payload: capBytes}
	tranActions := make([]*pp.TransactionAction, 1)
	tranActions[0] = tranAction
	tx := &pp.Transaction{Actions: tranActions}

	txRaw, err := proto.Marshal(tx)
	if err != nil {
		return nil, err
	}
	payload := &common.Payload{Header: hdr, Data: txRaw}
	payloadRaw, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return payloadRaw, nil
}


func createChaincodeProposal(creator *msp.SerializedIdentity, chName, ccName string, inputs *[][]byte) ([]byte, error) {
	creatorData, err := proto.Marshal(creator)
	if err != nil {
		return nil, fmt.Errorf("failed to make a creator")
	}

	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: ccName},
			Input: &pp.ChaincodeInput{Args: *inputs},
		},
	}

	proposal, _, err := fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chName, cis, creatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to create a proposal: %s", err)
	}

	return proposal, nil
}

func (s *server) ReadLedger(ctx context.Context, req *immop.ReadLedgerReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("ReadLedger", req)
	if err != nil {
		retErr = err
		return
	}
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	creator := &msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert}
	creatorData, err := proto.Marshal(creator)
	if err != nil {
		retErr = fmt.Errorf("failed to make a creator")
		return
	}

	chConf, err := readChannelConf(req.StorageGroup)
	if err != nil {
		retErr = err
		return
	}

	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: defaultCCName},
			Input: &pp.ChaincodeInput{Args: [][]byte{[]byte("getLog"), []byte(req.Key) }},
		},
	}
	if req.Option != "" {
		cis.ChaincodeSpec.Input = &pp.ChaincodeInput{Args: [][]byte{[]byte("getLog"), []byte(req.Key), []byte(req.Option) }}
	}

	reply.Proposal, _, err = fabconf.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chConf.ChannelName, cis, creatorData)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: %s", err)
		return
	}
	
	signer, retErr := s.setSignatureCh("ReadLedger", cert, "")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		peers, ok := chConf.AnchorPeers[org]
		tlsCACert, ok2 := chConf.TlsCACerts[org]
		if !ok || !ok2 {
			signer.err <- fmt.Errorf("unexpected organization %s", org)
			return
		}
		
		conn, err := connectPeer(peers[0], []byte(tlsCACert))
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to %s", peers[0])
			return
		}

		propRsp, err := sendProcessProp(reply.Proposal, signature, conn)
		if err != nil {
			signer.err <- err
			return
		}

		if propRsp.Response.Status < int32(common.Status_SUCCESS) || propRsp.Response.Status >= int32(common.Status_BAD_REQUEST) {
			signer.err <- fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
			return
		}

		err = chConf.verifyEndorser(propRsp)
		if err != nil {
			signer.err <- err
			return
		}

		signer.rsp = propRsp.Response.Payload
		//fmt.Printf("log: ReadLedger: payload:\n%s\n", hex.Dump(signer.rsp))
		//fmt.Printf("log: ReadLedger: reponse.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))
		signer.err <- nil
		return
	}()

	return
}

func (s *server) QueryBlockByTxID(ctx context.Context, req *immop.QueryBlockByTxIDReq) (reply *immop.Prop, retErr error) {
	reply = &immop.Prop{}
	cert, err := s.checkCredential("QueryBlockByTxID", req)
	if err != nil {
		retErr = err
		return
	}
	if len(cert.Issuer.Organization) < 1 {
		retErr = fmt.Errorf("unexpected user")
		return
	}
	org := cert.Issuer.Organization[0]
	mspId := fabconf.MspIDPrefix + org
	creator := msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert}

	chConf, err := readChannelConf(req.StorageGroup)
	if err != nil {
		retErr = err
		return
	}

	reply.Proposal, err = createChaincodeProposal(&creator, chConf.ChannelName, "qscc",
		&[][]byte{[]byte("GetBlockByTxID"), []byte(chConf.ChannelName), []byte(req.TxID)})
	if err != nil {
		retErr = err
		return
	}

	signer, retErr := s.setSignatureCh("QueryBlockByTxID", cert, "")
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}

		peers, ok := chConf.AnchorPeers[org]
		tlsCACert, ok2 := chConf.TlsCACerts[org]
		if !ok || !ok2 {
			signer.err <- fmt.Errorf("unexpected organization %s", org)
			return
		}
		
		conn, err := connectPeer(peers[0], []byte(tlsCACert))
		if err != nil {
			signer.err <- fmt.Errorf("could not connect to %s", peers[0])
			return
		}

		propRsp, err := sendProcessProp(reply.Proposal, signature, conn)
		if err != nil {
			signer.err <- err
			return
		}

		if propRsp.Response.Status < int32(common.Status_SUCCESS) || propRsp.Response.Status >= int32(common.Status_BAD_REQUEST) {
			signer.err <- fmt.Errorf("bad proposal response %d: %s", propRsp.Response.Status, propRsp.Response.Message)
			return
		}

		err = chConf.verifyEndorser(propRsp)
		if err != nil {
			signer.err <- err
			return
		}

		signer.rsp = propRsp.Response.Payload
		//fmt.Printf("log: QueryBlockByTxID: payload:\n%s\n", hex.Dump(signer.rsp))
		//fmt.Printf("log: QueryBlockByTxID: reponse.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))
		signer.err <- nil
		return
	}()

	return
}

func (s *server) RegisterUser(ctx context.Context, req *immop.RegisterUserRequest) (reply *immop.Reply, retErr error) {
	reply = &immop.Reply{}
	cert, retErr := s.checkCredential("RegisterUser", req)
	if retErr != nil {
		return
	}

	caCommonName := s.parentCert.Subject.CommonName
	if caCommonName != cert.Issuer.CommonName {
		retErr = fmt.Errorf("invalid certificate")
		return
	}

	caPriv, caCert, retErr := immutil.K8sGetKeyPair(caCommonName)
	if retErr != nil {
		return
	}

	tmpPriv, tmpCert, retErr := immutil.CreateTemporaryCert(cert, caPriv, caCert)
	if retErr != nil {
		return
	}

	var adminCert []byte
	caCli := cacli.NewCAClient("https://"+caCommonName+cacli.DefaultPort)
	switch req.AuthType {
	case "LDAP":
		adminCert, retErr = registerLDAPAdmin(caCli, tmpPriv, tmpCert, req)
	case "JPKI":
		adminCert, retErr = registerJPKIAdmin(caCli, tmpPriv, tmpCert, req)
	case "OAUTH_GRAPH":
		adminCert, retErr = registerOAuthAdmin(caCli, tmpPriv, tmpCert, req)
	default:
		retErr = fmt.Errorf("unknown authentication type: %s", req.AuthType)
	}
	if retErr != nil {
		return
	}
	
	retErr = immutil.StoreCertID(adminCert, req.AuthType)
	return
}

func (s *server) EnrollUser(ctx context.Context, req *immop.EnrollUserRequest) (reply *immop.EnrollUserReply, retErr error) {
	reply = &immop.EnrollUserReply{}

	enrollReq := &immclient.EnrollmentRequestNet{}
	err := json.Unmarshal(req.EnrollReq, enrollReq)
	if err != nil {
		retErr = fmt.Errorf("invalid request: %s\n", err)
		return
	}

	csrPem := []byte(enrollReq.SignRequest.Request)
	csrRaw, _ := pem.Decode(csrPem)
	if csrRaw.Type != "CERTIFICATE REQUEST" {
		retErr = fmt.Errorf("invalid request type")
		return
	}
	csr, err := x509.ParseCertificateRequest(csrRaw.Bytes)
	if err != nil {
		retErr = fmt.Errorf("invalid certificate request: %s\n", err)
		return
	}

	username := csr.Subject.CommonName
	caName := s.parentCert.Subject.CommonName
	caCli := cacli.NewCAClient("https://"+caName+cacli.DefaultPort)

	adminID, authType, err := immutil.GetAdminID(username, caName)
	if err != nil || strings.HasPrefix(authType, authCAPrefix) {
		// request to CA
		reply.Cert, retErr = caCli.EnrollCAUser(username, req.Secret, enrollReq)
		return
	}
	adminUser := &immclient.UserID{Name: adminID.Name, Priv: adminID.Priv, Cert: adminID.Cert, Client: caCli, }
	
	// Enrolling user is federated user
	retErr = authenticateFedUser(adminUser, authType, username, req.Secret)
	if retErr != nil {
		return // authentication failure
	}
	// authentication success

	if adminUser.Name == username {
		reply.Cert, retErr = caCli.ReenrollCAUser(adminUser, enrollReq)
		return
	}

	// register and enroll user
	userType := "client"
	userAttrs := &[]immclient.Attribute{}
	if isVoterReg(adminUser, caCli.UrlBase) {
		userType, userAttrs = ballotGetUserTypeAndAttr()
	}
	reply.Cert, retErr = caCli.RegisterAndEnrollUser(adminUser, userType, username, userAttrs, enrollReq)
	return
}

func authenticateFedUser(adminID *immclient.UserID, authType, username, secret string) (retErr error) {
	if strings.HasPrefix(authType, authLDAPPrefix) {
		retErr = authenticateLDAPUser(adminID, authType, username, secret)
		return
	}
	if strings.HasPrefix(authType, authJPKIPrefix) {
		retErr = fmt.Errorf("unsupported authentication type ")
		return
	}
	if strings.HasPrefix(authType, authOAuthPrefix) {
		retErr = authenticateOAuthUser(adminID, authType, username, secret)
		return
	}
	
	retErr = fmt.Errorf("unknown authentication type")
	return
}

func (s *server) CommCA(ctx context.Context, req *immop.CommCARequest) (reply *immop.CommCAReply, retErr error) {
	reply = &immop.CommCAReply{}
	token := strings.SplitN(req.Token, ".", 2)
	certRaw, err := base64.StdEncoding.DecodeString(token[0])
	if err != nil {
		retErr = fmt.Errorf("unexpected user")
		return
	}

	cert, _, err := immutil.ReadCertificate(certRaw)
	if err != nil {
		retErr = fmt.Errorf("could not parse a certificate: %s", err)
		return
	}

	caName := s.parentCert.Subject.CommonName
	if cert.Issuer.CommonName != caName {
		retErr = fmt.Errorf("unexpected user")
		return
	}

	
	cli := cacli.NewCAClient("https://" + caName + cacli.DefaultPort)
	
	var rsp []byte
	rsp, retErr = cli.RequestCA(req)
	if retErr != nil {
		return
	}

	reply.Rsp, retErr = modifyCAResponse(cert, req, rsp)
	return // success
}

func modifyCAResponse(user *x509.Certificate, req *immop.CommCARequest, rsp []byte) (retRsp []byte, retErr error) {
	switch req.Func {
	case "GetAllIdentities":
		_, _, err := jpkiGetAdminID(user.Subject.CommonName, user.Issuer.CommonName)
		if err != nil  { // not JPKI user
			break
		}

		ids := &immclient.GetAllIDsResponse{}
		reply := &immclient.Response{Result: ids}
		err = json.Unmarshal(rsp, reply)
		if err != nil || len(reply.Errors) > 0 {
			break
		}

		for i, _ := range ids.Identities {
			ids.Identities[i].Attributes = jpkiRemovePubKeyAttr(&ids.Identities[i].Attributes)
		}

		retRsp, err = json.Marshal(reply)
		if err != nil {
			retErr = fmt.Errorf("failed to marshal a response: %s", err)
			return
		}
		return // success
	case "GetIdentity":
		_, _, err := jpkiGetAdminID(user.Subject.CommonName, user.Issuer.CommonName)
		if err != nil  { // not JPKI user
			break
		}

		id := &immclient.IdentityResponse{}
		reply := &immclient.Response{Result: id}
		err = json.Unmarshal(rsp, reply)
		if err != nil || len(reply.Errors) > 0 {
			break
		}

		id.Attributes = jpkiRemovePubKeyAttr(&id.Attributes)
		retRsp, err = json.Marshal(reply)
		if err != nil {
			retErr = fmt.Errorf("failed to marshal a response: %s", err)
			return
		}
		return // success
	}

	retRsp = rsp
	return
}

func (s *server) JPKIFunc(ctx context.Context, req *immop.JPKIFuncRequest) (reply *immop.JPKIFuncReply, retErr error) {
	reply = &immop.JPKIFuncReply{}

	switch req.Func {
	case jpkicli.FGetRequiredPrivInfo:
		var err error
		reply.Rsp, err = getRequiredPrivInfo(s.parentCert.Subject.CommonName)
		if err != nil {
			retErr = fmt.Errorf("failed to get an information for JPKI")
			//retErr = fmt.Errorf("failed to get an information for JPKI: " + err.Error())
			return
		}
	case jpkicli.FRegisterJPKIUser:
		reply.Rsp, retErr = registerJPKIUser(s.parentCert.Subject.CommonName, req.Req)
	case jpkicli.FEnrollJPKIUser:
		reply.Rsp, retErr = enrollJPKIUser(s.parentCert.Subject.CommonName, req.Req)
	case jpkicli.FGetJPKIUsername:
		reply.Rsp, retErr = getJPKIUsername(s.parentCert.Subject.CommonName, req.Req)
	case jpkicli.FDebugData:
		reply.Rsp, retErr = debugDataJPKI(s.parentCert.Subject.CommonName, req.Req)
	default:
		retErr = fmt.Errorf("unknown function")
	}

	return
}

func (s *server) BallotFunc(ctx context.Context, req *immop.BallotFuncRequest) (reply *immop.BallotFuncReply, retErr error) {
	reply = &immop.BallotFuncReply{}

	reqTime := &time.Time{}
	err := reqTime.UnmarshalText([]byte(req.Time))
	if err != nil {
		retErr = fmt.Errorf("invalid request")
		return
	}

	now := time.Now()
	diffMins := now.Sub(*reqTime).Minutes()
	if (-3  >= diffMins) || (diffMins >= 3) {
		// The requestor's time is incorrect.
		reply.Time = now.Format(time.RFC3339)
		return // retry request
	}

	cert, retErr := s.checkCredential("BallotFunc", req)
	if retErr != nil {
		return
	}

	switch req.Func {
	case ballotcli.FCreateBox:
		reply.Rsp, retErr = ballotCreateBox(req, cert)
	case ballotcli.FSelectVoter:
		reply.Rsp, retErr = ballotSelectVoter(req, cert)
	case ballotcli.FGetPaper:
		reply.Rsp, retErr = ballotGetPaper(req, cert)
	case ballotcli.FGetSealKey:
		reply.Rsp, retErr = ballotGetSealKey(req, cert)
	case ballotcli.FVote:
		reply.Rsp, retErr = ballotVote(req, cert)
	case ballotcli.FGetResultVote:
		reply.Rsp, retErr = ballotGetVotingResult(req, cert)
	case ballotcli.FGetVoterState:
		reply.Rsp, retErr = ballotGetVoterState(req, cert)
	}

	return
}

func (s *server) ImmstFunc(ctx context.Context, req *immop.ImmstFuncRequest) (reply *immop.ImmstFuncReply, retErr error) {
	reply = &immop.ImmstFuncReply{}

	reqTime := &time.Time{}
	err := reqTime.UnmarshalText([]byte(req.Time))
	if err != nil {
		retErr = fmt.Errorf("invalid request")
		return
	}

	now := time.Now()
	diffMins := now.Sub(*reqTime).Minutes()
	if (-3  >= diffMins) || (diffMins >= 3) {
		// The requestor's time is incorrect.
		reply.Time = now.Format(time.RFC3339)
		return // retry request
	}

	cert, retErr := s.checkCredential("ImmstFunc", req)
	if retErr != nil {
		return
	}

	switch req.Mod {
	case immcommon.MCommon:
		return s.commonFunc(req, cert)
	case st2mng.MST2:
		return s.st2Func(req, cert)
	}
	
	return
}

func main() {
	cert, err := readCertificateFile(certPath)
	if err != nil {
		log.Fatalf(err.Error())
	}

	org := cert.Subject.Organization[0]

	if hasOAuthAdmin(org) {
		createOAuthHandler(org)
	}
	
	caSecretName := immutil.CAHostname + "." + org
	_, parentCertPem, err := immutil.K8sGetKeyPair(caSecretName)
	if err != nil {
		log.Fatalf(err.Error())
	}
	parentCert, _, err := immutil.ReadCertificate(parentCertPem)
	if err != nil {
		log.Fatalf(err.Error())
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %s", err)
	}

	creds, err := credentials.NewServerTLSFromFile(certPath, privPath)
	if err != nil {
		log.Fatalf("failed to get a credential from files\n", err)
	}
	opts := []grpc.ServerOption{grpc.Creds(creds)}

	immserver := &server{
		parentCert: parentCert,
		parentCertPem: parentCertPem,
		org: org,
		signer: make(map[string]*signerState),
	}

	s := grpc.NewServer(opts...)
	immop.RegisterImmOperationServer(s, immserver)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
