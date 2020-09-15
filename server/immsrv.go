package main

import (
	"log"
	"net"
	"net/http"

	"immop"
	"immutil"
	"fabconf"

	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/credentials"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"

	"fmt"

	"math"
	"math/big"
	"encoding/pem"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha256"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"archive/tar"
	"strings"
	"bytes"
	"strconv"
	"io/ioutil"

	"github.com/golang/protobuf/proto"

	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/common"

	pp "github.com/hyperledger/fabric/protos/peer"
	po "github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/hyperledger/fabric/core/scc/cscc"
	"github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/hyperledger/fabric/common/channelconfig"

	"sync/atomic"
	"sync"
	"gopkg.in/yaml.v2"
)

const (
	port = ":50051"
	parentCertPath = "/var/lib/immsrv/ca.crt"
	certPath = "/var/lib/immsrv/server.crt"
	privPath = "/var/lib/immsrv/server.key"
	workDir = "/var/lib/immsrv/work"

	//	dockerNetPrefix = "net_hfl_"

	couchdbHostPrefix = "couchdb"

	hostKeyDir = "key"
	hostConfDir = "conf"
	hostDataDir = "data"
	hostDockerCertDir = "docker-certs"
	contDockerCertDir = "/certs"
	hostDockerVarDir = "docker-var"
	contDockerVarDir = "/var/lib/docker"
	hostDockerImgTar = "/immsrv/chaincode-base.tar"
	contDockerImgTar = "/var/lib/chaincode-base.tar"
	loadImgCmd = `dockerd-entrypoint.sh & while [ ! -S /var/run/docker.sock ]; do sleep 1; done; if [ "$(docker images -q hyperledger/fabric-baseos)" = "" ]; then cat `+contDockerImgTar+` | docker load; docker tag hyperledger/fabric-ccenv:1.4.7 hyperledger/fabric-ccenv:latest; fi; wait`
	
	fabDefaultConfDir = "/etc/hyperledger/fabric"
	certsTarDir = "/var/lib/certs"
	
	ordererGenesisFile = "/var/hyperledger/orderer/block/genesis.block"
	ordererKeyDir = "/var/hyperledger/orderer"
	ordererDataDir = "/var/hyperledger/production/orderer"
	ordererWorkingDir = "/opt/gopath/src/github.com/hyperledger/fabric"

	peerKeyDir = "/var/hyperledger/peer"
	peerDataDir = "/var/hyperledger/production"
	peerWorkingDir = "/opt/gopath/src/github.com/hyperledger/fabric/peer"

	chaincodePath = "/var/lib/immsrv/hlRsyslog"
	defaultCCName = "hlRsyslog"

	clearMspCmd = "rm -rf "+fabDefaultConfDir+"/msp"
	cpKeyCmd = "tar xf "+certsTarDir+"/keys.tar -C "+fabDefaultConfDir
	
	mkOrdererKeyDir = "mkdir -p "+ordererKeyDir
	cpOrdererKeyCmd = "tar xf "+certsTarDir+"/keys.tar -C "+ordererKeyDir
	ordererEpCmd = clearMspCmd+"&&"+cpKeyCmd+"&&"+mkOrdererKeyDir+"&&"+cpOrdererKeyCmd

	mkPeerKeyDir = "mkdir -p "+peerKeyDir
	cpPeerKeyCmd = "tar xf "+certsTarDir+"/keys.tar -C "+peerKeyDir
	peerEpCmd = clearMspCmd+"&&"+cpKeyCmd+"&&"+mkPeerKeyDir+"&&"+cpPeerKeyCmd

	storageAdminAttr = "StorageAdmin"
	grpAdminOU = "StorageGrpAdmin"

	storageGrpPort = 7050
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
	tlsCAPrivPath, tlsCACertPath string

	signer map[string]*signerState
}

type ECDSASignature struct {
	R, S *big.Int
}

type tarData struct {
	header *tar.Header
	body []byte
}

type channelConf struct {
	ChannelName string `yaml:"ChannelName"`
	OrdererHost string `yaml:"OrdererHost"`
	OrdererTlsCACert string `yaml:"OrdererTlsCACert"`
	AnchorPeers map[string] []string `yaml:"AnchorPeers"`
	TlsCACerts map[string] string `yaml:"TlsCACerts"`
	CACerts map[string] string `yaml:"CACerts"`
	ClientOU string `yaml:"ClientOU"`
}

// import from github.com/cloudflare/cfssl/api
// ResponseMessage implements the standard for response errors and
// messages. A message has a code and a string message.
type ResponseMessage struct {
        Code    int    `json:"code"`
        Message string `json:"message"`
}

// Response implements the CloudFlare standard for API
// responses.
type Response struct {
        Success  bool              `json:"success"`
        Result   interface{}       `json:"result"`
        Errors   []ResponseMessage `json:"errors"`
        Messages []ResponseMessage `json:"messages"`
}

// Attributes contains attribute names and values
type Attributes struct {
	Attrs map[string]string `json:"attrs"`
}

// Attribute is a name and value pair
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert,omitempty"`
}

// IdentityResponse is the response from the any add/modify/remove identity call
type IdentityResponse struct {
	ID             string      `json:"id" skip:"true"`
	Type           string      `json:"type,omitempty"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs,omitempty" mapstructure:"attrs"`
	MaxEnrollments int         `json:"max_enrollments,omitempty" mapstructure:"max_enrollments"`
	Secret         string      `json:"secret,omitempty"`
	CAName         string      `json:"caname,omitempty"`
}


func (s *server) checkCredential(funcName string, reqParam proto.Message) (*x509.Certificate, error) {
	param := proto.Clone(reqParam)
	credMsg := proto.MessageReflect(param)
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

		attrs := &Attributes{}
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

func sendReqCA(req *http.Request) (result interface{}, retErr error){
	caCertData, err := ioutil.ReadFile(parentCertPath)
	if err != nil {
		retErr = fmt.Errorf("failed to read a CA certificate: %s\n")
		return
	}
	rootCAPool := x509.NewCertPool()
	ok := rootCAPool.AppendCertsFromPEM(caCertData)
	if !ok {
		retErr = fmt.Errorf("failed to append a certificate for the CA")
		return
	}
	
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAPool}}
	client := &http.Client{Transport: tr}
	//client := &http.Client{}
	resp, err := client.Do(req)
	if (err != nil) || resp.Body == nil {
		retErr = fmt.Errorf("failed to request: " + err.Error())
		return
	}
	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("failed to close the body: %s\n", err)
		}
	}()
	if err != nil {
		retErr = fmt.Errorf("could not read the body: " + err.Error())
		return
	}

	fmt.Printf("body: \n%s\n", hex.Dump(respBody))
        
	body := &Response{}
	err = json.Unmarshal(respBody, body)
	if err != nil {
		retErr = fmt.Errorf("unexpected body: " + err.Error())
		return
	}
	if len(body.Errors) > 0 {
		var retStr string
		for _, errMsg := range body.Errors {
			retStr += errMsg.Message + ": code=" + fmt.Sprintf("0x%x\n", errMsg.Code)
		}
		
		retErr = fmt.Errorf(retStr)
		return
	}

	result = body.Result
	return
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
	taskID, _ := generateTxID(cert.Raw)
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
		createEnv func(hostname, org, tlsPrivFile, tlsCertFile, tlsCAFile, netName string) error
		mspPrefix string
	}{
		"orderer": {
			hasPrivilege: hasStorageGrpAdmin,
			createEnv: s.createOrderer,
			mspPrefix: fabconf.OrdererMspIDPrefix,
		},
		"peer": {
			hasPrivilege: hasStorageAdmin,
			createEnv: createPeer,
			mspPrefix: fabconf.MspIDPrefix,
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
	privSki, err := readPrivKey(req.Priv)
	if err != nil {
		retErr = fmt.Errorf("failed to read a private key of the specified service: "+err.Error())
		return
	}

	if pubSki != privSki {
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

	fmt.Printf("log: CreateService")
	
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

	// create a key-pair for TLS
	tlsPriv, tlsPub, tlsSki, retErr := createKeyPair()
	if retErr != nil {
		return
	}

	tlsCAPriv, err := ioutil.ReadFile(s.tlsCAPrivPath)
	if err != nil {
		retErr = fmt.Errorf("failed to read a private key of TLS CA: "+err.Error())
		return
	}
	tlsCACert, err := ioutil.ReadFile(s.tlsCACertPath)
	if err != nil {
		retErr = fmt.Errorf("failed to read a certificate of TLS CA: "+err.Error())
		return
	}

	tlsCert, retErr := signPublicKey(tlsPub, &cert.Subject, tlsCAPriv, tlsCACert)
	if retErr != nil {
		return
	}
	
	tlsPrivFile := tlsSki+"_sk"
	tlsCertFile := host+"-cert.pem"
	tlsCACertFile := immutil.TlsCAHostname+"."+org+"-cert.pem"

		
	// create a secret
	caCert, err := ioutil.ReadFile(parentCertPath)
	if err != nil {
		retErr = fmt.Errorf("could not read a CA certificate: " + err.Error())
		return
	}
	skiStr := hex.EncodeToString(pubSki[:])

	mspID := svc.mspPrefix + org
	configYaml := s.createConfigYaml()
	data := []tarData{
		{&tar.Header{ Name: "tls/", Mode: 0755, }, nil },
		{&tar.Header{ Name: "tls/"+tlsPrivFile, Mode: 0400, Size: int64(len(tlsPriv)), }, tlsPriv },
		{&tar.Header{ Name: "tls/"+tlsCertFile, Mode: 0444, Size: int64(len(tlsCert)), }, tlsCert},
		{&tar.Header{ Name: "msp/", Mode: 0755, }, nil },
		{&tar.Header{ Name: "msp/keystore/", Mode: 0755, }, nil},
		{&tar.Header{ Name: "msp/keystore/"+skiStr+"_sk", Mode: 0400, Size: int64(len(req.Priv)), }, req.Priv},
		{&tar.Header{ Name: "msp/signcerts/", Mode: 0755, }, nil},
		{&tar.Header{ Name: "msp/signcerts/"+host+"@"+mspID+"-cert.pem", Mode: 0444, Size: int64(len(req.Cert)), }, req.Cert},
		{&tar.Header{ Name: "msp/cacerts/", Mode: 0755, }, nil},
		{&tar.Header{ Name: "msp/cacerts/"+s.parentCert.Subject.CommonName+"-cert.pem", Mode: 0444, Size: int64(len(caCert)), }, caCert},
		{&tar.Header{ Name: "msp/admincerts/", Mode: 0755, }, nil},
		{&tar.Header{ Name: "msp/admincerts/"+userName+"@"+mspID+"-cert.pem", Mode: 0444, Size: int64(len(req.Cred.Cert)), }, req.Cred.Cert},
		{&tar.Header{ Name: "msp/tlscacerts/", Mode: 0755, }, nil},
		{&tar.Header{ Name: "msp/tlscacerts/"+tlsCACertFile, Mode: 0444, Size: int64(len(tlsCACert)), }, tlsCACert},
		{&tar.Header{ Name: "msp/config.yaml", Mode: 0755, Size: int64(len(configYaml)), }, configYaml},
	}

	buf, retErr := getTarBuf(data)
	if retErr != nil {
		return
	}

	secretTar := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: host,
		},
		Data: map[string][]byte{
			"keys.tar": buf.Bytes(),
		},
	}

	secretsClient, retErr := immutil.K8sGetSecretsClient()
	if retErr != nil {
		return
	}
	resultSecret, retErr := secretsClient.Create(context.TODO(), secretTar, metav1.CreateOptions{})
	if retErr != nil {
		return
	}
	print("Create a secret: " + resultSecret.GetObjectMeta().GetName() + "\n")
	
	// create an enviroment
	netName := immutil.DockerNetPrefix + org
	retErr = svc.createEnv(host, mspID, tlsPrivFile, tlsCertFile, tlsCACertFile, netName)
	
	return
}

func getTarBuf(data []tarData) (bytes.Buffer, error) {
	var buf bytes.Buffer
	tarW := tar.NewWriter(&buf)

	for _, tarFile := range data {
		tarFile.header.ModTime = time.Now()
		tarFile.header.Format = tar.FormatGNU
		err := tarW.WriteHeader(tarFile.header)
		if err != nil {
			return buf, fmt.Errorf("failed to archive "+tarFile.header.Name)
		}
		if tarFile.body == nil {
			continue
		}
		_, err = tarW.Write(tarFile.body)
		if err != nil {
			return buf, fmt.Errorf("failed to write "+tarFile.header.Name)
		}
	}

	err := tarW.Close()
	if err != nil {
		return buf, fmt.Errorf("failed to flush tar")
	}

	return buf, nil
}

func (s *server) createOrderer(hostname, mspID, tlsPrivFile, tlsCertFile, tlsCAFile, netName string) error {
	port, err := s.allocStorageGrpPort()
	if err != nil {
		return err
	}
	
	ordererEnvMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: hostname+"-env",
			Labels: map[string]string{
				"app": "orderer",
			},
		},
		Data: map[string]string{
			"ORDERER_GENERAL_LOGLEVEL": "DEBUG",
			"ORDERER_GENERAL_LISTENADDRESS": "0.0.0.0",
			"ORDERER_GENERAL_LISTENPORT": port,
			"ORDERER_GENERAL_GENESISMETHOD": "file",
			"ORDERER_GENERAL_GENESISFILE": ordererGenesisFile,
			"ORDERER_GENERAL_LOCALMSPID": mspID,
			"ORDERER_GENERAL_LOCALMSPDIR": ordererKeyDir+"/msp",
			"ORDERER_GENERAL_TLS_ENABLED": "true",
			"ORDERER_GENERAL_TLS_PRIVATEKEY": ordererKeyDir+"/tls/"+tlsPrivFile,
			"ORDERER_GENERAL_TLS_CERTIFICATE": ordererKeyDir+"/tls/"+tlsCertFile,
			"ORDERER_GENERAL_TLS_ROOTCAS": "["+ordererKeyDir+"/msp/tlscacerts/"+tlsCAFile+"]",
		},
	}

	configMapClient, err := immutil.K8sGetConfigMapsClient()
	if err != nil {
		return err
	}
	_, err = configMapClient.Create(context.TODO(), ordererEnvMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for orderer enviriment variable: " + err.Error())
	}
	
	return nil
}

func getImmSrvExternalIPs() (ips []string, retErr error) {
	ips = make([]string, 0)
	client, retErr := immutil.K8sGetServiceClient()
	if retErr != nil {
		return
	}

	envoySvc, err := client.Get(context.TODO(), immutil.EnvoyHostname, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to get a service: " + err.Error())
		return
	}

	ips = envoySvc.Spec.ExternalIPs
	return
}

func getStorageGrpPort(grpAdminHost string) (port int32) {
	port = storageGrpPort
	
	client, err := immutil.K8sGetConfigMapsClient()
	if err != nil {
		return
	}

	configMap, err := client.Get(context.TODO(), grpAdminHost+"-env", metav1.GetOptions{})
	if err != nil || configMap == nil {
		return
	}

	portStr, ok := configMap.Data["ORDERER_GENERAL_LISTENPORT"]
	if !ok {
		return
	}

	envPort, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}

	port = int32(envPort)
	return
}

func startOrderer(serviceName string) error {
	podPortName := strings.SplitN(serviceName, ":", 2)
	podName := podPortName[0]
	port := storageGrpPort
	if len(podName) > 2 {
		port, _ = strconv.Atoi(podPortName[1])
	}
	
	shortName := strings.SplitN(podName, ".", 2)[0]
	podLabel := "app="+shortName 
	
	podState, stateVer, err := immutil.K8sGetPodState(podLabel, podName)
	if err != nil {
		return err
	}

	switch podState {
	case immutil.Ready:
		return nil
	case immutil.NotReady:
		return nil
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
	
	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		return err
	}

	genesisFile := strings.Split(ordererGenesisFile, "/")
	genesisDir := strings.TrimSuffix(ordererGenesisFile, "/"+genesisFile[len(genesisFile)-1])
	repn := int32(1)
	pathType := corev1.HostPathType(corev1.HostPathDirectoryOrCreate)
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
					Volumes: []corev1.Volume{
						{
							Name: "vol1",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: immutil.ConfBaseDir+"/"+podName,
									Type: &pathType,
								},
							},
						},
						{
							Name: "secret-vol1",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: podName,
								},
							},
						},
						{
							Name: "configmap-vol1",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: podName,
									},
								},
							},
						},
					},
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
							Image: immutil.OrdererImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: ordererDataDir, SubPath: hostDataDir, },
								{ Name: "secret-vol1", MountPath: certsTarDir, },
								{ Name: "configmap-vol1", MountPath: genesisDir, },
							},
							EnvFrom: ordererEnv,
							WorkingDir: ordererWorkingDir,
							Command: []string{"sh", "-c", ordererEpCmd+"&& orderer"},
							Ports: []corev1.ContainerPort{
								{
									Name: "grpc",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 7050,
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
	fmt.Printf("Create deployment %q.\n", result.GetObjectMeta().GetName())

		
	// create a service
	externalIPs, _ := getImmSrvExternalIPs()
	
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
						IntVal: getStorageGrpPort(podName),
					},
				},
			},
			Type: corev1.ServiceTypeLoadBalancer,
			ExternalIPs: externalIPs,
		},
	}

	serviceClient, err := immutil.K8sGetServiceClient()
	if err != nil {
		return err
	}
	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("Create service %q.\n", resultSvc.GetObjectMeta().GetName())
	
	return nil
}

func createPeer(hostname, mspID, tlsPrivFile, tlsCertFile, tlsCAFile, netName string) error {
	peerEnvMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: hostname+"-env",
			Labels: map[string]string{
				"app": "peer",
			},
		},
		Data: map[string]string{
			"CORE_VM_ENDPOINT": "tcp://localhost:2376",
			"CORE_VM_DOCKER_TLS_ENABLED": "true",
			"CORE_VM_DOCKER_TLS_CERT_FILE": "/certs/client/cert.pem",
			"CORE_VM_DOCKER_TLS_KEY_FILE": "/certs/client/key.pem",
			"CORE_VM_DOCKER_TLS_CA_FILE": "/certs/client/ca.pem",
			"CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE": "bridge", //netName
			//"CORE_LOGGING_LEVEL": "INFO",
			//"CORE_LOGGING_LEVEL": "DEBUG",
			"FABRIC_LOGGING_SPEC": "debug,shim=debug",
			"CORE_LOGGING_PEER": "debug",
			"CORE_CHAINCODE_LOGGING_LEVEL": "DEBUG",
			"CORE_CHAINCODE_LOGGING_SHIM": "DEBUG",
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
			"CORE_PEER_ADDRESS": hostname+":7051",
			//"CORE_PEER_GOSSIP_BOOTSTRAP": peer1Hostname+":7051",
			//"CORE_PEER_GOSSIP_EXTERNALENDPOINT": "localhost:7051",
			"CORE_PEER_GOSSIP_EXTERNALENDPOINT": hostname+":7051",
			"CORE_PEER_LOCALMSPID": mspID,
			"CORE_PEER_LOCALMSPDIR": peerKeyDir+"/msp",
			"CORE_LEDGER_STATE_STATEDATABASE": "CouchDB",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS": "localhost:5984",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME": "",
			"CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD": "",
		},
	}

	couchDBEnvMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: couchdbHostPrefix+hostname+"-env",
			Labels: map[string]string{
				"app": "couchdb",
			},
		},
		Data: map[string]string{
			"COUCHDB_USER": "",
			"COUCHDB_PASSWORD": "",
		},
	}

	configMapClient, err := immutil.K8sGetConfigMapsClient()
	if err != nil {
		return err
	}
	
	_, err = configMapClient.Create(context.TODO(), peerEnvMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for peer environment variable: " + err.Error())
	}

	_, err = configMapClient.Create(context.TODO(), couchDBEnvMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create a ConfigMap for couchDB environment variable: " + err.Error())
	}
	
	return nil
}

func startPeer(podName string) (state, resourceVersion string, retErr error) {
	shortName := strings.SplitN(podName, ".", 2)[0]
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

	peerEnv := []corev1.EnvFromSource{
		{ ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{ Name: podName+"-env", }, }, },
	}
	couchDBEnv := []corev1.EnvFromSource{
		{ ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{ Name: couchdbHostPrefix+podName+"-env",},},},
	}
	
	deployClient, retErr := immutil.K8sGetDeploymentClient()
	if retErr != nil {
		return
	}

	repn := int32(1)
	privilegedF := bool(true)
	pathType := corev1.HostPathType(corev1.HostPathDirectoryOrCreate)
	pathTypeFile := corev1.HostPathType(corev1.HostPathFileOrCreate)
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
					Volumes: []corev1.Volume{
						{
							Name: "vol1",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: immutil.ConfBaseDir+"/"+podName,
									Type: &pathType,
								},
							},
						},
						{
							Name: "file1",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: immutil.TmplDir+hostDockerImgTar,
									Type: &pathTypeFile,
								},
							},
						},
						{
							Name: "secret-vol1",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: podName,
								},
							},
						},
					},
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
							Image: immutil.PeerImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: peerDataDir, SubPath: hostDataDir, },
								{ Name: "vol1", MountPath: contDockerCertDir, SubPath: hostDockerCertDir, },
								{ Name: "secret-vol1", MountPath: certsTarDir, },
							},
							EnvFrom: peerEnv,
							WorkingDir: peerWorkingDir,
							Command: []string{"sh", "-c", peerEpCmd+"&& env && peer node start"},
							Ports: []corev1.ContainerPort{
								{
									Name: "peer",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 7051,
								},
								{
									Name: "chaincode",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 7052,
								},

							},
						},
						{
							Name: "dind-chaincode",
							Image: immutil.DockerImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: contDockerCertDir, SubPath: hostDockerCertDir, },
								{ Name: "vol1", MountPath: contDockerVarDir, SubPath: hostDockerVarDir, },
								{ Name: "file1", MountPath: contDockerImgTar, },
							},
							Command: []string{"sh", "-c", loadImgCmd},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privilegedF,
							},
							Ports: []corev1.ContainerPort{
								{
									Name: "docker",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 2376,
								},
							},
						},
						{
							Name: couchdbHostPrefix+shortName,
							Image: immutil.CouchDBImg,
							EnvFrom: couchDBEnv,
							Ports: []corev1.ContainerPort{
								{
									Name: "db",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 5984,
								},
							},
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
	
	// create a service
	externalIPs, _ := getImmSrvExternalIPs()
	
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: shortName,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": shortName,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "peer",
					Port: 7051,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 7051,
					},
				},
				corev1.ServicePort{
					Name: "chaincode",
					Port: 7052,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 7052,
					},
				},
			},
			Type: corev1.ServiceTypeLoadBalancer,
			ExternalIPs: externalIPs,
		},
	}

	serviceClient, retErr := immutil.K8sGetServiceClient()
	if retErr != nil {
		return
	}
	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a service for a peer: %s", err)
		return
	}
	fmt.Printf("Create service %q\n", resultSvc.GetObjectMeta().GetName())

	resourceVersion = createdDep.GetObjectMeta().GetResourceVersion()
	return
}

func createKeyPair() (priv, pub []byte, skiStr string, retErr error) {
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
	priv = pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )

	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )
	skiStr = hex.EncodeToString(ski[:])

	pubDer, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		retErr = fmt.Errorf("Failed to marshal a public key into ASN.1 DEF format: %s", err)
		return
	}

	pub = pem.EncodeToMemory( &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	return
}

func signPublicKey(pub []byte, pubSubj *pkix.Name, caKey, caCertPem []byte) ([]byte, error) {
	// decode public key
	pubKeyData, _ := pem.Decode(pub)
	if pubKeyData.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid pubilc key")
	}
	srcPubKeyRaw, err := x509.ParsePKIXPublicKey(pubKeyData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse a public key: %s", err)
	}
	srcPubKey, ok := srcPubKeyRaw.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key")
	}

	// decode CA private key
	privData, _ := pem.Decode(caKey)
	if privData.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected private key (type=%s)", privData.Type)
	}
	if x509.IsEncryptedPEMBlock(privData) {
		return nil, fmt.Errorf("not support encrypted PEM")
	}
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unsupported key format: %s", err)
	}
	caPrivKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key")
	}

	// decode CA certificatate
	caCertData, _ := pem.Decode(caCertPem)
	if caCertData.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected CA private key")
	}
	caCert, err := x509.ParseCertificate(caCertData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unexpected certificate: %s", err)
	}
	_, ok = caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key")
	}

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

	cert, err := x509.CreateCertificate(rand.Reader, certTempl, caCert, srcPubKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a certificate: %s", err)
	}
	pubPem := pem.EncodeToMemory( &pem.Block{Type: "CERTIFICATE", Bytes: cert})

	return pubPem, nil
}

func readPrivKey(privPem []byte) (privSki [sha256.Size]byte, retErr error) {
	privData, _ := pem.Decode(privPem)
	if privData.Type != "PRIVATE KEY" {
		retErr = fmt.Errorf("unexpected private key (type=%s)", privData.Type)
		return
	}
	if x509.IsEncryptedPEMBlock(privData) {
		retErr = fmt.Errorf("not support encrypted PEM")
		return
	}
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		retErr = fmt.Errorf("unsupported key format: %s", err)
		return
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		retErr = fmt.Errorf("unsupported type of key")
		return
	}
	privSki = sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y) )
	return
}

func readCertificateFile(certPath string) (*x509.Certificate, error) {
	certPem, err := ioutil.ReadFile(certPath)
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

func (s *server) ExportService(ctx context.Context, req *immop.ExportServiceRequest) (reply *immop.ExportServiceReply, err error) {
	reply = &immop.ExportServiceReply{}
	
	uCert, err := s.checkCredential("ExportService", req)
	if err != nil {
		return
	}
	
	if ! hasStorageAdmin(uCert) {
		err = fmt.Errorf("permission denied")
		return
	}

	secretName := req.Hostname
	reply.CACert, reply.AdminCert, reply.TlsCACert, err = immutil.K8sGetCertsFromSecret(secretName)
	reply.Hostname = secretName
	reply.Port = "7051" // not support for swarm

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

var storageGrpPorts = uint32(0)
func (s *server) lockedbittestandset(bit int) bool {
	old := storageGrpPorts
	new := old | (1 << bit)
	
	if new == old {
		return false
	}
		
	return atomic.CompareAndSwapUint32(&storageGrpPorts, old, new)
}

func (s *server) lockedbittestandreset(bit int) bool {
	old := storageGrpPorts
	new := old &^ (1 << bit)

	if new == old {
		return false
	}
	
	return atomic.CompareAndSwapUint32(&storageGrpPorts, old, new)
}

func (s *server) allocStorageGrpPort() (port string, retErr error ) {
	client, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return // error
	}

	list, err := client.List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app=orderer",
	})
	if err != nil {
		retErr = fmt.Errorf("failed to get a list of service: " + err.Error())
		return // error
	}

	for _, configMap := range list.Items {
		portStr, ok := configMap.Data["ORDERER_GENERAL_LISTENPORT"]
		if !ok {
			continue
		}

		portNum, _ := strconv.Atoi(portStr)
		bit := (portNum - storageGrpPort)/100
		s.lockedbittestandset(int(bit))
	}

	for i := 0; i < 16; i++ {
		if s.lockedbittestandset(i) {
			port = strconv.Itoa(storageGrpPort+i*100)
			return // success
		}
	}

	retErr = fmt.Errorf("There is no unused port in this cluster.")
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

	port := strconv.Itoa(int(getStorageGrpPort(grpAdminHost)))
	serviceName := ordererName+":"+port
	genesisBlock, err := fabconf.CreateGenesisBlock(req.ChannelID, serviceName, anchorPeers)
	if err != nil {
		retErr = fmt.Errorf("failed to create genesis block: %s", err)
		return
	}

	// create a ConfigMap for genesis-block
	genesisFile := strings.Split(ordererGenesisFile, "/")
	genesisMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ordererName,
			Labels: map[string]string{
				"block": "genesis",
			},
		},
		BinaryData: map[string][]byte{
			genesisFile[len(genesisFile)-1]: genesisBlock,
		},
	}
	mapClient, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}
	_, err = mapClient.Create(context.TODO(), genesisMap, metav1.CreateOptions{})
	if retErr != nil {
		retErr = fmt.Errorf("failed to create a ConfigMap for genesis.block: " + err.Error())
		return
	}

	err = startOrderer(serviceName)
	if err != nil {
		retErr = err
		return
	}

	return
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

	confMapClient, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}
	
	chName := grpAdminHost+"-ch"
	chMap, err := confMapClient.Get(context.TODO(), chName, metav1.GetOptions{})
	if err != nil || chMap == nil {
		chMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: chName,
				Labels: map[string] string{
					"grpHost": grpAdminHost,
				},
			},				
		}
		
		chMap, err = confMapClient.Create(context.TODO(), chMap, metav1.CreateOptions{})
		if err != nil {
			retErr = fmt.Errorf("failed to create a ConfigMap: " + err.Error())
			return
		}
	}

	serviceData, err := proto.Marshal(req.Service)
	if err != nil {
		retErr = err
		return
	}

	if chMap.BinaryData == nil {
		chMap.BinaryData = make(map[string][]byte)
	}
	
	chMap.BinaryData[req.Service.Hostname+"."+req.Service.Port] = serviceData
	_, err = confMapClient.Update(context.TODO(), chMap, metav1.UpdateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to update a ConfigMap for " +req.Service.Hostname + ": " + err.Error())
		return
	}

	return
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

	confMapClient, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}

	chName := grpAdminHost+"-ch"
	chMap, err := confMapClient.Get(context.TODO(), chName, metav1.GetOptions{})
	if err != nil {
		return // ignore this request
	}

	key := req.Peer.Hostname + "." + req.Peer.Port
	if chMap.BinaryData == nil {
		return // ignore this request
	}
	_, ok := chMap.BinaryData[key]
	if !ok {
		return // ignore this request
	}
	delete(chMap.BinaryData, key)
		
	_, err = confMapClient.Update(context.TODO(), chMap, metav1.UpdateOptions{})
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
				Args: [][]byte{[]byte(cscc.GetChannels)},
			},
		},
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal ID: " + err.Error())
		return
	}

	prop, _, err := utils.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}

	reply.Proposal, err = proto.Marshal(prop)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a proposal: " + err.Error())
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
				Args: [][]byte{[]byte(cscc.GetConfigBlock), []byte(req.ChannelID)},
			},
		},
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to marshal ID: " + err.Error())
		return
	}

	prop, _, err := utils.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}

	reply.Proposal, err = proto.Marshal(prop)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal a proposal: " + err.Error())
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

		chConf, err := getConfigFromBlock(propRsp.Response.Payload)
		if err != nil {
			signer.err <- err
			return
		}

		writeChannelConf(storageHost, chConf)
		signer.err <- nil
		return
	}()

	return
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

	mapClient, retErr := immutil.K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}
	
	genesisMap, err := mapClient.Get(context.TODO(), grpHost, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("could not get a genesis.block: " + err.Error())
		return
	}
	if genesisMap.BinaryData == nil {
		retErr = fmt.Errorf("Unexpected configMap for gensis block")
	}
	
	genesisFile := strings.Split(ordererGenesisFile, "/")
	genesisName := genesisFile[len(genesisFile)-1]
	genesisData, ok := genesisMap.BinaryData[genesisName]
	if !ok {
		retErr = fmt.Errorf("Unexpected configMap for genesis block")
		return
	}
	reply.Body = genesisData

	return // success
}

func connectPeerWithName(peerName string) (*grpc.ClientConn, error) {
	_, _, tlsCACert, err := immutil.K8sGetCertsFromSecret(peerName)
	if err != nil {
		return nil, err
	}
	return connectPeer(peerName+":7051", tlsCACert)
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

	chConf, err := getConfigFromBlock(req.Msg)
	if err != nil {
		retErr = err
		return
	}
	grpHost := chConf.OrdererHost

	spec := &pp.ChaincodeSpec{
		Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
		ChaincodeId: &pp.ChaincodeID{Name: "cscc"},
		Input: &pp.ChaincodeInput{
			Args: [][]byte{[]byte(cscc.JoinChain), req.Msg},
		},
	}
	
	invocation := &pp.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = err
		return
	}

	prop, _, err := utils.CreateProposalFromCIS(common.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		retErr = fmt.Errorf("Error creating proposal for join %s", err)
		return
	}

	reply.Proposal, err = proto.Marshal(prop)
	if err != nil {
		retErr = err
		return
	}

	signer, retErr := s.setSignatureCh("JoinChannel", cert, grpHost)
	if retErr != nil {
		return
	}
	reply.TaskID = signer.taskID

	go func() {
		peerName := storageHost
		peerState, ver, peerErr := startPeer(peerName)
		signature, err := signer.waitSignatureCh()
		if err != nil {
			return
		}
		if peerErr != nil {
			signer.err <- peerErr
			return
		}

		if peerState == immutil.NotReady {
			for retryC := 1; ; retryC++ {
				label := "app=" + strings.SplitN(peerName, ".", 2)[0]
				err = immutil.K8sWaitPodReady(ver, label, peerName)
				if err == nil {
					break
				}

				if err.Error() != immutil.NotReady {
					signer.err <- err
					return
				}

				prevSigner := signer
				signer, err = s.setSignatureCh("JoinChannel:Retry"+strconv.Itoa(retryC), cert, grpHost)
				if err != nil {
					prevSigner.err <- err
					return
				}

				retryRsp := &immop.Reply{
					NotReadyF: true,
					TaskID: signer.taskID,
				}
				prevSigner.rsp, err = proto.Marshal(retryRsp)
				if err != nil {
					signer.signatureChDone()
					prevSigner.err <- fmt.Errorf("failed to marshal a reply")
					return
				}

				prevSigner.err <- nil

				_, err = signer.waitSignatureCh()
				if err != nil {
					return
				}
			}
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
				fmt.Printf("retry process proposal\n")
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

		fmt.Printf("Successfully submitted proposal to join channel")
		signer.err <- nil
		return
	}()

	return
}

func getConfigFromBlock(blockRaw []byte) (chConf *channelConf, retErr error) {
	block := &common.Block{}
	bEnvelope := &common.Envelope{}
	payload := &common.Payload{}
	confEnvelope := &common.ConfigEnvelope{}

	proto.Unmarshal(blockRaw, block)

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

	return
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

	fmt.Printf("log: signedProp:\n%s\n", hex.Dump(req.Msg))
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
		if err != nil {
			signer.err <- fmt.Errorf("could not read a certificate: " + err.Error())
			return
		}
		
		caTlsCert, _, err := immutil.ReadCertificate(caTlsCertRaw)
		certPool := x509.NewCertPool()
		certPool.AddCert(caTlsCert)
		creds := credentials.NewClientTLSFromCert(certPool, "")
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
		}

		err = ordererClient.Send(envelope)
		err2 := <- eventCh
		if signer.state != 2 {
			fmt.Printf("log: unexpected state: %d", signer.state)
			return
		}

		if err != nil {
			signer.err <- fmt.Errorf("send error: %s", err)
			return
		}

		ordererRsp, err := ordererClient.Recv()
		if err != nil || ordererRsp.Status != common.Status_SUCCESS {
			fmt.Printf("log: failed to boradcast: status = %s err=%s\n", ordererRsp.Status.String(), err)
			ordererClient.CloseSend()
			signer.err <- err
			return
		}
		//		fmt.Printf("log: status=%s\n", ordererRsp.Status.String())
		
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
	privPem, certPem, _, err := immutil.GenerateKeyPair(tlsSubj)
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

	payloadChHeader := utils.MakeChannelHeader(common.HeaderType_DELIVER_SEEK_INFO, int32(0), chConf.ChannelName, uint64(0) )
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
					fmt.Printf("log: got an event ( TxId=0x%x )\n", TxId)
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
	
	fmt.Printf("Successfully submitted proposal\n")
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
	codePkgRaw, err := ioutil.ReadFile(chaincodePath)
	if err != nil {
		retErr = fmt.Errorf("could not read user chaincode")
		return
	}

	cds := &pp.ChaincodeDeploymentSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Path: "hlRsyslog/go", Name: defaultCCName, Version: "5.0"},
			Input: &pp.ChaincodeInput{},
		},
		CodePackage: codePkgRaw,
	}

	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: mspId, IdBytes: req.Cred.Cert})
	if err != nil {
		retErr = fmt.Errorf("failed to make a creator")
		return
	}

	prop, _, err := utils.CreateInstallProposalFromCDS(cds, creator)
	if err != nil {
		retErr = fmt.Errorf("could not create a proposal: %s", err)
		return
	}

	reply.Proposal, err = proto.Marshal(prop)
	if err != nil {
		retErr = err
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
	
	policyStr := req.Policy
	if policyStr == "" {
		firstOrg := true
		policyStr = "AND("
		for orgName, _ := range chConf.CACerts {
			if ! firstOrg {
				policyStr += ","
			}
			policyStr += "'"+fabconf.MspIDPrefix+orgName+".member'"
			firstOrg = false
		}
		policyStr += ")"
	}
	policy, err := cauthdsl.FromString(policyStr)
	if err != nil {
		retErr = fmt.Errorf("failed to parse the specified policy \"%s\": %s", policyStr, err)
		return
	}

	policyRaw, err := proto.Marshal(policy)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal policy")
		return
	}

	var codePkgRaw []byte
	cds := &pp.ChaincodeDeploymentSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_Type(pp.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pp.ChaincodeID{Path: "hlRsyslog/go", Name: defaultCCName, Version: "5.0"},
			Input: &pp.ChaincodeInput{},
		},
		CodePackage: codePkgRaw,
	}

	proposal, _, err := utils.CreateDeployProposalFromCDS(chConf.ChannelName, cds, creator, policyRaw, []byte("escc"), []byte("vscc"), nil)
	if err != nil {
		retErr = fmt.Errorf("error creating proposal: %s", err)
		return
	}
	reply.Proposal, err = proto.Marshal(proposal)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal proposal")
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
		hdrExt, err := utils.GetChaincodeHeaderExtension(hdr)
		if err != nil {
			signer.err <- fmt.Errorf("could not get header extensions: " + err.Error())
			return
		}

		chPropPayload := &pp.ChaincodeProposalPayload{}
		err = proto.Unmarshal(proposal.Payload, chPropPayload)
		if err != nil {
			signer.err <- fmt.Errorf("could not get channel proposal payload: " + err.Error())
			return
		}

		cea := &pp.ChaincodeEndorsedAction{ProposalResponsePayload: propRsp.Payload, Endorsements: endorsements}
		propPayloadBytes, err := utils.GetBytesProposalPayloadForTx(chPropPayload, hdrExt.PayloadVisibility)
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
	var tlsCACert []byte

	
	if req.Option == "installed" {
		spec.ChaincodeSpec.Input = &pp.ChaincodeInput{Args: [][]byte{[]byte("getinstalledchaincodes")}}
		
		peerName = getStorageAdminHost(cert)
		if peerName == "" {
			retErr = fmt.Errorf("storage host was not determined")
			return
		}
		_, _, tlsCACert, retErr = immutil.K8sGetCertsFromSecret(peerName)
		if retErr != nil {
			return
		}
		peerName += ":7051"
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

		tlsCACertStr, ok := chConf.TlsCACerts[org]
		if !ok {
			retErr = fmt.Errorf("CA certificate is not found")
			return
		}
		tlsCACert = []byte(tlsCACertStr)
	} else {
		retErr = fmt.Errorf("invalid option")
		return
	}

	prop, _, err := utils.CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chName, spec, creator)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: " + err.Error())
		return
	}
	reply.Proposal, err = proto.Marshal(prop)
	if err != nil {
		retErr = err
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

		conn, err := connectPeer(peerName, tlsCACert)
		if err != nil {
			signer.err <- err
			return
		}
		propRsp, err := sendProcessProp(reply.Proposal, signature, conn)
		if err != nil {
			signer.err <- err
			return
		}

		fmt.Printf("payload:\n%s\n", hex.Dump(propRsp.Payload))
		fmt.Printf("response.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))

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
	confMapClient, err := immutil.K8sGetConfigMapsClient()
	if err != nil {
		return err
	}
	
	confMapName := storageHost+"-ch"
	chMap, err := confMapClient.Get(context.TODO(), confMapName, metav1.GetOptions{})
	if err != nil || chMap == nil {
		chMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: confMapName,
				Labels: map[string] string{
					"config": "channel",
				},
			},				
		}

		chMap, err = confMapClient.Create(context.TODO(), chMap, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create a ConfigMap for channel: " + err.Error())
		}
	}

	confData, err := yaml.Marshal(chConf)
	if chMap.BinaryData == nil {
		chMap.BinaryData = make(map[string][]byte)
	}
	chMap.BinaryData[chConf.ChannelName] = confData
	_, err = confMapClient.Update(context.TODO(), chMap, metav1.UpdateOptions{})
	return err
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

	txId, nonce := generateTxID(creatorData)
	
	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: defaultCCName},
			Input: &pp.ChaincodeInput{Args: [][]byte{[]byte("addLog"), []byte(req.Key), []byte("TraditionalFormat"), []byte(req.Log)}},
		},
	}
	
	proposal, _, err := utils.CreateChaincodeProposalWithTxIDNonceAndTransient(txId, common.HeaderType_ENDORSER_TRANSACTION, chConf.ChannelName, cis, nonce, creatorData, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: %s", err)
		return
	}
	
	reply.Proposal, err = proto.Marshal(proposal)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal proporal: %s", err)
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
	hdrExt, err := utils.GetChaincodeHeaderExtension(hdr)
	if err != nil {
		return nil, fmt.Errorf("could not get header extensions: " + err.Error())
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
	propPayloadBytes, err := utils.GetBytesProposalPayloadForTx(chPropPayload, hdrExt.PayloadVisibility)
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

func generateTxID(creatorData []byte) (string, []byte) {
	randNum := make([]byte, 24)
	rand.Read(randNum)

	buf := append(randNum, creatorData...)
	digest := sha256.Sum256(buf)
	txID := hex.EncodeToString(digest[:])	

	return txID, randNum[:]
}

func createChaincodeProposal(creator *msp.SerializedIdentity, chName, ccName string, inputs *[][]byte) (*pp.Proposal, error) {
	creatorData, err := proto.Marshal(creator)
	if err != nil {
		return nil, fmt.Errorf("failed to make a creator")
	}

	txId, nonce := generateTxID(creatorData)
	
	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: ccName},
			Input: &pp.ChaincodeInput{Args: *inputs},
		},
	}

	proposal, _, err := utils.CreateChaincodeProposalWithTxIDNonceAndTransient(txId, common.HeaderType_ENDORSER_TRANSACTION, chName, cis, nonce, creatorData, nil)
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

	txId, nonce := generateTxID(creatorData)
	
	cis := &pp.ChaincodeInvocationSpec{
		ChaincodeSpec: &pp.ChaincodeSpec{
			Type: pp.ChaincodeSpec_GOLANG, ChaincodeId: &pp.ChaincodeID{Name: defaultCCName},
			Input: &pp.ChaincodeInput{Args: [][]byte{[]byte("getLog"), []byte(req.Key) }},
		},
	}

	proposal, _, err := utils.CreateChaincodeProposalWithTxIDNonceAndTransient(txId, common.HeaderType_ENDORSER_TRANSACTION, chConf.ChannelName, cis, nonce, creatorData, nil)
	if err != nil {
		retErr = fmt.Errorf("failed to create a proposal: %s", err)
		return
	}
	
	reply.Proposal, err = proto.Marshal(proposal)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal proporal: %s", err)
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
		fmt.Printf("log: ReadLedger: payload:\n%s\n", hex.Dump(signer.rsp))
		fmt.Printf("log: ReadLedger: reponse.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))
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

	proposal, err := createChaincodeProposal(&creator, chConf.ChannelName, "qscc",
		&[][]byte{[]byte("GetBlockByTxID"), []byte(chConf.ChannelName), []byte(req.TxID)})
	if err != nil {
		retErr = err
		return
	}

	reply.Proposal, err = proto.Marshal(proposal)
	if err != nil {
		retErr = fmt.Errorf("failed to marshal proposal: %s", err)
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
		fmt.Printf("log: QueryBlockByTxID: payload:\n%s\n", hex.Dump(signer.rsp))
		fmt.Printf("log: QueryBlockByTxID: reponse.payload:\n%s\n", hex.Dump(propRsp.Response.Payload))
		signer.err <- nil
		return
	}()

	return
}

func main() {
	parentCert, err := readCertificateFile(parentCertPath)
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


	// create a CA for TLS
	cert, _ := readCertificateFile(certPath)
	tlsSubj := &pkix.Name{
		Country: cert.Subject.Country,
		Organization: cert.Subject.Organization,
		Locality: cert.Subject.Locality,
		Province: cert.Subject.Province,
		CommonName: immutil.TlsCAHostname + "." + cert.Subject.Organization[0],
	}
	privFile, certFile, err := immutil.CreateSelfKeyPair(tlsSubj, workDir)
	if err != nil {
		log.Fatalf("failed to create keys for %s CA TLS\n", tlsSubj.CommonName)
	}

	immserver := &server{
		parentCert: parentCert,
		tlsCAPrivPath: workDir+"/"+privFile,
		tlsCACertPath: workDir+"/"+certFile,
		signer: make(map[string]*signerState),
	}

	s := grpc.NewServer(opts...)
	immop.RegisterImmOperationServer(s, immserver)
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
