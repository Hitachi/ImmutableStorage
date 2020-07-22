package immclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha256"

	"encoding/pem"
	"encoding/json"
	"encoding/base64"
	"encoding/hex"
	"encoding/asn1"
	"net/http"
	"bytes"

	"github.com/mitchellh/mapstructure"

	"math/big"

	"fmt"
	"errors"
	"io/ioutil"
	"time"
	"strings"

	"immop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"crypto/tls"
	"context"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/ledger/queryresult"
)

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

// AttributeRequest is a request for an attribute.
type AttributeRequest struct {
        Name     string
        Optional bool
}


// import from github.com/cloudflare/cfssl/config
// OID is our own version of asn1's ObjectIdentifier, so we can define a custom
// JSON marshal / unmarshal.
type OID asn1.ObjectIdentifier

// import from github.com/cloudflare/cfssl/csr
// A Name contains the SubjectInfo fields.
type Name struct {
        C            string // Country
        ST           string // State
        L            string // Locality
        O            string // OrganisationName
        OU           string // OrganisationalUnitName
        SerialNumber string
}


// import from github.com/cloudflare/cfssl/signer
// Extension represents a raw extension to be included in the certificate.  The
// "value" field must be hex encoded.
type Extension struct {
        ID       OID `json:"id"`
        Critical bool       `json:"critical"`
        Value    string     `json:"value"`
}


// Subject contains the information that should be used to override the
// subject information when signing a certificate.
type Subject struct {
        CN           string
        Names        []Name `json:"names"`
        SerialNumber string
}


// SignRequest stores a signature request, which contains the hostname,
// the CSR, optional subject information, and the signature profile.
//
// Extensions provided in the signRequest are copied into the certificate, as
// long as they are in the ExtensionWhitelist for the signer's policy.
// Extensions requested in the CSR are ignored, except for those processed by
// ParseCertificateRequest (mainly subjectAltName).
type SignRequest struct {
        Hosts       []string    `json:"hosts"`
        Request     string      `json:"certificate_request"`
        Subject     *Subject    `json:"subject,omitempty"`
        Profile     string      `json:"profile"`
        CRLOverride string      `json:"crl_override"`
        Label       string      `json:"label"`
        Serial      *big.Int    `json:"serial,omitempty"`
        Extensions  []Extension `json:"extensions,omitempty"`
        // If provided, NotBefore will be used without modification (except
        // for canonicalization) as the value of the notBefore field of the
        // certificate. In particular no backdating adjustment will be made
        // when NotBefore is provided.
        NotBefore time.Time
        // If provided, NotAfter will be used without modification (except
        // for canonicalization) as the value of the notAfter field of the
        // certificate.
        NotAfter time.Time
}



// EnrollmentRequestNet is a request to enroll an identity
type EnrollmentRequestNet struct {
	SignRequest
	CAName   string
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}


// CAInfoResponseNet is the response to the GET /info request
type CAInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
	// Base64 encoding of Idemix issuer public key
	IssuerPublicKey string
	// Base64 encoding of PEM-encoded Idemix issuer revocation public key
	IssuerRevocationPublicKey string
	// Version of the server
	Version string
}

// EnrollmentResponseNet is the response to the /enroll request
type EnrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string
	// The server information
	ServerInfo CAInfoResponseNet
}

// RevocationRequest is a revocation request for a single certificate or all certificates
// associated with an identity.
// To revoke a single certificate, both the Serial and AKI fields must be set;
// otherwise, to revoke all certificates and the identity associated with an enrollment ID,
// the Name field must be set to an existing enrollment ID.
// A RevocationRequest can only be performed by a user with the "hf.Revoker" attribute.
type RevocationRequest struct {
	// Name of the identity whose certificates should be revoked
	// If this field is omitted, then Serial and AKI must be specified.
	Name string `json:"id,omitempty" opt:"e" help:"Identity whose certificates should be revoked"`
	// Serial number of the certificate to be revoked
	// If this is omitted, then Name must be specified
	Serial string `json:"serial,omitempty" opt:"s" help:"Serial number of the certificate to be revoked"`
	// AKI (Authority Key Identifier) of the certificate to be revoked
	AKI string `json:"aki,omitempty" opt:"a" help:"AKI (Authority Key Identifier) of the certificate to be revoked"`
	// Reason is the reason for revocation.  See https://godoc.org/golang.org/x/crypto/ocsp for
	// valid values.  The default value is 0 (ocsp.Unspecified).
	Reason string `json:"reason,omitempty" opt:"r" help:"Reason for revocation"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
	// GenCRL specifies whether to generate a CRL
	GenCRL bool `def:"false" skip:"true" json:"gencrl,omitempty"`
}

// AddAffiliationRequest represents the request to add a new affiliation to the
// fabric-ca-server
type AddAffiliationRequest struct {
	Name   string `json:"name"`
	Force  bool   `json:"force"`
	CAName string `json:"caname,omitempty"`
}

// AffiliationResponse contains the response for get, add, modify, and remove an affiliation
type AffiliationResponse struct {
	AffiliationInfo `mapstructure:",squash"`
	CAName          string `json:"caname,omitempty"`
}

// AffiliationInfo contains the affiliation name, child affiliation info, and identities
// associated with this affiliation.
type AffiliationInfo struct {
	Name         string            `json:"name"`
	Affiliations []AffiliationInfo `json:"affiliations,omitempty"`
	Identities   []IdentityInfo    `json:"identities,omitempty"`
}

// IdentityInfo contains information about an identity
type IdentityInfo struct {
	ID             string      `json:"id"`
	Type           string      `json:"type"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs" mapstructure:"attrs"`
	MaxEnrollments int         `json:"max_enrollments" mapstructure:"max_enrollments"`
}

// ModifyIdentityRequest represents the request to modify an existing identity on the
// fabric-ca-server
type ModifyIdentityRequest struct {
	ID             string      `skip:"true"`
	Type           string      `json:"type" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	Affiliation    string      `json:"affiliation" help:"The identity's affiliation"`
	Attributes     []Attribute `mapstructure:"attrs" json:"attrs"`
	MaxEnrollments int         `mapstructure:"max_enrollments" json:"max_enrollments" help:"The maximum number of times the secret can be reused to enroll"`
	Secret         string      `json:"secret,omitempty" mask:"password" help:"The enrollment secret for the identity"`
	CAName         string      `json:"caname,omitempty" skip:"true"`
}


type InstanceValue struct {
	Format  string
	Log  string
}

const (
	OneYear  = 365*24*time.Hour
	TenYears = 10*OneYear

	StorageAdmin = "StorageAdmin"
	GrpAdmin = "StorageGrpAdmin"
)

func EnrollUser(username string, validityPeriod time.Duration, enSecret, urlBase string) (*UserID, error) {
	// generate key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("Failed to generate a private key: " + err.Error())
	}
	privAsn1, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, errors.New("Failed to marshal an ecdsa private key into ASN.1 DEF format: " + err.Error() )
	}
	
	privPem := pem.EncodeToMemory( &pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1} )

	ski := sha256.Sum256( elliptic.Marshal(privKey.Curve, privKey.X,  privKey.Y) )
	skiStr := hex.EncodeToString(ski[:])


	// create CSR
	subj := &pkix.Name{CommonName: username}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: *subj, SignatureAlgorithm: x509.ECDSAWithSHA256}, privKey)
	if err != nil {
		return nil, errors.New("failed to create CSR: " + err.Error())
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr,})

	nowT := time.Now().UTC()
	enrollReq := &EnrollmentRequestNet{
		SignRequest: SignRequest{
			Request: string(csrPem),
			NotBefore: nowT,
			NotAfter: nowT.Add(validityPeriod).UTC(),
		},
	}

	reqData, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, errors.New("could not create a request: " + err.Error())
	}


	csrUrl := urlBase + "/ca/enroll"
	certSignReq, err := http.NewRequest("POST", csrUrl, bytes.NewReader(reqData))
	if err != nil {
		return nil, errors.New("could not create a POST request: " + err.Error())
	}
	certSignReq.SetBasicAuth(username, string(enSecret))

	reply, err := sendReqCA(certSignReq)
	if err != nil {
		return nil, err
	}

	csrRsp := &EnrollmentResponseNet{}
	mapstructure.Decode(reply, csrRsp)

	certRaw, err := base64.StdEncoding.DecodeString(csrRsp.Cert)
	if err != nil {
		return nil, errors.New("unexpected certificate format: " + err.Error())
	}

	return &UserID{Name: username, Priv: privPem, Cert: certRaw, SKI: skiStr}, nil
}


func sendReqCA(req *http.Request) (result interface{}, retErr error){
//	tr := &http.Transport{TLSClientConfig: nil}
//	client := &http.Client{Transport: tr}
	client := &http.Client{}
	resp, err := client.Do(req)
	if (err != nil) || resp.Body == nil {
		retErr = errors.New("failed to request: " + err.Error())
		return
	}
	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			print("log: failed to close the body: " + err.Error() + "\n")
		}
	}()
	if err != nil {
		retErr = errors.New("could not read the body: " + err.Error())
		return
	}

	//	fmt.Printf("body: \n%s\n", hex.Dump(respBody))
        
	body := &Response{}
	err = json.Unmarshal(respBody, body)
	if err != nil {
		retErr = errors.New("unexpected body: " + err.Error())
		return
	}
	if len(body.Errors) > 0 {
		var retStr string
		for _, errMsg := range body.Errors {
			retStr += errMsg.Message + ": code=" + fmt.Sprintf("0x%x\n", errMsg.Code)
		}
		
		retErr = errors.New(retStr)
		return
	}

	result = body.Result
	return
}


type ECDSASignature struct {
        R, S *big.Int
}

func (id *UserID) genToken(req_data []byte, req *http.Request) (string, error) {
	privData, _ := pem.Decode(id.Priv)
	if x509.IsEncryptedPEMBlock(privData) {
		return "", errors.New("not support encrypted PEM")
	}
	
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		return "", errors.New("unsupported key format: " + err.Error())
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("unexpected key")

	}	

	// generate token
	reqBase64 := base64.StdEncoding.EncodeToString(req_data)
	certBase64 := base64.StdEncoding.EncodeToString(id.Cert)
	payload := reqBase64 + "." + certBase64
	if req != nil {
		//	print("log: method=" + req.Method + " uri=" + req.URL.RequestURI() + "\n")
		uri := strings.TrimPrefix(req.URL.RequestURI(), "/ca")
		uriBase64 := base64.StdEncoding.EncodeToString([]byte(uri))
		payload = req.Method + "." + uriBase64 + "." + payload
	}
	digest := sha256.Sum256( []byte(payload) )
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return "", errors.New("failed to sign: " + err.Error())
	}
	baseN := privKey.Params().N
	if s.Cmp(new(big.Int).Rsh(baseN, 1)) == 1 {
		s.Sub(baseN, s)
	}
	signRaw, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return "", errors.New("failed to get signature: " + err.Error())
	}
	
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(signRaw)
	return token, nil
}

func (id *UserID) addToken(req_data []byte, req *http.Request) error {
	token, err := id.genToken(req_data, req)
	if err != nil {
		return err
	}

	req.Header.Set("authorization", token)
	return nil
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



type UserID struct {
	Name string
	Priv, Cert []byte
	SKI string
}

func (id *UserID) GetAllIdentities(urlBase string) ([]*IdentityResponse, error) {
	url := urlBase + "/ca/identities"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New("failed to create a request for getting identities: " + err.Error())
	}

	if err = id.addToken(nil, req); err != nil {
		return nil, err
	}

	reply, err := sendReqCA(req)
	if err != nil {
		return nil, err
	}

	idsBuf, ok := reply.(map[string]interface {})
	if !ok {
		return nil, errors.New("unexpected reply")
	}
	idsReply, ok := idsBuf["identities"]
	if !ok {
		return nil, errors.New("unexpected reply")
	}

	var users []*IdentityResponse
	for _, userRaw := range idsReply.([]interface{}) {
		user := &IdentityResponse{}
		mapstructure.Decode(userRaw, user)
		users = append(users, user)
	}
	
	return users, nil
}


// RegistrationRequest for a new identity
type RegistrationRequest struct {
	// Name is the unique name of the identity
	Name string `json:"id" help:"Unique name of the identity"`
	// Type of identity being registered (e.g. "peer, app, user")
	Type string `json:"type" def:"client" help:"Type of identity being registered (e.g. 'peer, app, user')"`
	// Secret is an optional password.  If not specified,
	// a random secret is generated.  In both cases, the secret
	// is returned in the RegistrationResponse.
	Secret string `json:"secret,omitempty" mask:"password" help:"The enrollment secret for the identity being registered"`
	// MaxEnrollments is the maximum number of times the secret can
	// be reused to enroll.
	MaxEnrollments int `json:"max_enrollments,omitempty" help:"The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)"`
	// is returned in the response.
	// The identity's affiliation.
	// For example, an affiliation of "org1.department1" associates the identity with "department1" in "org1".
	Affiliation string `json:"affiliation" help:"The identity's affiliation"`
	// Attributes associated with this identity
	Attributes []Attribute `json:"attrs,omitempty"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
}

// RegistrationResponse is a registration response
type RegistrationResponse struct {
	// The secret returned from a successful registration response
	Secret string `json:"secret"`
}

// Attributes contains attribute names and values
type Attributes struct {
	Attrs map[string]string `json:"attrs"`
}

type UserPrivilege struct {
	GenCRL bool
	StorageAdmin string
	StorageGrpAdmin string
}

func (id *UserID) GetAllAffiliations(urlBase string) (*AffiliationResponse, error) {
	url := urlBase + "/ca/affiliations"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New("failed to create a request for getting all affiliations: " + err.Error())
	}

	err = id.addToken(nil, req)
	if err != nil {
		return nil, err
	}

	reply, err := sendReqCA(req)
	if err != nil {
		return nil, errors.New("failed to send a request to CA: " + err.Error())
	}
	
	affiliations := &AffiliationResponse{}
	err = mapstructure.Decode(reply, affiliations)
	if err != nil {
		return nil, errors.New("unexpected response: " + err.Error())
	}

	return affiliations, nil
}

func (id *UserID) GetAffiliation(urlBase, affiliation string) (*AffiliationResponse, error) {
	url := urlBase + "/ca/affiliations/" + affiliation
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New("failed to create a request for getting affiliation: " + err.Error())
	}

	err = id.addToken(nil, req)
	if err != nil {
		return nil, err
	}

	reply, err := sendReqCA(req)
	if err != nil {
		return nil, errors.New("failed to send a request to CA: " + err.Error())
	}
	
	info := &AffiliationResponse{}
	err = mapstructure.Decode(reply, info)
	if err != nil {
		return nil, errors.New("unexpected response: " + err.Error())
	}

	return info, nil
}

func (id *UserID) AddAffiliation(urlBase, affiliation string) error {
	url := urlBase + "/ca/affiliations"	
	req := &AddAffiliationRequest{Name: affiliation}
	
	reqData, err := json.Marshal(req)
	if err != nil {
		return errors.New("failed to marshal a request: " + err.Error())
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqData) )
	if err != nil {
		return errors.New("failed to create a POST request: " + err.Error())
	}
	httpReq.URL.RawQuery = "force=false"

	err = id.addToken(reqData, httpReq)
	if err != nil {
		return err
	}

	reply, err := sendReqCA(httpReq)
	if err != nil {
		return err
	}

	affiliationRsp := &AffiliationResponse{}
	err = mapstructure.Decode(reply, affiliationRsp)
	if err != nil {
		return errors.New("unexpected response: " + err.Error())
	}

	return nil
}

func (id *UserID) RemoveAffiliation(urlBase, affiliation string) error {
	url := urlBase + "/ca/affiliations/" + affiliation
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.New("failed to create a DELETE request: " + err.Error())
	}
	req.URL.RawQuery = "force=true"

	err = id.addToken(nil, req)
	if err != nil {
		return err
	}

	_, err = sendReqCA(req)
	if err != nil {
		return err
	}

	return nil
}

func (id *UserID) Register(username, secret, ouType string, privilege *UserPrivilege, urlBase string) (string, error) {
	req := &RegistrationRequest{Name: username}
	maxEnrollments := -1

	var attr []Attribute

	if privilege != nil {
		if privilege.GenCRL {
			attr = append(attr, Attribute{Name: "hf.GenCRL", Value: "true"})
		}
		if privilege.StorageAdmin != "" {
			attr = append(attr, Attribute{Name: StorageAdmin, Value: privilege.StorageAdmin, ECert: true})
		}
		if privilege.StorageGrpAdmin != "" {
			affiliation := GrpAdmin + ":" + strings.ReplaceAll(privilege.StorageGrpAdmin, ".", ":")
			affiliationAddF := true
			
			affiliationL, err := id.GetAllAffiliations(urlBase)
			if err != nil {
				return "", err
			}
			for _, item := range affiliationL.Affiliations {
				if item.Name == affiliation {
					affiliationAddF = false
					break
				}
			}
			if affiliationAddF {
				err := id.AddAffiliation(urlBase, affiliation)
				if err != nil {
					return "", err
				}
			}

			//attr = append(attr, Attribute{Name: "StorageGrpAdmin", Value: "true", ECert: false})
			//attr = append(attr, Attribute{Name: "hf.Registrar.Roles", Value: "client", ECert: false})
			//attr = append(attr, Attribute{Name: "hf.AffiliationMgr", Value: "true", ECert: false})
			req.Affiliation = affiliation
		}
	}

	if attr != nil {
		req.Attributes = attr
	}
	if ouType != "" {
		req.Type = ouType
	}
	if maxEnrollments != -1 {
		req.MaxEnrollments = maxEnrollments
	}
	if secret != "" {
		req.Secret = secret
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return "", errors.New("could not create a request: " + err.Error())
	}

	url := urlBase + "/ca/register"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqData) )
	if err != nil {
		return "", errors.New("could not create a POST request: " + err.Error())
	}

	err = id.addToken(reqData, httpReq)
	if err != nil {
		return "", err
	}

	reply, err := sendReqCA(httpReq)
	if err != nil {
		return "", err
	}

	regReply := &RegistrationResponse{}
	err = mapstructure.Decode(reply, regReply)
	if err != nil {
		return "", errors.New("unexpected response: " + err.Error())
	}
	
	return regReply.Secret, err
}

func (id *UserID) GetIssuerOrg() (string, error) {
	uCertData, _ := pem.Decode(id.Cert)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		return "", err
	}
	return uCert.Issuer.Organization[0],  nil
}

func (id *UserID) dial(url string) (conn *grpc.ClientConn, err error) {
	conn, err = grpc.Dial(url, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true,})))
	return
}

func (id *UserID) CreateService(mspID string, priv, cert []byte, url string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.CreateServiceRequest{MspID: mspID, Priv: priv, Cert: cert}
	req.Cred, err = id.signMsg("CreateService", req)
	if err != nil {
		return err
	}

	_, err = cli.CreateService(context.Background(), req)
	if err != nil {
		return err
	}

	return nil
}

func (id *UserID) ListService(url string) (list []*immop.ServiceAttribute, err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ListServiceRequest{}
	req.Cred, err = id.signMsg("ListService", req)
	if err != nil {
		return
	}

	replyList, err := cli.ListService(context.Background(), req)
	if err != nil {
		return
	}

	list = replyList.Service 
	return
}

func (id *UserID) ExportService(hostname, url string) (serviceData []byte, err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ExportServiceRequest{Hostname: hostname, }
	req.Cred, err = id.signMsg("ExportService", req)
	if err != nil {
		return
	}

	replyData, err := cli.ExportService(context.Background(), req)
	if err != nil {
		return
	}

	serviceData, err = proto.Marshal(replyData)
	return
}

func (id *UserID) ImportService(serviceData []byte, url string) (err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	token, err := id.genToken(nil, nil)
	if err != nil {
		return
	}

	peer := &immop.ExportServiceReply{}
	proto.Unmarshal(serviceData, peer)
	
	req := &immop.ImportServiceRequest{Service: peer, CAToken: token, }
	req.Cred, err = id.signMsg("ImportService", req)
	if err != nil {
		return
	}

	_, err = cli.ImportService(context.Background(), req)
	return
}

func (id *UserID) RemoveServiceFromCh(hostName, portName, url string) (err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	token, err := id.genToken(nil, nil)
	if err != nil {
		return
	}

	req := &immop.RemoveServiceRequest{Peer: &immop.ServiceSummary{Hostname: hostName, Port: portName}, CAToken: token, }
	req.Cred, err = id.signMsg("RemoveSeviceFromCh", req)
	if err != nil {
		return
	}

	_, err = cli.RemoveServiceFromCh(context.Background(), req)
	return
}

func (id *UserID) ListImportedService(url string) (list []*immop.ServiceSummary, err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ListImportedServiceRequest{}
	req.Cred, err = id.signMsg("ListImportedService", req)
	if err != nil {
		return
	}

	listReply, err := cli.ListImportedService(context.Background(), req)
	if err != nil {
		return
	}

	list = listReply.Peer
	return
}

func (id *UserID) CreateChannel(channelID, url string) (err error) {
	conn, err := id.dial(url)
	if err != nil {
		return
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	token, err := id.genToken(nil, nil)
	if err != nil {
		return
	}

	req := &immop.CreateChannelRequest{ChannelID: channelID, CAToken: token, }
	req.Cred, err = id.signMsg("CreateChannel", req)
	if err != nil {
		return
	}

	_, err = cli.CreateChannel(context.Background(), req)
	return
}

func (id *UserID) signMsg(funcName string, param proto.Message) (cred *immop.Credential , retErr error) {
	cred = &immop.Credential{}
	msg := []byte(funcName)
	
	if param == nil {
		param = cred
	}

	paramRaw, err := proto.Marshal(param)
	if err != nil {
		retErr = errors.New("failed to marshal: " + err.Error())
		return
	}
	msg = append(msg, paramRaw...)

	cred.Signature, retErr = id.signData(msg)
	cred.Cert = id.Cert
	return
}

func (id *UserID) signData(data []byte) ([]byte, error) {
	privData, _ := pem.Decode(id.Priv)
	if x509.IsEncryptedPEMBlock(privData) {
		return nil, errors.New("not support encrypted PEM")
	}
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		return nil, errors.New("unsupported key format: " + err.Error())
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected key")

	}

	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, errors.New("failed to sign: " + err.Error())
	}
	baseN := privKey.Params().N
	if s.Cmp(new(big.Int).Rsh(baseN, 1)) == 1 {
		s.Sub(baseN, s)
	}
	
	signature, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return nil, errors.New("failed to create signature: " + err.Error())
	}

	return signature, nil
}

func (id *UserID) JoinChannel(block []byte, url string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.PropReq{Msg: block,}
	req.Cred, err = id.signMsg("JoinChannel", req)
	if err != nil {
		return err
	}

	rsp, err := cli.JoinChannel(context.Background(), req)
	if err != nil {
		return errors.New("failed to create a client: " + err.Error())
	}

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	for {
		propReq.Cred = nil
		propReq.Cred, _ = id.signMsg("SendSignedProp", propReq)
		reply, err := cli.SendSignedProp(context.Background(), propReq)
		if err != nil {
			return errors.New("failed to send a signature: " + err.Error())
		}

		if ! reply.NotReadyF {
			break
		}
		
		// retry
		propReq.TaskID = reply.TaskID
	}

	return nil
}

func (id *UserID) GetConfigBlock(chName, url string) ([]byte, error) {
	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.GetConfigBlockReq{ChName: chName}
	req.Cred, err = id.signMsg("GetConfigBlock", req)
	if err != nil {
		return nil, err
	}

	rsp, err := cli.GetConfigBlock(context.Background(), req)
	if err != nil {
		return nil, err
	}
	
	return rsp.Body, nil
}

func (id *UserID) InstallChainCode(url string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.InstallCC{Cds: nil, }
	req.Cred, err = id.signMsg("InstallChainCode", req)
	if err != nil {
		return  err
	}

	rsp, err := cli.InstallChainCode(context.Background(), req)
	if err != nil {
		return err
	}

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	propReq.Cred, _ = id.signMsg("SendSignedProp", propReq)
	_, err = cli.SendSignedProp(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature: " + err.Error())
	}

	return nil
}

func (id *UserID) InstantiateChainCode(url, chName string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.InstantiateReq{ChannelID: chName,}
	req.Cred, err = id.signMsg("Instantiate", req)
	if err != nil {
		return  err
	}
	
	rsp, err := cli.Instantiate(context.Background(), req)
	if err != nil {
		return err
	}
	taskID := rsp.TaskID

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq := &immop.PropReq{Msg: signature, TaskID: taskID, }
	for {
		propReq.Cred = nil
		propReq.Cred, _ = id.signMsg("SendSignedPropOrderer", propReq)
		rsp, err = cli.SendSignedPropOrderer(context.Background(), propReq)
		if err != nil {
			return errors.New("failed to send a signature: " + err.Error())
		}
		if ! rsp.NotReadyF {
			break
		}

		// retry
		taskID = rsp.TaskID
	}

	signature, err = id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq = &immop.PropReq{Msg: signature, TaskID: taskID, } 
	propReq.Cred, _ = id.signMsg("SendSignedProp", propReq)
	_, err = cli.SendSignedProp(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature for orderer: " + err.Error())
	}

	return nil
}

func (id *UserID) ListChannelInPeer(url string) ([]string, error) {
	chNames := make([]string, 0)

	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)
	cred, err := id.signMsg("ListChannelInPeer", nil)
	if err != nil {
		return nil, err
	}

	rsp, err := cli.ListChannelInPeer(context.Background(), cred)
	if err != nil {
		return nil, err
	}
	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return nil, err
	}

	req := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	req.Cred, _ = id.signMsg("SendSignedPropAndRspDone", req)
	rsp, err = cli.SendSignedPropAndRspDone(context.Background(), req)
	if err != nil {
		return nil, err
	}

	chList := &immop.ListChannelReply{}
	err = proto.Unmarshal(rsp.Proposal, chList)
	if err != nil {
		return nil, err
	}

	chNames = append(chNames, chList.ChName...)
	return chNames, nil
}

func (id *UserID) ListAvailableStorageGroup(url string) ([]string, error) {
	storageGrpList := make([]string, 0)
	
	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)
	cred, err := id.signMsg("ListChannelInMyOU", nil)
	if err != nil {
		return nil, err
	}

	rsp, err := cli.ListChannelInMyOU(context.Background(), cred)
	if err != nil {
		return nil, err
	}
	
	chList := &immop.ListChannelReply{}
	err = proto.Unmarshal(rsp.Proposal, chList)
	if err != nil {
		return nil, err
	}

	for _, chName := range chList.ChName {
		codeName, err := id.ListChainCode(url, chName)
		if err != nil || codeName == nil || len(codeName) < 1 {
			continue
		}
		
		storageGrpList = append(storageGrpList, strings.TrimSuffix(chName, "-ch"))
	}
	
	return storageGrpList, nil
}

func (id *UserID) ActivateChannel(url, chName string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ActivateChannelReq{ChannelID: chName, }
	req.Cred, err = id.signMsg("ActivateChannel", req)
	if err != nil {
		return err
	}
	
	rsp, err := cli.ActivateChannel(context.Background(), req)
	if err != nil {
		return err
	}
	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	propReq.Cred, _ = id.signMsg("SendSignedProp", propReq)
	_, err = cli.SendSignedProp(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature: " + err.Error())
	}

	return nil
}

func (id *UserID) RecordLedger(storageGrp, key, msgLog, url string) error {
	conn, err := id.dial(url)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.RecordLedgerReq{Key: key, Log: msgLog, StorageGroup: storageGrp, }
	req.Cred, err = id.signMsg("RecordLedger", req)
	if err != nil {
		return  err
	}

	rsp, err := cli.RecordLedger(context.Background(), req)
	if err != nil {
		return err
	}
	taskID := rsp.TaskID

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return err
	}

	propReq := &immop.PropReq{Msg: signature, WaitEventF: true, TaskID: taskID,}
	propReq.Cred, _ = id.signMsg("SendSignedPropOrderer", propReq)
	rsp, err = cli.SendSignedPropOrderer(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature to peers: " + err.Error())
	}

	signature, _ = id.signData(rsp.Proposal)
	propReq = &immop.PropReq{Msg: signature, TaskID: taskID, }
	propReq.Cred, _ = id.signMsg("SendSignedPropAndRsp", propReq)
	rsp, err = cli.SendSignedPropAndRsp(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature to an orderer: " + err.Error())
	}

	signature, _ = id.signData(rsp.Proposal)
	propReq = &immop.PropReq{Msg: signature, TaskID: taskID, } 
	propReq.Cred, _ = id.signMsg("SendSignedPropAndRspDone", propReq)
	rsp, err = cli.SendSignedPropAndRspDone(context.Background(), propReq)
	if err != nil {
		return errors.New("failed to send a signature to event handler on peer")
	}
	
	return nil
}

func (id *UserID) ReadLedger(storageGrp, key, url string) (*[]queryresult.KeyModification, error) {
	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ReadLedgerReq{Key: key, StorageGroup: storageGrp, }
	req.Cred, err = id.signMsg("ReadLedger", req)
	if err != nil {
		return  nil, err
	}

	rsp, err := cli.ReadLedger(context.Background(), req)
	if err != nil {
		return nil, err
	}

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return nil, err
	}
	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	propReq.Cred, _ = id.signMsg("SendSignedPropAndRspDone", propReq)
	rsp, err = cli.SendSignedPropAndRspDone(context.Background(), propReq)
	if err != nil {
		return nil, errors.New("failed to send a signature to a peer: " + err.Error())
	}

	historyV := &[]queryresult.KeyModification{}
	err = json.Unmarshal(rsp.Proposal, historyV)
	if err != nil {
		return nil, errors.New("failed to unmarshal history: " + err.Error())
	}

	return historyV, nil
}

func (id *UserID) QueryBlockByTxID(storageGrp, txID, url string) (*common.Block, error) {
	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.QueryBlockByTxIDReq{TxID: txID, StorageGroup: storageGrp, }
	req.Cred, err = id.signMsg("QueryBlockByTxID", req)
	if err != nil {
		return  nil, err
	}

	rsp, err := cli.QueryBlockByTxID(context.Background(), req)
	if err != nil {
		return nil, err
	}

	signature, err := id.signData(rsp.Proposal)
	if err != nil {
		return nil, err
	}
	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	propReq.Cred, _ = id.signMsg("SendSignedPropAndRspDone", propReq)
	rsp, err = cli.SendSignedPropAndRspDone(context.Background(), propReq)
	if err != nil {
		return nil, errors.New("failed to send a signature to a peer: " + err.Error())
	}

	block := &common.Block{}
	err = proto.Unmarshal(rsp.Proposal, block)
	if err != nil {
		return nil, errors.New("failed to unmarshal Block: " + err.Error())
	}

	return block, nil
}

func (id *UserID) listChainCode(url, option string) ([]string, error) {
	conn, err := id.dial(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cli := immop.NewImmOperationClient(conn)

	req := &immop.ListChainCodeReq{Option: option, }
	req.Cred, err = id.signMsg("ListChainCode", req)
	if err != nil {
		return nil, err
	}

	rsp, err := cli.ListChainCode(context.Background(), req)
	if err != nil {
		return nil, err
	}

	signature, err := id.signData(rsp.Proposal)
	propReq := &immop.PropReq{Msg: signature, TaskID: rsp.TaskID, }
	propReq.Cred, _ = id.signMsg("SendSignedPropAndRspDone", propReq)
	rsp, err = cli.SendSignedPropAndRspDone(context.Background(), propReq)
	if err != nil {
		return nil, errors.New("failed to send a signature to peer")
	}

	listRsp := &immop.ListChainCodeReply{}
	err = proto.Unmarshal(rsp.Proposal, listRsp)
	if err != nil {
		return nil, errors.New("failed to unmarshal a proposal: " + err.Error())
	}

	return listRsp.CodeName, nil
}

func (id *UserID) ListChainCode(url, chName string) ([]string, error) {
	return id.listChainCode(url, "enabled:"+chName)
}

func (id *UserID) ListChainCodeInPeer(url string) ([]string, error) {
	return id.listChainCode(url, "installed")
}

func (id *UserID) GetStorageAdminHost() string {
	uCertData, _ := pem.Decode(id.Cert)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		return ""
	}
	
	org, err := id.GetIssuerOrg()
	if err != nil {
		return ""
	}

	for _, ext := range uCert.Extensions {
		if ! ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}) {
			continue
		}

		attrs := &Attributes{}
		err = json.Unmarshal(ext.Value, attrs)
		if err != nil {
			continue
		}
		
		hostname, ok := attrs.Attrs[StorageAdmin]
		if !ok {
			continue
		}

		if strings.Contains(hostname, org) {
			return hostname
		}
	}

	return "" // permission denied
}

func (id *UserID) HasStorageAdmin() bool {
	return id.GetStorageAdminHost() != ""
}

func (id *UserID) GetGrpAdminHost() string {
	uCertData, _ := pem.Decode(id.Cert)
	uCert, err := x509.ParseCertificate(uCertData.Bytes)
	if err != nil {
		return ""
	}

	org, err := id.GetIssuerOrg()
	if err != nil {
		return ""
	}

	for _, ou := range uCert.Subject.OrganizationalUnit {
		hostname := strings.TrimPrefix(ou, GrpAdmin+":")
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

func (id *UserID) HasStorageGrpAdmin() bool {
	return id.GetGrpAdminHost() != ""
}

func (id *UserID) GetIdentity(urlBase, userName string) (*IdentityResponse, error) {
	url := urlBase + "/ca/identities/" + userName
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New("failed to create a request for getting ID: " + err.Error())
	}

	err = id.addToken(nil, req)
	if err != nil {
		return nil, err
	}

	reply, err := sendReqCA(req)
	if err != nil {
		return nil, errors.New("failed to send a request to CA: " + err.Error())
	}
	
	user := &IdentityResponse{}
	err = mapstructure.Decode(reply, user)
	if err != nil {
		return nil, errors.New("unexpected response: " + err.Error())
	}

	return user, nil
}

func (id *UserID) RemoveIdentity(urlBase, userName string) error {
	url := urlBase + "/ca/identities/" + userName
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.New("failed to remove " + userName + ": " + err.Error())
	}

	err = id.addToken(nil, req)
	if err != nil {
		return err
	}

	_, err = sendReqCA(req)
	if err != nil {
		return err
	}

	return nil
}

func (id *UserID) RevokeIdentity(urlBase, userName string) error {
	url := urlBase + "/ca/revoke"

	reqData, err := json.Marshal(&RevocationRequest{Name: userName})
	if err != nil {
		return errors.New("could not marshal a request for revocation")
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqData))
	if err != nil {
		return errors.New("could not create a request")
	}

	err = id.addToken(reqData, httpReq)
	if err != nil {
		return err
	}

	_, err = sendReqCA(httpReq)
	if err != nil {
		return err
	}
	return nil
}

func RandStr(num int) string {
	availStr := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567")
	randStr := ""

	b := make([]byte, num)
	rand.Read(b)

	for i := 0; i < num; i++ {
		randStr += string(availStr[int(b[i])%len(availStr)])
	}

	return randStr
}

func (id *UserID) ChangeSecret(urlBase, userName, secret string) (string, error) {
	url := urlBase + "/ca/identities/" + userName

	if secret == "" {
		secret = RandStr(8)
	}
	reqData, err := json.Marshal(&ModifyIdentityRequest{Secret: secret})
	if err != nil {
		return "", errors.New("could not marshal a request for modifying secret")
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewReader(reqData))
	if err != nil {
		return "", errors.New("could not create a request")
	}

	err = id.addToken(reqData, httpReq)
	if err != nil {
		return "", err
	}

	_, err = sendReqCA(httpReq)
	if err != nil {
		return "", err
	}
	
	return secret, nil
}
