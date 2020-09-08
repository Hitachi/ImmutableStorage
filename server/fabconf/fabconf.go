package fabconf

import (
	"immutil"
	"immop"
	"fmt"
	"strings"
	"strconv"
	"time"

	"math/big"
	"encoding/pem"
	"encoding/asn1"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/sha256"
	"crypto/rand"

	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/golang/protobuf/proto"

	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/common"

	"github.com/hyperledger/fabric/common/genesis"
	"github.com/hyperledger/fabric/common/policies"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/common/channelconfig"

	pp "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/common/tools/configtxlator/update"

	po "github.com/hyperledger/fabric/protos/orderer"
)

const (
	AdminsPolicyKey = "Admins"
	ordererAdminsPolicyName = "/Channel/Orderer/Admins"
	BlockValidationPolicyKey = "BlockValidation"
	
	MspIDPrefix        = "MSP"
	OrdererMspIDPrefix = "OrdererMSP"
)

func CreateGenesisBlock(channelID, ordererName string, anchorPeers []*immop.ExportServiceReply) (blockRaw []byte, err error) { 
	chGr, err := newChannelGroup(channelID+"Consortium", ordererName, anchorPeers)
	if err != nil {
		return
	}

	block := genesis.NewFactoryImpl(chGr).Block(channelID)
	blockRaw, err = proto.Marshal(block)
	return
}

func newChannelGroup(consortiumName, ordererName string, anchorPeers []*immop.ExportServiceReply) (chGr *common.ConfigGroup, err error) {
	chGr = common.NewConfigGroup()
	chGr.ModPolicy = AdminsPolicyKey

	err = addValue(chGr, channelconfig.HashingAlgorithmValue(), AdminsPolicyKey)
	if err != nil {
		return
	}
	err = addValue(chGr, channelconfig.BlockDataHashingStructureValue(), AdminsPolicyKey)
	if err != nil {
		return
	}
	err = addValue(chGr, channelconfig.OrdererAddressesValue([]string{ordererName}), ordererAdminsPolicyName)
	if err != nil {
		return
	}
	err = addValue(chGr, channelconfig.ConsortiumValue(consortiumName), channelconfig.AdminsPolicyKey)
	if err != nil {
		return
	}
	err = addValue(chGr, channelconfig.CapabilitiesValue(map[string] bool{"V1_3": true} ), channelconfig.AdminsPolicyKey)
	if err != nil {
		return
	}


	addImplicitMetaPolicyDefaults(chGr)

	chGr.Groups[channelconfig.OrdererGroupKey], err = newOrdererGroup(ordererName)
	if err != nil {
		return
	}
	appOrdererGr := proto.Clone(chGr.Groups[channelconfig.OrdererGroupKey]).(*common.ConfigGroup)
	consortiumsOrdererGr := proto.Clone(appOrdererGr).(*common.ConfigGroup)


/*
	chGr.Groups[channelconfig.ApplicationGroupKey] = common.NewConfigGroup()
	chGr.Groups[channelconfig.ApplicationGroupKey].ModPolicy = channelconfig.AdminsPolicyKey
*/
	chGr.Groups[channelconfig.ApplicationGroupKey], err = newApplicationGroup(appOrdererGr)
	if err != nil {
		return
	}
	err = addOrgAnchorsToAppGroup(chGr.Groups[channelconfig.ApplicationGroupKey], anchorPeers)
	if err != nil {
		return
	}

	chGr.Groups[channelconfig.ConsortiumsGroupKey], err = newConsortiumsGroup(consortiumName, anchorPeers, consortiumsOrdererGr)
	return
}

func addImplicitMetaPolicyDefaults(cg *common.ConfigGroup){
	addPolicy(cg, policies.ImplicitMetaMajorityPolicy(channelconfig.AdminsPolicyKey), channelconfig.AdminsPolicyKey)
	addPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.ReadersPolicyKey), channelconfig.AdminsPolicyKey)
	addPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.WritersPolicyKey), channelconfig.AdminsPolicyKey)
}

func addValue(cg *common.ConfigGroup, value channelconfig.ConfigValue, modPolicy string) (err error) {
	valueRaw, err := proto.Marshal(value.Value())
	if err != nil {
		return
	}

	cg.Values[value.Key()] = &common.ConfigValue{
		Value: valueRaw,
		ModPolicy: modPolicy,
	}
	return
}


func addPolicy(cg *common.ConfigGroup, policy policies.ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &common.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}


func newOrdererGroup(ordererName string) (ordererGr *common.ConfigGroup , err error) {
	ordererGr = common.NewConfigGroup()
	ordererGr.ModPolicy = AdminsPolicyKey

	addImplicitMetaPolicyDefaults(ordererGr)

	implicitMetaAnyPolicy := &common.ImplicitMetaPolicy{
		Rule: common.ImplicitMetaPolicy_ANY,
		SubPolicy: channelconfig.WritersPolicyKey,
	}
	implicitMetaAnyPolicyWriteRaw, err := proto.Marshal(implicitMetaAnyPolicy)
	ordererGr.Policies[BlockValidationPolicyKey] = &common.ConfigPolicy{
		Policy: &common.Policy{
			Type: int32(common.Policy_IMPLICIT_META),
			Value: implicitMetaAnyPolicyWriteRaw,
		},
		ModPolicy: channelconfig.AdminsPolicyKey,
	}

	addValue(ordererGr, channelconfig.BatchSizeValue(10 /*MaxMessageCount*/, 98*1024*1024, 512*1024),
		channelconfig.AdminsPolicyKey)
	addValue(ordererGr, channelconfig.BatchTimeoutValue("2s"), channelconfig.AdminsPolicyKey)
	addValue(ordererGr, channelconfig.ChannelRestrictionsValue(0), channelconfig.AdminsPolicyKey)
	addValue(ordererGr, channelconfig.CapabilitiesValue(map[string] bool{"V1_1": true,}), channelconfig.AdminsPolicyKey)

	addValue(ordererGr, channelconfig.KafkaBrokersValue([]string{"127.0.0.1:9092"}), channelconfig.AdminsPolicyKey)
	addValue(ordererGr, channelconfig.ConsensusTypeValue("solo", nil), channelconfig.AdminsPolicyKey)

	
	caCert, adminCert, tlsCACert, err := immutil.K8sGetCertsFromSecret(strings.SplitN(ordererName, ":", 2)[0])
	if err != nil {
		return
	}
	caCertS, _, err := immutil.ReadCertificate(caCert)
	if err != nil {
		return
	}
	org := caCertS.Subject.Organization[0]
	ordererGr.Groups["orderer."+org], err = newOrgGroup(OrdererMspIDPrefix+org, caCert, adminCert, tlsCACert, false)
	return
}

func newApplicationGroup(ordererGr *common.ConfigGroup) (appGr *common.ConfigGroup, err error) {
	appGr = common.NewConfigGroup()
	appGr.ModPolicy = channelconfig.AdminsPolicyKey

	addImplicitMetaPolicyDefaults(appGr)

	var acls = map[string] string {
        "lscc/ChaincodeExists": "/Channel/Application/Readers",
        "lscc/GetDeploymentSpec": "/Channel/Application/Readers",
        "lscc/GetChaincodeData": "/Channel/Application/Readers",
        "lscc/GetInstantiatedChaincodes": "/Channel/Application/Readers",
        "qscc/GetChainInfo": "/Channel/Application/Readers",
        "qscc/GetBlockByNumber": "/Channel/Application/Readers",
        "qscc/GetBlockByHash": "/Channel/Application/Readers",
        "qscc/GetTransactionByID": "/Channel/Application/Readers",
        "qscc/GetBlockByTxID": "/Channel/Application/Readers",
        "cscc/GetConfigBlock": "/Channel/Application/Readers",
        "cscc/GetConfigTree": "/Channel/Application/Readers",
        "cscc/SimulateConfigTreeUpdate": "/Channel/Application/Readers",
        "peer/Propose": "/Channel/Application/Writers",
        "peer/ChaincodeToChaincode": "/Channel/Application/Readers",
        "event/Block": "/Channel/Application/Readers",
        "event/FilteredBlock": "/Channel/Application/Readers",
	}
	addValue(appGr, channelconfig.ACLValues(acls), channelconfig.AdminsPolicyKey)
	addValue(appGr, channelconfig.CapabilitiesValue(map[string] bool{"V1_3": true, "V1_2": true, "V1_1": true}), channelconfig.AdminsPolicyKey)

	if ordererGr == nil {
		return
	}

	var key string
	var orgGrp *common.ConfigGroup
	for key, orgGrp = range ordererGr.Groups {
		break
	}
	appGr.Groups[key] = orgGrp
	addValue(appGr.Groups[key], channelconfig.AnchorPeersValue([]*pp.AnchorPeer{}), channelconfig.AdminsPolicyKey)
 
	return
}

func addOrgAnchorsToAppGroup(appGr *common.ConfigGroup, anchorPeers []*immop.ExportServiceReply) error {
	anchors := make(map[string] []*pp.AnchorPeer)
	for _, peer := range anchorPeers {
		caCert, _, err := immutil.ReadCertificate(peer.CACert)
		if err != nil {
			return fmt.Errorf("failed to read a CA certificate: " + err.Error())
		}

		orgName := caCert.Subject.Organization[0]
		_, ok := anchors[orgName]
		if ok {
			port, _ := strconv.Atoi(peer.Port)
			anchors[orgName] = append(anchors[orgName], &pp.AnchorPeer{Host: peer.Hostname, Port: int32(port),})
			continue
		}

		anchors[orgName] = make([]*pp.AnchorPeer, 1)
		port, _ := strconv.Atoi(peer.Port)
		anchors[orgName][0] = &pp.AnchorPeer{Host: peer.Hostname, Port: int32(port),}

		mspID := MspIDPrefix + orgName
		appGr.Groups[orgName], err = newOrgGroup(mspID, peer.CACert, peer.AdminCert, peer.TlsCACert, true)
		if err != nil {
			return err
		}
	}

	for orgName, peers := range anchors {
		addValue(appGr.Groups[orgName], channelconfig.AnchorPeersValue(peers), channelconfig.AdminsPolicyKey)
	}

	return nil
}

func newConsortiumsGroup(consortiumName string, anchorPeers []*immop.ExportServiceReply, ordererGr *common.ConfigGroup) (consortiumsGr *common.ConfigGroup, err error) {
	consortiumsGr = common.NewConfigGroup()
	consortiumsGr.ModPolicy = ordererAdminsPolicyName

	acceptAllPolicy := &common.SignaturePolicyEnvelope{
		Version: 0,
		Rule: &common.SignaturePolicy{
			Type: &common.SignaturePolicy_NOutOf_{
				NOutOf: &common.SignaturePolicy_NOutOf{
					N: 0,
					Rules: []*common.SignaturePolicy{},
				}, }, },
		Identities: make([]*msp.MSPPrincipal, 0),
	}
	acceptAllPolicyRaw, err := proto.Marshal(acceptAllPolicy)
	if err != nil {
		return
	}
	consortiumsGr.Policies[channelconfig.AdminsPolicyKey] = &common.ConfigPolicy{
		Policy: &common.Policy{
			Type: int32(common.Policy_SIGNATURE),
			Value: acceptAllPolicyRaw,
		},
		ModPolicy: ordererAdminsPolicyName,
	}

	consortiumsGr.Groups[consortiumName], err = newConsortiumGr(anchorPeers, ordererGr)
	return
}

func newConsortiumGr(anchorPeers []*immop.ExportServiceReply, ordererGr *common.ConfigGroup) (consortiumGr *common.ConfigGroup, retErr error) {
	consortiumGr = common.NewConfigGroup()
	consortiumGr.ModPolicy = ordererAdminsPolicyName

	addValue(consortiumGr, channelconfig.ChannelCreationPolicyValue(policies.ImplicitMetaAnyPolicy(channelconfig.AdminsPolicyKey).Value()), ordererAdminsPolicyName)

	for _, peer := range anchorPeers {
		caCert, _, err := immutil.ReadCertificate(peer.CACert)
		if err != nil {
			retErr = fmt.Errorf("failed to read a CA certificate: " + err.Error())
			return
		}

		orgName := caCert.Subject.Organization[0]
		_, ok := consortiumGr.Groups[orgName]
		if ok {
			continue
		}

		mspID := MspIDPrefix + orgName
		consortiumGr.Groups[orgName], err = newOrgGroup(mspID, peer.CACert, peer.AdminCert, peer.TlsCACert, true)
		if err != nil {
			retErr = err
			return
		}
	}

	var key string 
	var orgGrp *common.ConfigGroup
	for key, orgGrp = range ordererGr.Groups {
		break
	}
	consortiumGr.Groups[key] = orgGrp

	return
}

func newOrgGroup(mspID string, CACert, AdminCert, TlsCACert []byte, nodeOUsF bool) (orgGroup *common.ConfigGroup, retErr error) {
	orgGroup = common.NewConfigGroup()
	orgGroup.ModPolicy = AdminsPolicyKey

	mspConfig := getMSPConfig(mspID, CACert, AdminCert, TlsCACert, nodeOUsF)
	mspConfigRaw, err := proto.Marshal(mspConfig)
	if err != nil {
		retErr = err
		return
	}
	orgGroup.Values["MSP"] = &common.ConfigValue{
		Value: mspConfigRaw,
		ModPolicy: AdminsPolicyKey,
	}


	principalMember, err := proto.Marshal(&msp.MSPRole{MspIdentifier: mspID, Role: msp.MSPRole_MEMBER})
	if err != nil {
		retErr = err
		return
	}
	principalAdmin, err := proto.Marshal(&msp.MSPRole{MspIdentifier: mspID, Role: msp.MSPRole_ADMIN})
	if err != nil {
		retErr = err
		return
	}
	var policies = map[string] []byte {
		"Readers": principalMember,
		"Writers": principalMember,
		"Admins": principalAdmin,
	}

	for key, principal := range policies {
		sp := &common.SignaturePolicyEnvelope{
			Version: 0,
			Rule: &common.SignaturePolicy{
				Type: &common.SignaturePolicy_SignedBy{
					SignedBy: 0,
				},
			},
			Identities: []*msp.MSPPrincipal{
				&msp.MSPPrincipal{
					PrincipalClassification: msp.MSPPrincipal_ROLE,
					Principal: principal,
				},
			},	
		}
		
		spRaw, err := proto.Marshal(sp)
		if err != nil {
			retErr = err
			return
		}

		configPolicy := &common.ConfigPolicy{
			ModPolicy: channelconfig.AdminsPolicyKey,
			Policy: &common.Policy{
				Type: int32(common.Policy_SIGNATURE),
				Value: spRaw,
			},
		}
		
		orgGroup.Policies[key] = configPolicy
	}

	return
}

func getMSPConfig(mspID string, CACert, AdminCert, TlsCACert []byte, nodeOUsF bool) (*msp.MSPConfig) {  
	var nodeOUs *msp.FabricNodeOUs

	if nodeOUsF {
		nodeOUs = &msp.FabricNodeOUs{
			Enable: true,
			ClientOuIdentifier: &msp.FabricOUIdentifier{
				OrganizationalUnitIdentifier: "client", 
				Certificate: CACert},
			PeerOuIdentifier: &msp.FabricOUIdentifier{
				OrganizationalUnitIdentifier: "peer",
				Certificate: CACert},
		}
	}

	// Set FabricCryptoConfig
	cryptoConfig := &msp.FabricCryptoConfig{
		SignatureHashFamily:            "SHA2",
		IdentityIdentifierHashFunction: "SHA256",
	}

	// Compose FabricMSPConfig
	fmspconf := &msp.FabricMSPConfig{
		Admins: [][]byte{AdminCert},
		RootCerts: [][]byte{CACert},
		IntermediateCerts: nil, // not support
		SigningIdentity: nil,
		Name: mspID,
		OrganizationalUnitIdentifiers: nil,
		RevocationList: nil,
		CryptoConfig: cryptoConfig,
		TlsRootCerts: [][]byte{TlsCACert},
		TlsIntermediateCerts: nil, // not support
		FabricNodeOus: nodeOUs,
	}
	fmpsjs, _ := proto.Marshal(fmspconf)
	mspconf := &msp.MSPConfig{Config: fmpsjs, Type: int32(0/*FABRIC*/)}

	return mspconf
}  

func getOrgAnchor(anchorPeers []*immop.ExportServiceReply) (anchors map[string] []*pp.AnchorPeer, retErr error) {
	anchors = make(map[string] []*pp.AnchorPeer)
	for _, peer := range anchorPeers {
		caCert, _, err := immutil.ReadCertificate(peer.CACert)
		if err != nil {
			retErr = fmt.Errorf("failed to read a CA certificate: " + err.Error())
			return
		}

		orgName := caCert.Subject.Organization[0]
		_, ok := anchors[orgName]
		if ok {
			port, _ := strconv.Atoi(peer.Port)
			anchors[orgName] = append(anchors[orgName], &pp.AnchorPeer{Host: peer.Hostname, Port: int32(port),})
			continue
		}

		anchors[orgName] = make([]*pp.AnchorPeer, 1)
		port, _ := strconv.Atoi(peer.Port)
		anchors[orgName][0] = &pp.AnchorPeer{Host: peer.Hostname, Port: int32(port),}
	}

	return
}

func makeChannelCreationTransaction(channelID, secretName  string, anchorPeers []*immop.ExportServiceReply) (*common.Envelope, error) {
	appGr, err := newApplicationGroup(nil)
	if err != nil {
		return nil, err
	}

	err = addOrgAnchorsToAppGroup(appGr, anchorPeers)
	if err != nil {
		return nil, err
	}

	// increase version
	newChannelGroup := &common.ConfigGroup{
		Groups: map[string]*common.ConfigGroup{
			channelconfig.ApplicationGroupKey: appGr,
		},
	}
	
	original := proto.Clone(newChannelGroup).(*common.ConfigGroup)
	original.Groups[channelconfig.ApplicationGroupKey].Values = nil
	original.Groups[channelconfig.ApplicationGroupKey].Policies = nil
	newChannelConfig, err := update.Compute(&common.Config{ChannelGroup: original}, &common.Config{ChannelGroup: newChannelGroup})
	if err != nil {
		return nil, err
	}
	
	consortiumNameRaw, err := proto.Marshal(&common.Consortium{Name: channelID+"Consortium"})
	if err != nil {
		return nil, err
	}

//	newChannelConfig.ChannelId = channelID+"_1"
	newChannelConfig.ChannelId = channelID
	newChannelConfig.ReadSet.Values[channelconfig.ConsortiumKey] = &common.ConfigValue{Version: 0}
	newChannelConfig.WriteSet.Values[channelconfig.ConsortiumKey] = &common.ConfigValue{
		Version: 0,
		Value: consortiumNameRaw,
	}

	newChannelConfigRaw, err := proto.Marshal(newChannelConfig)
	if err != nil {
		return nil, err
	}
	newConfigUpdate := &common.ConfigUpdateEnvelope{ ConfigUpdate: newChannelConfigRaw, }


	readSet, err := mapConfig(newChannelConfig.ReadSet, "Channel")
	writeSet, err := mapConfig(newChannelConfig.WriteSet, "Channel")
	computeDeltaSet(readSet, writeSet)


	keyPem, certPem, err := immutil.K8sGetSignKeyFromSecret(secretName)
	if err != nil {
		return nil, err
	}
	return signConfigUpdate(channelID, OrdererMspIDPrefix, keyPem, certPem, newConfigUpdate)
//	return signConfigUpdate(channelID, "peer0.ledger.com", fabctr.PeerImg, "/var/hyperledger/peer/", mspIDPrefix, newConfigUpdate)
}

/* test only ->*/
type comparable struct {
	*common.ConfigGroup
	*common.ConfigValue
	*common.ConfigPolicy
	key  string
	path []string
}

func (cg comparable) version() uint64 {
	switch {
	case cg.ConfigGroup != nil:
		return cg.ConfigGroup.Version
	case cg.ConfigValue != nil:
		return cg.ConfigValue.Version
	case cg.ConfigPolicy != nil:
		return cg.ConfigPolicy.Version
	}

	// Unreachable
	return 0
}

const (
	groupPrefix  = "[Group]  "
	valuePrefix  = "[Value]  "
	policyPrefix = "[Policy] "

	pathSeparator = "/"
)

func mapConfig(channelGroup *common.ConfigGroup, rootGroupKey string) (map[string]comparable, error) {
	result := make(map[string]comparable)
	if channelGroup != nil {
		err := recurseConfig(result, []string{rootGroupKey}, channelGroup)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func addToMap(cg comparable, result map[string]comparable) error {
	var fqPath string

	switch {
	case cg.ConfigGroup != nil:
		fqPath = groupPrefix
	case cg.ConfigValue != nil:
		fqPath = valuePrefix
	case cg.ConfigPolicy != nil:
		fqPath = policyPrefix
	}

	if len(cg.path) == 0 {
		fqPath += pathSeparator + cg.key
	} else {
		fqPath += pathSeparator + strings.Join(cg.path, pathSeparator) + pathSeparator + cg.key
	}


	result[fqPath] = cg

	return nil
}
// recurseConfig is used only internally by mapConfig
func recurseConfig(result map[string]comparable, path []string, group *common.ConfigGroup) error {
	if err := addToMap(comparable{key: path[len(path)-1], path: path[:len(path)-1], ConfigGroup: group}, result); err != nil {
		return err
	}

	for key, group := range group.Groups {
		nextPath := make([]string, len(path)+1)
		copy(nextPath, path)
		nextPath[len(nextPath)-1] = key
		if err := recurseConfig(result, nextPath, group); err != nil {
			return err
		}
	}

	for key, value := range group.Values {
		if err := addToMap(comparable{key: key, path: path, ConfigValue: value}, result); err != nil {
			return err
		}
	}

	for key, policy := range group.Policies {
		if err := addToMap(comparable{key: key, path: path, ConfigPolicy: policy}, result); err != nil {
			return err
		}
	}

	return nil
}

func computeDeltaSet(readSet, writeSet map[string]comparable) map[string]comparable {
	result := make(map[string]comparable)
	for key, value := range writeSet {
		readVal, ok := readSet[key]
		
		fmt.Printf("log: key=%s, read.ver=%d write.ver=%d ok=%v\n", key, readVal.version(), value.version(), ok)
		if ok && readVal.version() == value.version() {
			continue
		}
		
		// If the key in the readset is a different version, we include it
		// Error checking on the sanity of the update is done against the config
		result[key] = value
	}
	return result
}

/* test only <- */

func signConfigUpdate(channelID, mspPrefix string, keyPem, certPem []byte, newConfigUpdate *common.ConfigUpdateEnvelope) (*common.Envelope, error) {
	signHeader, err := NewSignatureHeader(certPem, mspPrefix)
	if err != nil {
		return nil, err
	}
	msg := append(signHeader, newConfigUpdate.ConfigUpdate ...)
	chSign, err := signMessage(keyPem, msg)
	if err != nil {
		return nil, err
	}

	configSign := &common.ConfigSignature{
		SignatureHeader: signHeader,
		Signature: chSign,
	}

	newConfigUpdate.Signatures = append(newConfigUpdate.Signatures, configSign)

	chHeader, err := proto.Marshal(&common.ChannelHeader{
		Type: int32(common.HeaderType_CONFIG_UPDATE),
		Version: 0,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos: 0,
		},
		ChannelId: channelID,
		Epoch: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create a channel header: %s", err)
	}
		
	header := &common.Header {
		ChannelHeader: chHeader,
		SignatureHeader: signHeader,
	}

	data, err := proto.Marshal(newConfigUpdate)
	if err != nil {
		return nil, fmt.Errorf("could not create a configuration to update channel: %s", err)
	}

	payload, err := proto.Marshal(&common.Payload{
		Header: header,
		Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create a payload: %s", err)
	}

	signPayload, err := signMessage(keyPem, payload)
	if err != nil {
		return nil, err
	}

	return &common.Envelope{
		Payload: payload,
		Signature: signPayload,
	}, nil
}

func makeAnchorPeersUpdate(channelID, ordererSecretName string, anchors []*pp.AnchorPeer, orgName string) (*common.Envelope, error) {
	cfg := &common.ConfigUpdate{
		ChannelId: channelID,
		WriteSet: common.NewConfigGroup(),
		ReadSet: common.NewConfigGroup(),
	}

	anchorsRaw, err := proto.Marshal(channelconfig.AnchorPeersValue(anchors).Value())
	if err != nil {
		return nil, err
	}

	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey] = common.NewConfigGroup()
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Version = 0
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].ModPolicy = channelconfig.AdminsPolicyKey
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName] = common.NewConfigGroup()
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Values[channelconfig.MSPKey] = &common.ConfigValue{}
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.ReadersPolicyKey] = &common.ConfigPolicy{}
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.WritersPolicyKey] = &common.ConfigPolicy{}
	cfg.ReadSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.AdminsPolicyKey] = &common.ConfigPolicy{}

	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey] = common.NewConfigGroup()
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Version = 0
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].ModPolicy = channelconfig.AdminsPolicyKey
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName] = common.NewConfigGroup()
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Version = 1
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].ModPolicy = channelconfig.AdminsPolicyKey
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Values[channelconfig.MSPKey] = &common.ConfigValue{}
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.ReadersPolicyKey] = &common.ConfigPolicy{}
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.WritersPolicyKey] = &common.ConfigPolicy{}
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Policies[channelconfig.AdminsPolicyKey] = &common.ConfigPolicy{}
	cfg.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Values[channelconfig.AnchorPeersKey] = &common.ConfigValue{
		Value: anchorsRaw,
		ModPolicy: channelconfig.AdminsPolicyKey,
	}
	
	cfgRaw, err := proto.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	cfgEnvelope := &common.ConfigUpdateEnvelope{ ConfigUpdate: cfgRaw, }

	keyPem, certPem, err := immutil.K8sGetSignKeyFromSecret(ordererSecretName)
	if err != nil {
		return nil, err
	}
	return signConfigUpdate(channelID, OrdererMspIDPrefix, keyPem, certPem, cfgEnvelope)
}

func sendChannelConfigUpdate(ordererHostname string, chTX *common.Envelope) error {
	_, _, tlsCACert, err := immutil.K8sGetCertsFromSecret(ordererHostname)
	if err != nil {
		return err
	}

	cert, _, err := immutil.ReadCertificate(tlsCACert)
	if err != nil {
		return err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(certPool, ordererHostname)
	conn, err := grpc.Dial(ordererHostname+":7050", grpc.WithTransportCredentials(creds)) 
	if err != nil {
		return fmt.Errorf("did not connect to orderer: %s", err)
	}
	defer conn.Close()

	ordererClient, err := po.NewAtomicBroadcastClient(conn).Broadcast(context.TODO())
	if err != nil {
		return fmt.Errorf("failed connecting to orderer service: %s", err)
	}

	err = ordererClient.Send(chTX)
	if err != nil {
		return fmt.Errorf("send error: %s", err)
	}

	rsp, err := ordererClient.Recv()
	if (err != nil) || (rsp.Status != common.Status_SUCCESS) {
		var errMsg string
		if err != nil {
			errMsg = err.Error()
		}
		
		return fmt.Errorf("get an error response from orderer service: %s, status=%s, info=%s\n",
			errMsg, rsp.Status, rsp.Info)
	}

	return nil
}

func NewSignatureHeader(certPem []byte, mspPrefix string) ([]byte, error) {
	cert, _, err := immutil.ReadCertificate(certPem)
	if err != nil {
		return nil, err
	}
	mspId := mspPrefix + cert.Issuer.Organization[0]
	creator := &msp.SerializedIdentity{Mspid: mspId, IdBytes: certPem}
	creatorData, err := proto.Marshal(creator)
	if err != nil {
		return nil, fmt.Errorf("unexpected certificate: %s", err)
	}

	randNum := make([]byte, 24)
	rand.Read(randNum)

	header := &common.SignatureHeader{
		Creator: creatorData,
		Nonce: randNum,
	}

	headerData, err := proto.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("could not create header: %s\n", err)
	}

	return headerData, nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func signMessage(key, msg []byte) ([]byte, error) {
	privData, _ := pem.Decode(key)
	if x509.IsEncryptedPEMBlock(privData) {
		return nil, fmt.Errorf("not support encrypted PEM")
	}
	
	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unsupported key format: %s", err)
	}
	privKey, ok := privKeyBase.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key\n")
		
	}
	digest := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign a message: %s", err)
	}
	baseN := privKey.Params().N
	if s.Cmp(new(big.Int).Rsh(baseN, 1)) == 1 {
		s.Sub(baseN, s)
	}
	signRaw, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %s", err)
	}

	return signRaw, nil
}
