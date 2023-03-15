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

package fabconf

import (
	"immutil"
	"immop"
	"fmt"
	"strings"
	"strconv"
	"time"

	"encoding/hex"
	"crypto/sha256"
	"crypto/rand"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"fabric/protos/msp"
	"fabric/protos/common"
	pp "fabric/protos/peer"

	"fabric/channelconfig"
)

const (
	AdminsPolicyKey = "Admins"
	ordererAdminsPolicyName = "/Channel/Orderer/Admins"
	BlockValidationPolicyKey = "BlockValidation"
	
	MspIDPrefix        = "MSP"
	OrdererMspIDPrefix = "OrdererMSP"
)

func GenerateTxID(creatorData []byte) (string, []byte) {
	randNum := make([]byte, 24)
	rand.Read(randNum)

	buf := append(randNum, creatorData...)
	digest := sha256.Sum256(buf)
	txID := hex.EncodeToString(digest[:])	

	return txID, randNum[:]
}

func CreateGenesisBlock(channelID, ordererName string, anchorPeers []*immop.ExportServiceReply) (blockRaw []byte, err error) { 
	chGr, err := newChannelGroup(channelID+"Consortium", ordererName, anchorPeers)
	if err != nil {
		return
	}

	txID, nonce := GenerateTxID(nil)
	chHeader, _ := proto.Marshal(&common.ChannelHeader{
		Type: int32(common.HeaderType_CONFIG),
		Version: int32(1),
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos: 0,
		},
		ChannelId: channelID,
		Epoch: uint64(0),
		TxId: txID,
	})
	signatureHeader, _ := proto.Marshal(&common.SignatureHeader{
		Creator: nil,
		Nonce: nonce,
	})

	payloadData, _ := proto.Marshal(&common.ConfigEnvelope{Config: &common.Config{ChannelGroup: chGr}})
	payload, _ := proto.Marshal(&common.Payload{
		Header: &common.Header{
			ChannelHeader: chHeader,
			SignatureHeader: signatureHeader,
		},
		Data: payloadData,
	})
	
	envelope, _ := proto.Marshal(&common.Envelope{
		Payload: payload,
		Signature: nil,
	})
	envelopeHash := sha256.New()
	envelopeHash.Write(envelope)
	
	block := &common.Block{
		Header: &common.BlockHeader{
			Number: 0,
			PreviousHash: nil,
			DataHash: envelopeHash.Sum(nil),
		},
		Data: &common.BlockData{
			Data: [][]byte{envelope},
		},
		Metadata: &common.BlockMetadata{
		},
	}

	lastConfigVal, _ := proto.Marshal(&common.LastConfig{Index: 0})
	block.Metadata.Metadata = make([][]byte, len(common.BlockMetadataIndex_name))
	block.Metadata.Metadata[common.BlockMetadataIndex_LAST_CONFIG], _ = proto.Marshal(&common.Metadata{
		Value: lastConfigVal,
	})
	
	blockRaw, err = proto.Marshal(block)
	return
}

func newConfigGroup() *common.ConfigGroup {
	return &common.ConfigGroup{
		Groups: make(map[string]*common.ConfigGroup),
		Values: make(map[string]*common.ConfigValue),
		Policies: make(map[string]*common.ConfigPolicy),
	}
}

func newChannelGroup(consortiumName, ordererName string, anchorPeers []*immop.ExportServiceReply) (chGr *common.ConfigGroup, err error) {
	chGr = newConfigGroup()
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
	//addPolicy(cg, policies.ImplicitMetaMajorityPolicy(channelconfig.AdminsPolicyKey), channelconfig.AdminsPolicyKey)

	//ddPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.ReadersPolicyKey), channelconfig.AdminsPolicyKey)
	//addPolicy(cg, policies.ImplicitMetaAnyPolicy(channelconfig.WritersPolicyKey), channelconfig.AdminsPolicyKey)	
	addPolicyImplicitMeta(cg, channelconfig.AdminsPolicyKey, &common.ImplicitMetaPolicy{
		Rule: common.ImplicitMetaPolicy_MAJORITY,
		SubPolicy: channelconfig.AdminsPolicyKey,
	}, channelconfig.AdminsPolicyKey)
	addPolicyImplicitMeta(cg, channelconfig.ReadersPolicyKey, &common.ImplicitMetaPolicy{
		Rule: common.ImplicitMetaPolicy_ANY,
		SubPolicy: channelconfig.ReadersPolicyKey,
	}, channelconfig.AdminsPolicyKey)
	addPolicyImplicitMeta(cg, channelconfig.WritersPolicyKey, &common.ImplicitMetaPolicy{
		Rule: common.ImplicitMetaPolicy_ANY,
		SubPolicy: channelconfig.WritersPolicyKey,
	}, channelconfig.AdminsPolicyKey)	
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

func addPolicyImplicitMeta(cg *common.ConfigGroup, key string, value *common.ImplicitMetaPolicy, modPolicy string) {
	valueRaw, _ := proto.Marshal(value)
	cg.Policies[key] = &common.ConfigPolicy{
		Policy: &common.Policy{
			Type: int32(common.Policy_IMPLICIT_META),
			Value: valueRaw,
		},
		ModPolicy: modPolicy,
	}
}

/*
func addPolicy(cg *common.ConfigGroup, policy policies.ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &common.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}
*/


func newOrdererGroup(ordererName string) (ordererGr *common.ConfigGroup , err error) {
	ordererGr = newConfigGroup()
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
	appGr = newConfigGroup()
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
	consortiumsGr = newConfigGroup()
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
	consortiumGr = newConfigGroup()
	consortiumGr.ModPolicy = ordererAdminsPolicyName

	policyValRaw, _ := proto.Marshal(&common.ImplicitMetaPolicy{
		Rule: common.ImplicitMetaPolicy_ANY,
		SubPolicy: channelconfig.AdminsPolicyKey,
	})
	policy := &common.Policy{
		Type: int32(common.Policy_IMPLICIT_META),
		Value: policyValRaw,
	}

	addValue(consortiumGr, channelconfig.ChannelCreationPolicyValue(policy), ordererAdminsPolicyName)

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
	orgGroup = newConfigGroup()
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

func CreateProposalFromCIS(hType common.HeaderType, chName string, cis *pp.ChaincodeInvocationSpec, creator []byte) (propRaw []byte,prop *pp.Proposal,  retErr error) {
	defer func() {
		if retErr == nil {
			return
		}
		
		retErr = fmt.Errorf("failed to marshal a message: %s", retErr)
	}()
	
	txID, nonce := GenerateTxID(creator)
	headerEx, retErr := proto.Marshal(&pp.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId})
	if retErr != nil {
		return
	}
	cisRaw, retErr := proto.Marshal(cis)
	if retErr != nil {
		return
	}
	ccPropPayload, retErr := proto.Marshal(&pp.ChaincodeProposalPayload{Input: cisRaw})
	if retErr != nil {
		return
	}
	
	chHeader, retErr := proto.Marshal(&common.ChannelHeader{
		Type: int32(hType),
		TxId: txID,
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos: 0,
		},
		ChannelId: chName,
		Epoch: uint64(0),
		Extension: headerEx,
	})
	if retErr != nil {
		return
	}
	signatureHeader, retErr := proto.Marshal(&common.SignatureHeader{
		Creator: creator,
		Nonce: nonce,
	})
	if retErr != nil {
		return
	}
	header, retErr := proto.Marshal(&common.Header{
		ChannelHeader: chHeader,
		SignatureHeader: signatureHeader,
	})
	if retErr != nil {
		return
	}

	prop = &pp.Proposal{
		Header: header,
		Payload: ccPropPayload,
	}
	propRaw, retErr = proto.Marshal(prop)
	if retErr != nil {
		return
	}

	return // success
}
