// Copyied from Hyperledger Fabric 1.4
// https://github.com/hyperledger/fabric/common/channelconfig

package channelconfig

import (
	"math"

	"google.golang.org/protobuf/proto"
	cb "fabric/protos/common"
	ab "fabric/protos/orderer"
	pb "fabric/protos/peer"
)


// Channel config keys
const (
        // ConsortiumKey is the key for the cb.ConfigValue for the Consortium message
        ConsortiumKey = "Consortium"

        // HashingAlgorithmKey is the cb.ConfigItem type key name for the HashingAlgorithm message
        HashingAlgorithmKey = "HashingAlgorithm"

        // BlockDataHashingStructureKey is the cb.ConfigItem type key name for the BlockDataHashingStructure message
        BlockDataHashingStructureKey = "BlockDataHashingStructure"

        // OrdererAddressesKey is the cb.ConfigItem type key name for the OrdererAddresses message
        OrdererAddressesKey = "OrdererAddresses"

        // GroupKey is the name of the channel group
        ChannelGroupKey = "Channel"

        // CapabilitiesKey is the name of the key which refers to capabilities, it appears at the channel,
        // application, and orderer levels and this constant is used for all three.
        CapabilitiesKey = "Capabilities"
)

const (
        // OrdererGroupKey is the group name for the orderer config.
        OrdererGroupKey = "Orderer"
)

const (
        // ConsensusTypeKey is the cb.ConfigItem type key name for the ConsensusType message.
        ConsensusTypeKey = "ConsensusType"

        // BatchSizeKey is the cb.ConfigItem type key name for the BatchSize message.
        BatchSizeKey = "BatchSize"

        // BatchTimeoutKey is the cb.ConfigItem type key name for the BatchTimeout message.
        BatchTimeoutKey = "BatchTimeout"

        // ChannelRestrictionsKey is the key name for the ChannelRestrictions message.
        ChannelRestrictionsKey = "ChannelRestrictions"

        // KafkaBrokersKey is the cb.ConfigItem type key name for the KafkaBrokers message.
        KafkaBrokersKey = "KafkaBrokers"

        // EndpointsKey is the cb.COnfigValue key name for the Endpoints message in the OrdererOrgGroup.
        EndpointsKey = "Endpoints"
)

const (
        // ApplicationGroupKey is the group name for the Application config
        ApplicationGroupKey = "Application"

        // ACLsKey is the name of the ACLs config
        ACLsKey = "ACLs"
)

const (
        // AnchorPeersKey is the key name for the AnchorPeers ConfigValue
        AnchorPeersKey = "AnchorPeers"
)

const (
	// ChannelCreationPolicyKey is the key used in the consortium config to denote the policy
	// to be used in evaluating whether a channel creation request is authorized
	ChannelCreationPolicyKey = "ChannelCreationPolicy"
)

const (
	// ConsortiumsGroupKey is the group name for the consortiums config
	ConsortiumsGroupKey = "Consortiums"
)

const (
	// ReadersPolicyKey is the key used for the read policy
	ReadersPolicyKey = "Readers"

	// WritersPolicyKey is the key used for the read policy
	WritersPolicyKey = "Writers"

	// AdminsPolicyKey is the key used for the read policy
	AdminsPolicyKey = "Admins"
	
	defaultHashingAlgorithm = "SHA256"

	defaultBlockDataHashingStructureWidth = math.MaxUint32	
)

// ConfigValue defines a common representation for different *cb.ConfigValue values.
type ConfigValue interface {
	// Key is the key this value should be stored in the *cb.ConfigGroup.Values map.
	Key() string

	// Value is the message which should be marshaled to opaque bytes for the *cb.ConfigValue.value.
	Value() proto.Message
}

// StandardConfigValue implements the ConfigValue interface.
type StandardConfigValue struct {
	key   string
	value proto.Message
}

// Key is the key this value should be stored in the *cb.ConfigGroup.Values map.
func (scv *StandardConfigValue) Key() string {
	return scv.key
}

// Value is the message which should be marshaled to opaque bytes for the *cb.ConfigValue.value.
func (scv *StandardConfigValue) Value() proto.Message {
	return scv.value
}

// ConsortiumValue returns the config definition for the consortium name.
// It is a value for the channel group.
func ConsortiumValue(name string) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsortiumKey,
		value: &cb.Consortium{
			Name: name,
		},
	}
}

// HashingAlgorithm returns the only currently valid hashing algorithm.
// It is a value for the /Channel group.
func HashingAlgorithmValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: HashingAlgorithmKey,
		value: &cb.HashingAlgorithm{
			Name: defaultHashingAlgorithm,
		},
	}
}

// BlockDataHashingStructureValue returns the only currently valid block data hashing structure.
// It is a value for the /Channel group.
func BlockDataHashingStructureValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: BlockDataHashingStructureKey,
		value: &cb.BlockDataHashingStructure{
			Width: defaultBlockDataHashingStructureWidth,
		},
	}
}

// OrdererAddressesValue returns the a config definition for the orderer addresses.
// It is a value for the /Channel group.
func OrdererAddressesValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: OrdererAddressesKey,
		value: &cb.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// ConsensusTypeValue returns the config definition for the orderer consensus type.
// It is a value for the /Channel/Orderer group.
func ConsensusTypeValue(consensusType string, consensusMetadata []byte) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsensusTypeKey,
		value: &ab.ConsensusType{
			Type:     consensusType,
			Metadata: consensusMetadata,
		},
	}
}

// BatchSizeValue returns the config definition for the orderer batch size.
// It is a value for the /Channel/Orderer group.
func BatchSizeValue(maxMessages, absoluteMaxBytes, preferredMaxBytes uint32) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchSizeKey,
		value: &ab.BatchSize{
			MaxMessageCount:   maxMessages,
			AbsoluteMaxBytes:  absoluteMaxBytes,
			PreferredMaxBytes: preferredMaxBytes,
		},
	}
}

// BatchTimeoutValue returns the config definition for the orderer batch timeout.
// It is a value for the /Channel/Orderer group.
func BatchTimeoutValue(timeout string) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchTimeoutKey,
		value: &ab.BatchTimeout{
			Timeout: timeout,
		},
	}
}

// ChannelRestrictionsValue returns the config definition for the orderer channel restrictions.
// It is a value for the /Channel/Orderer group.
func ChannelRestrictionsValue(maxChannelCount uint64) *StandardConfigValue {
	return &StandardConfigValue{
		key: ChannelRestrictionsKey,
		value: &ab.ChannelRestrictions{
			MaxCount: maxChannelCount,
		},
	}
}

// KafkaBrokersValue returns the config definition for the addresses of the ordering service's Kafka brokers.
// It is a value for the /Channel/Orderer group.
func KafkaBrokersValue(brokers []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: KafkaBrokersKey,
		value: &ab.KafkaBrokers{
			Brokers: brokers,
		},
	}
}

// CapabilitiesValue returns the config definition for a a set of capabilities.
// It is a value for the /Channel/Orderer, Channel/Application/, and /Channel groups.
func CapabilitiesValue(capabilities map[string]bool) *StandardConfigValue {
	c := &cb.Capabilities{
		Capabilities: make(map[string]*cb.Capability),
	}

	for capability, required := range capabilities {
		if !required {
			continue
		}
		c.Capabilities[capability] = &cb.Capability{}
	}

	return &StandardConfigValue{
		key:   CapabilitiesKey,
		value: c,
	}
}

// EndpointsValue returns the config definition for the orderer addresses at an org scoped level.
// It is a value for the /Channel/Orderer/<OrgName> group.
func EndpointsValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: EndpointsKey,
		value: &cb.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// AnchorPeersValue returns the config definition for an org's anchor peers.
// It is a value for the /Channel/Application/*.
func AnchorPeersValue(anchorPeers []*pb.AnchorPeer) *StandardConfigValue {
	return &StandardConfigValue{
		key:   AnchorPeersKey,
		value: &pb.AnchorPeers{AnchorPeers: anchorPeers},
	}
}

// ChannelCreationPolicyValue returns the config definition for a consortium's channel creation policy
// It is a value for the /Channel/Consortiums/*/*.
func ChannelCreationPolicyValue(policy *cb.Policy) *StandardConfigValue {
	return &StandardConfigValue{
		key:   ChannelCreationPolicyKey,
		value: policy,
	}
}

// ACLsValues returns the config definition for an applications resources based ACL definitions.
// It is a value for the /Channel/Application/.
func ACLValues(acls map[string]string) *StandardConfigValue {
	a := &pb.ACLs{
		Acls: make(map[string]*pb.APIResource),
	}

	for apiResource, policyRef := range acls {
		a.Acls[apiResource] = &pb.APIResource{PolicyRef: policyRef}
	}

	return &StandardConfigValue{
		key:   ACLsKey,
		value: a,
	}
}
