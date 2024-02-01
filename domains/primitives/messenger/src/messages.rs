use crate::endpoint::{Endpoint, EndpointRequest, EndpointResponse};
use codec::{Decode, Encode, FullCodec};
use frame_support::storage::generator::StorageMap;
use frame_support::storage::storage_prefix;
use frame_support::Identity;
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
pub use sp_domains::ChainId;
use sp_domains::DomainId;
use sp_mmr_primitives::{EncodableOpaqueLeaf, Proof as MmrProof};
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::{sp_std, DispatchError};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::StorageProof;

/// Channel identity.
pub type ChannelId = U256;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Unique Id of a message between two chains.
pub type MessageId = (ChannelId, Nonce);

/// Fee model to send a request and receive a response from another chain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee to relay message from one chain to another
    pub relay_fee: Balance,
}

/// Parameters for a new channel between two chains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct InitiateChannelParams<Balance> {
    pub max_outgoing_messages: u32,
    pub fee_model: FeeModel<Balance>,
}

/// Defines protocol requests performed on chains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest<Balance> {
    /// Request to open a channel with foreign chain.
    ChannelOpen(InitiateChannelParams<Balance>),
    /// Request to close an open channel with foreign chain.
    ChannelClose,
}

/// Defines protocol requests performed on chains.
pub type ProtocolMessageResponse = Result<(), DispatchError>;

/// Protocol message that encompasses  request or its response.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum RequestResponse<Request, Response> {
    Request(Request),
    Response(Response),
}

/// Payload of the message
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Payload<Balance> {
    /// Protocol message.
    Protocol(RequestResponse<ProtocolMessageRequest<Balance>, ProtocolMessageResponse>),
    /// Endpoint message.
    Endpoint(RequestResponse<EndpointRequest, EndpointResponse>),
}

/// Versioned message payload
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum VersionedPayload<Balance> {
    V0(Payload<Balance>),
}

/// Message weight tag used to indicate the consumed weight when handling the message
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Default)]
pub enum MessageWeightTag {
    ProtocolChannelOpen,
    ProtocolChannelClose,
    EndpointRequest(Endpoint),
    EndpointResponse(Endpoint),
    #[default]
    None,
}

impl MessageWeightTag {
    // Construct the weight tag for outbox message based on the outbox payload
    pub fn outbox<Balance>(outbox_payload: &VersionedPayload<Balance>) -> Self {
        match outbox_payload {
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelOpen(_),
            ))) => MessageWeightTag::ProtocolChannelOpen,
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelClose,
            ))) => MessageWeightTag::ProtocolChannelClose,
            VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(endpoint_req))) => {
                MessageWeightTag::EndpointRequest(endpoint_req.dst_endpoint.clone())
            }
            _ => MessageWeightTag::None,
        }
    }

    // Construct the weight tag for inbox response based on the weight tag of the request
    // message and the response payload
    pub fn inbox_response<Balance>(
        req_type: MessageWeightTag,
        resp_payload: &VersionedPayload<Balance>,
    ) -> Self {
        match (req_type, resp_payload) {
            (
                MessageWeightTag::ProtocolChannelOpen,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(Ok(_)))),
            ) => MessageWeightTag::ProtocolChannelOpen,
            (
                MessageWeightTag::EndpointRequest(endpoint),
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(_))),
            ) => MessageWeightTag::EndpointResponse(endpoint),
            _ => MessageWeightTag::None,
        }
    }
}

/// Message contains information to be sent to or received from another chain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Message<Balance> {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Payload of the message
    pub payload: VersionedPayload<Balance>,
    /// Last delivered message response nonce on src_chain.
    pub last_delivered_message_response_nonce: Option<Nonce>,
}

/// Block info used as part of the Cross chain message proof.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct BlockInfo<Number, Hash> {
    /// Block number of the chain.
    pub block_number: Number,
    /// Block hash of the chain.
    pub block_hash: Hash,
}

/// Consensus chain MMR leaf and its Proof at specific block
#[derive(Debug, Encode, Decode, Eq, PartialEq, TypeInfo)]
pub struct ConsensusChainMmrLeafProof<BlockNumber, BlockHash, MmrHash> {
    /// Consensus block info from which this proof was generated.
    pub block_info: BlockInfo<BlockNumber, BlockHash>,
    /// Encoded MMR leaf
    pub opaque_mmr_leaf: EncodableOpaqueLeaf,
    /// MMR proof for the leaf above.
    pub proof: MmrProof<MmrHash>,
}

// TODO: update upstream `EncodableOpaqueLeaf` to derive clone.
impl<BlockNumber, BlockHash, MmrHash> Clone
    for ConsensusChainMmrLeafProof<BlockNumber, BlockHash, MmrHash>
where
    BlockNumber: Clone,
    BlockHash: Clone,
    MmrHash: Clone,
{
    fn clone(&self) -> Self {
        Self {
            block_info: self.block_info.clone(),
            opaque_mmr_leaf: EncodableOpaqueLeaf(self.opaque_mmr_leaf.0.clone()),
            proof: self.proof.clone(),
        }
    }
}

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Proof<CBlockNumber, CBlockHash, MmrHash> {
    Consensus {
        /// Consensus chain MMR leaf proof.
        consensus_chain_mmr_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
        /// Storage proof that message is processed on src_chain.
        message_proof: StorageProof,
    },
    Domain {
        /// Consensus chain MMR leaf proof.
        consensus_chain_mmr_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
        /// Storage proof that src domain chain's block is out of the challenge period on Consensus chain.
        domain_proof: StorageProof,
        /// Storage proof that message is processed on src_chain.
        message_proof: StorageProof,
    },
}

impl<CBlockNumber, CBlockHash, MmrHash> Proof<CBlockNumber, CBlockHash, MmrHash> {
    pub fn message_proof(&self) -> StorageProof {
        match self {
            Proof::Consensus { message_proof, .. } => message_proof.clone(),
            Proof::Domain { message_proof, .. } => message_proof.clone(),
        }
    }
}

/// Holds the Block info and state roots from which a proof was constructed.
#[derive(Debug, Default, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct ExtractedStateRootsFromProof<BlockNumber, BlockHash, StateRoot> {
    /// Consensus chain block info when proof was constructed
    pub consensus_chain_block_info: BlockInfo<BlockNumber, BlockHash>,
    /// State root of Consensus chain at above number and block hash.
    pub consensus_chain_state_root: StateRoot,
    /// Storage proof that src chain state_root is registered on Consensus chain.
    /// This is optional when the src_chain is the consensus chain.
    /// BlockNumber and BlockHash is used with storage proof to validate and fetch its state root.
    pub domain_info: Option<(DomainId, BlockInfo<BlockNumber, BlockHash>, StateRoot)>,
}

/// Cross Domain message contains Message and its proof on src_chain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CrossDomainMessage<CBlockNumber, CBlockHash, MmrHash> {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Proof of message processed on src_chain.
    pub proof: Proof<CBlockNumber, CBlockHash, MmrHash>,
    /// The message weight tag
    pub weight_tag: MessageWeightTag,
}

/// Message with storage key to generate storage proof using the backend.
#[derive(Debug, Encode, Decode, TypeInfo, Clone, Eq, PartialEq)]
pub struct BlockMessageWithStorageKey {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Storage key to generate proof for using proof backend.
    pub storage_key: Vec<u8>,
    /// The message weight tag
    pub weight_tag: MessageWeightTag,
}

/// Set of messages with storage keys to be relayed in a given block..
#[derive(Default, Debug, Encode, Decode, TypeInfo, Clone, Eq, PartialEq)]
pub struct BlockMessagesWithStorageKey {
    pub outbox: Vec<BlockMessageWithStorageKey>,
    pub inbox_responses: Vec<BlockMessageWithStorageKey>,
}

// TODO: remove or update this accordingly
impl<BlockNumber, BlockHash, StateRoot> CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    pub fn from_relayer_msg_with_proof(
        r_msg: BlockMessageWithStorageKey,
        proof: Proof<BlockNumber, BlockHash, StateRoot>,
    ) -> Self {
        CrossDomainMessage {
            src_chain_id: r_msg.src_chain_id,
            dst_chain_id: r_msg.dst_chain_id,
            channel_id: r_msg.channel_id,
            nonce: r_msg.nonce,
            proof,
            weight_tag: r_msg.weight_tag,
        }
    }
}

// TODO: remove or update this accordingly
/// This is a representation of actual StateRoots storage in pallet-domains.
/// Any change in key or value there should be changed here accordingly.
pub struct DomainStateRootStorage<Number, Hash, StateRoot>(PhantomData<(Number, Hash, StateRoot)>);

impl<Number, Hash, StateRoot> StorageMap<(DomainId, Number, Hash), StateRoot>
    for DomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    type Query = Option<StateRoot>;
    type Hasher = Identity;

    fn pallet_prefix() -> &'static [u8] {
        "Domains".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "StateRoots".as_ref()
    }

    fn prefix_hash() -> [u8; 32] {
        storage_prefix(Self::pallet_prefix(), Self::storage_prefix())
    }

    fn from_optional_value_to_query(v: Option<StateRoot>) -> Self::Query {
        v
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<StateRoot> {
        v
    }
}

impl<Number, Hash, StateRoot> DomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    pub fn storage_key(domain_id: DomainId, number: Number, hash: Hash) -> StorageKey {
        StorageKey(Self::storage_map_final_key::<(DomainId, Number, Hash)>((
            domain_id, number, hash,
        )))
    }
}
