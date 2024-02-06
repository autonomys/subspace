use crate::endpoint::{Endpoint, EndpointRequest, EndpointResponse};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::ChainId;
use sp_mmr_primitives::{EncodableOpaqueLeaf, Proof as MmrProof};
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::{sp_std, DispatchError};
use sp_std::vec;
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

/// Consensus chain MMR leaf and its Proof at specific block
#[derive(Debug, Encode, Decode, Eq, PartialEq, TypeInfo)]
pub struct ConsensusChainMmrLeafProof<BlockHash, MmrHash> {
    /// Consensus block info from which this proof was generated.
    pub consensus_block_hash: BlockHash,
    /// Encoded MMR leaf
    pub opaque_mmr_leaf: EncodableOpaqueLeaf,
    /// MMR proof for the leaf above.
    pub proof: MmrProof<MmrHash>,
}

impl<BlockHash, MmrHash> Default for ConsensusChainMmrLeafProof<BlockHash, MmrHash>
where
    BlockHash: Default,
{
    fn default() -> Self {
        Self {
            consensus_block_hash: Default::default(),
            opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
            proof: MmrProof {
                leaf_indices: vec![],
                leaf_count: 0,
                items: vec![],
            },
        }
    }
}

impl<BlockHash, MmrHash> Clone for ConsensusChainMmrLeafProof<BlockHash, MmrHash>
where
    BlockHash: Clone,
    MmrHash: Clone,
{
    fn clone(&self) -> Self {
        Self {
            consensus_block_hash: self.consensus_block_hash.clone(),
            opaque_mmr_leaf: EncodableOpaqueLeaf(self.opaque_mmr_leaf.0.clone()),
            proof: self.proof.clone(),
        }
    }
}

/// Proof combines the storage proofs to validate messages.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Proof<CBlockHash, MmrHash> {
    /// Consensus chain MMR leaf proof.
    pub consensus_chain_mmr_proof: ConsensusChainMmrLeafProof<CBlockHash, MmrHash>,
    /// Storage proof that src domain chain's block is out of the challenge period on Consensus chain.
    /// This is None when the src_chain is Consensus.
    pub domain_proof: Option<StorageProof>,
    /// Storage proof that message is processed on src_chain.
    pub message_proof: StorageProof,
}

impl<CBlockHash: Default, MmrHash: Default> Proof<CBlockHash, MmrHash> {
    #[cfg(feature = "runtime-benchmarks")]
    pub fn dummy() -> Self {
        Proof {
            consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
                consensus_block_hash: Default::default(),
                opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                proof: MmrProof {
                    leaf_indices: vec![],
                    leaf_count: 0,
                    items: vec![],
                },
            },
            domain_proof: None,
            message_proof: StorageProof::empty(),
        }
    }
}

/// Cross Domain message contains Message and its proof on src_chain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CrossDomainMessage<CBlockHash, MmrHash> {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Proof of message processed on src_chain.
    pub proof: Proof<CBlockHash, MmrHash>,
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

impl<BlockHash, StateRoot> CrossDomainMessage<BlockHash, StateRoot> {
    pub fn from_relayer_msg_with_proof(
        r_msg: BlockMessageWithStorageKey,
        proof: Proof<BlockHash, StateRoot>,
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
