#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::endpoint::{Endpoint, EndpointRequest, EndpointResponse};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
pub use sp_domains::{ChainId, ChannelId};
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::DispatchError;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Unique Id of a message between two chains.
pub type MessageId = (ChannelId, Nonce);

/// Unique message key for Outbox and Inbox responses
pub type MessageKey = (ChainId, ChannelId, Nonce);

/// Fee model to send a request and receive a response from another chain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee to relay message from one chain to another
    pub relay_fee: Balance,
}

/// State of a channel.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ChannelState {
    /// Channel between chains is initiated but do not yet send or receive messages in this state.
    #[default]
    Initiated,
    /// Channel is open and can send and receive messages.
    Open,
    /// Channel is closed and do not send or receive messages.
    Closed,
}

/// Channel describes a bridge to exchange messages between two chains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Channel<Balance, AccountId> {
    /// Channel identifier.
    pub channel_id: ChannelId,
    /// State of the channel.
    pub state: ChannelState,
    /// Next inbox nonce.
    pub next_inbox_nonce: Nonce,
    /// Next outbox nonce.
    pub next_outbox_nonce: Nonce,
    /// Latest outbox message nonce for which response was received from dst_chain.
    pub latest_response_received_message_nonce: Option<Nonce>,
    /// Maximum outgoing non-delivered messages.
    pub max_outgoing_messages: u32,
    /// Fee model for this channel between the chains.
    pub fee: FeeModel<Balance>,
    /// Owner of the channel
    /// Owner maybe None if the channel was initiated on the other chain.
    pub maybe_owner: Option<AccountId>,
    /// The amount of funds put on hold by the owner account for this channel
    pub channel_reserve_fee: Balance,
}

/// Channel open parameters
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct ChannelOpenParams<Balance> {
    pub max_outgoing_messages: u32,
    pub fee_model: FeeModel<Balance>,
}

/// Defines protocol requests performed on chains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest<Balance> {
    /// Request to open a channel with foreign chain.
    ChannelOpen(ChannelOpenParams<Balance>),
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

    pub fn consensus_mmr_proof(
        &self,
    ) -> ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>
    where
        CBlockNumber: Clone,
        CBlockHash: Clone,
        MmrHash: Clone,
    {
        match self {
            Proof::Consensus {
                consensus_chain_mmr_proof,
                ..
            } => consensus_chain_mmr_proof.clone(),
            Proof::Domain {
                consensus_chain_mmr_proof,
                ..
            } => consensus_chain_mmr_proof.clone(),
        }
    }

    pub fn domain_proof(&self) -> Option<StorageProof> {
        match self {
            Proof::Consensus { .. } => None,
            Proof::Domain { domain_proof, .. } => Some(domain_proof.clone()),
        }
    }
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

impl BlockMessageWithStorageKey {
    pub fn id(&self) -> (ChannelId, Nonce) {
        (self.channel_id, self.nonce)
    }
}

/// Set of messages with storage keys to be relayed in a given block..
#[derive(Default, Debug, Encode, Decode, TypeInfo, Clone, Eq, PartialEq)]
pub struct BlockMessagesWithStorageKey {
    pub outbox: Vec<BlockMessageWithStorageKey>,
    pub inbox_responses: Vec<BlockMessageWithStorageKey>,
}

impl BlockMessagesWithStorageKey {
    pub fn is_empty(&self) -> bool {
        self.outbox.is_empty() && self.inbox_responses.is_empty()
    }
}

impl<BlockNumber, BlockHash, MmrHash> CrossDomainMessage<BlockNumber, BlockHash, MmrHash> {
    pub fn from_relayer_msg_with_proof(
        r_msg: BlockMessageWithStorageKey,
        proof: Proof<BlockNumber, BlockHash, MmrHash>,
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
