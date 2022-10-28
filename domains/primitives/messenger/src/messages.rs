use crate::endpoint::{EndpointRequest, EndpointResponse};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::app_crypto::sp_core::storage::StorageKey;
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::traits::CheckedAdd;
use sp_runtime::DispatchError;
use sp_trie::StorageProof;

/// Channel identity.
pub type ChannelId = U256;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Unique Id of a message between two domains.
pub type MessageId = (ChannelId, Nonce);

/// Execution Fee to execute a send or receive request.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct ExecutionFee<Balance> {
    /// Fee paid to the relayer pool for the execution.
    pub relayer_pool_fee: Balance,
    /// Fee paid to the network for computation.
    pub compute_fee: Balance,
}

/// Fee model to send a request and receive a response from another domain.
/// A user of the endpoint will pay
///     - outbox_fee on src_domain
///     - inbox_fee on dst_domain
/// The reward is distributed to
///     - src_domain relayer pool when the response is received
///     - dst_domain relayer pool when the response acknowledgement from src_domain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee paid by the endpoint user for any outgoing message.
    pub outbox_fee: ExecutionFee<Balance>,
    /// Fee paid by the endpoint user any incoming message.
    pub inbox_fee: ExecutionFee<Balance>,
}

impl<Balance: CheckedAdd> FeeModel<Balance> {
    pub fn outbox_fee(&self) -> Option<Balance> {
        self.outbox_fee
            .compute_fee
            .checked_add(&self.outbox_fee.relayer_pool_fee)
    }

    pub fn inbox_fee(&self) -> Option<Balance> {
        self.inbox_fee
            .compute_fee
            .checked_add(&self.inbox_fee.relayer_pool_fee)
    }
}

/// Parameters for a new channel between two domains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct InitiateChannelParams<Balance> {
    pub max_outgoing_messages: u32,
    pub fee_model: FeeModel<Balance>,
}

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest<Balance> {
    /// Request to open a channel with foreign domain.
    ChannelOpen(InitiateChannelParams<Balance>),
    /// Request to close an open channel with foreign domain.
    ChannelClose,
}

/// Defines protocol requests performed on domains.
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

/// Message contains information to be sent to or received from another domain
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Message<DomainId, Balance> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Payload of the message
    pub payload: VersionedPayload<Balance>,
    /// Last delivered message response nonce on src_domain.
    pub last_delivered_message_response_nonce: Option<Nonce>,
}

/// Proof combines the storage proofs to validate messages.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Proof<StateRoot> {
    pub state_root: StateRoot,
    /// Storage proof that src_domain state_root is registered on System domain
    // TODO(ved): add system domain proof when store is available
    /// Storage proof that message is processed on src_domain.
    pub message_proof: StorageProof,
}

/// Cross Domain message contains Message and its proof on src_domain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CrossDomainMessage<DomainId, StateRoot> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Proof of message processed on src_domain.
    pub proof: Proof<StateRoot>,
}

/// Relayer message with storage key to generate storage proof using the backend.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq)]
pub struct RelayerMessageWithStorageKey<DomainId> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Storage key to generate proof for using proof backend.
    pub storage_key: StorageKey,
}

/// Set of messages with storage keys to be relayed by a given relayer.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq)]
pub struct RelayerMessagesWithStorageKey<DomainId> {
    pub outbox: Vec<RelayerMessageWithStorageKey<DomainId>>,
    pub inbox_responses: Vec<RelayerMessageWithStorageKey<DomainId>>,
}

impl<DomainId, StateRoot> CrossDomainMessage<DomainId, StateRoot> {
    pub fn from_relayer_msg_with_proof(
        r_msg: RelayerMessageWithStorageKey<DomainId>,
        proof: Proof<StateRoot>,
    ) -> Self {
        CrossDomainMessage {
            src_domain_id: r_msg.src_domain_id,
            dst_domain_id: r_msg.dst_domain_id,
            channel_id: r_msg.channel_id,
            nonce: r_msg.nonce,
            proof,
        }
    }
}
