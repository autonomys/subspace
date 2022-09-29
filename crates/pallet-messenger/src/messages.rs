use crate::verification::Proof;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum ProtocolMessageRequest {
    /// Request to open a channel with foreign domain.
    ChannelOpen,
    /// Request to close an open channel with foreign domain.
    ChannelClose,
}

/// Defines protocol response of request performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum ProtocolMessageResponse {
    /// Request was approved on the dst_domain
    Accepted,
    /// Request was denied on dst_domain
    Denied,
}

/// Protocol message that encompasses  request or its response.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum ProtocolMessage {
    /// Request to perform on dst_domain.
    Request(ProtocolMessageRequest),
    /// Response to action .
    Response(ProtocolMessageResponse),
}

/// Message states during a message life cycle.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum MessageState {
    /// Message is accepted and sent to dst_domain.
    Sent,
    /// Message response was received from dst_domain.
    ResponseReceived,
}

/// Message payload.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum MessagePayload {
    /// Protocol specific message.
    ProtocolMessage(ProtocolMessage),
}

/// Versioned message payload
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) enum VersionedPayload {
    V0(MessagePayload),
}

/// Message contains information to be sent to or received from another domain
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) struct Message<DomainId, ChannelId, Nonce> {
    /// Domain which initiated this message.
    pub(crate) src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub(crate) dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub(crate) channel_id: ChannelId,
    /// Message nonce within the channel.
    pub(crate) nonce: Nonce,
    /// State of the message.
    pub(crate) state: MessageState,
    /// Payload of the message
    pub(crate) payload: VersionedPayload,
}

/// Bundled message contains Message and its proof on src_domain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) struct BundledMessage<DomainId, ChannelId, Nonce, StateRoot> {
    pub(crate) message: Message<DomainId, ChannelId, Nonce>,
    pub(crate) proof: Proof<StateRoot>,
}
