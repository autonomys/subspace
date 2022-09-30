use crate::verification::Proof;
use crate::{ChannelId, Channels, Config, Error, Event, Nonce, Outbox, Pallet};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::ensure;
use scale_info::TypeInfo;
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum ProtocolMessageRequest {
    /// Request to open a channel with foreign domain.
    ChannelOpen,
    /// Request to close an open channel with foreign domain.
    ChannelClose,
}

/// Defines protocol response of request performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum ProtocolMessageResponse {
    /// Request was approved on the dst_domain
    Accepted,
    /// Request was denied on dst_domain
    Denied,
}

/// Protocol message that encompasses  request or its response.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum ProtocolMessage {
    /// Request to perform on dst_domain.
    Request(ProtocolMessageRequest),
    /// Response to action .
    Response(ProtocolMessageResponse),
}

/// Message states during a message life cycle.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum MessageState {
    /// Message is accepted and sent to dst_domain.
    Sent,
    /// Message response was received from dst_domain.
    ResponseReceived,
}

/// Message payload.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum MessagePayload {
    /// Protocol specific message.
    ProtocolMessage(ProtocolMessage),
}

/// Versioned message payload
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub enum VersionedPayload {
    V0(MessagePayload),
}

/// Message contains information to be sent to or received from another domain
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub struct Message<DomainId> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// State of the message.
    pub state: MessageState,
    /// Payload of the message
    pub payload: VersionedPayload,
}

/// Bundled message contains Message and its proof on src_domain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct BundledMessage<DomainId, StateRoot> {
    pub message: Message<DomainId>,
    pub proof: Proof<StateRoot>,
}

impl<T: Config> Pallet<T> {
    /// Takes a new message destined for dst_domain and adds the message to the outbox.
    pub(crate) fn new_outbox_message(
        src_domain_id: T::DomainId,
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
        payload: VersionedPayload,
    ) -> DispatchResult {
        Channels::<T>::try_mutate(
            dst_domain_id,
            channel_id,
            |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                let next_outbox_nonce = channel.next_outbox_nonce;
                // check if the outbox is full
                let count = Outbox::<T>::count();
                ensure!(
                    count < channel.max_outgoing_messages,
                    Error::<T>::OutboxFull
                );

                // add message to outbox
                let msg = Message {
                    src_domain_id,
                    dst_domain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                    state: MessageState::Sent,
                    payload,
                };
                Outbox::<T>::insert((dst_domain_id, channel_id, next_outbox_nonce), msg);

                // update channel state
                channel.next_outbox_nonce = next_outbox_nonce
                    .checked_add(Nonce::one())
                    .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

                // emit event to notify relayer
                Self::deposit_event(Event::OutboxMessage {
                    domain_id: dst_domain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                });
                Ok(())
            },
        )
    }
}
