use crate::verification::Proof;
use crate::{
    ChannelId, Channels, Config, Error, Event, Inbox, InboxMessageResponses, InitiateChannelParams,
    Nonce, Outbox, Pallet,
};
use codec::{Decode, Encode};
use frame_support::ensure;
use scale_info::TypeInfo;
use sp_runtime::traits::Get;
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest {
    /// Request to open a channel with foreign domain.
    ChannelOpen(InitiateChannelParams),
    /// Request to close an open channel with foreign domain.
    ChannelClose,
}

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct ProtocolMessageResponse(Result<(), DispatchError>);

/// Protocol message that encompasses  request or its response.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum RequestResponse<Request, Response> {
    Request(Request),
    Response(Response),
}

/// Payload of the message
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Payload {
    /// Protocol specific payload.
    Protocol(RequestResponse<ProtocolMessageRequest, ProtocolMessageResponse>),
}

/// Versioned message payload
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum VersionedPayload {
    V0(Payload),
}

/// Message contains information to be sent to or received from another domain
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Message<DomainId> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Payload of the message
    pub payload: VersionedPayload,
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
                // TODO(ved): ensure channel is ready to send messages.
                // check if the outbox is full
                let count = Outbox::<T>::count();
                ensure!(
                    count < channel.max_outgoing_messages,
                    Error::<T>::OutboxFull
                );

                let next_outbox_nonce = channel.next_outbox_nonce;
                // add message to outbox
                let msg = Message {
                    src_domain_id,
                    dst_domain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
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

    pub(crate) fn process_inbox_messages(
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
    ) -> DispatchResult {
        let mut next_inbox_nonce = Channels::<T>::get(dst_domain_id, channel_id)
            .ok_or(Error::<T>::MissingChannel)?
            .next_inbox_nonce;

        // TODO(ved): maybe a bound of number of messages to process in a single call?
        let mut messages_processed = 0;
        while let Some(msg) = Inbox::<T>::take((dst_domain_id, channel_id, next_inbox_nonce)) {
            let response = match msg.payload {
                VersionedPayload::V0(Payload::Protocol(msg)) => {
                    Self::process_incoming_protocol_message(dst_domain_id, channel_id, msg)
                }
            };

            InboxMessageResponses::<T>::insert(
                (dst_domain_id, channel_id, next_inbox_nonce),
                Message {
                    src_domain_id: T::SelfDomainId::get(),
                    dst_domain_id,
                    channel_id,
                    nonce: next_inbox_nonce,
                    payload: VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(
                        ProtocolMessageResponse(response),
                    ))),
                },
            );

            next_inbox_nonce = next_inbox_nonce
                .checked_add(Nonce::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
            messages_processed += 1;
        }

        if messages_processed > 0 {
            Channels::<T>::mutate(
                dst_domain_id,
                channel_id,
                |maybe_channel| -> DispatchResult {
                    let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                    channel.next_inbox_nonce = next_inbox_nonce;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    fn process_incoming_protocol_message(
        domain_id: T::DomainId,
        channel_id: ChannelId,
        req_resp: RequestResponse<ProtocolMessageRequest, ProtocolMessageResponse>,
    ) -> Result<(), DispatchError> {
        match req_resp {
            RequestResponse::Request(req) => match req {
                ProtocolMessageRequest::ChannelOpen(_) => {
                    Self::do_open_channel(domain_id, channel_id)
                }
                ProtocolMessageRequest::ChannelClose => {
                    Self::do_close_channel(domain_id, channel_id)
                }
            },
            RequestResponse::Response(_) => Err(Error::<T>::InvalidMessagePayload.into()),
        }
    }
}
