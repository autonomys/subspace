#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::pallet::{ChainAllowlist, OutboxMessageCount, UpdatedChannels};
use crate::{
    BalanceOf, ChannelId, ChannelState, Channels, CloseChannelBy, Config, Error, Event,
    InboxResponses, MessageWeightTags as MessageWeightTagStore, Nonce, Outbox, OutboxMessageResult,
    Pallet,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use frame_support::ensure;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_messenger::endpoint::{EndpointHandler, EndpointRequest, EndpointResponse};
use sp_messenger::messages::{
    BlockMessageWithStorageKey, BlockMessagesWithStorageKey, ChainId, Message, MessageId,
    MessageWeightTag, Payload, ProtocolMessageRequest, ProtocolMessageResponse, RequestResponse,
    VersionedPayload,
};
use sp_runtime::traits::Get;
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Weight tags for given outbox and inbox responses
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct MessageWeightTags {
    pub outbox: BTreeMap<(ChainId, MessageId), MessageWeightTag>,
    pub inbox_responses: BTreeMap<(ChainId, MessageId), MessageWeightTag>,
}

impl<T: Config> Pallet<T> {
    /// Takes a new message destined for dst_chain and adds the message to the outbox.
    pub(crate) fn new_outbox_message(
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        payload: VersionedPayload<BalanceOf<T>>,
    ) -> Result<Nonce, DispatchError> {
        // ensure message is not meant to self.
        ensure!(
            src_chain_id != dst_chain_id,
            Error::<T>::InvalidMessageDestination
        );

        Channels::<T>::try_mutate(
            dst_chain_id,
            channel_id,
            |maybe_channel| -> Result<Nonce, DispatchError> {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                // check if the outbox is full
                let count = OutboxMessageCount::<T>::get((dst_chain_id, channel_id));
                ensure!(
                    count < channel.max_outgoing_messages,
                    Error::<T>::OutboxFull
                );

                let weight_tag = MessageWeightTag::outbox(&payload);

                let next_outbox_nonce = channel.next_outbox_nonce;
                // add message to outbox
                let msg = Message {
                    src_chain_id,
                    dst_chain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                    payload,
                    last_delivered_message_response_nonce: channel
                        .latest_response_received_message_nonce,
                };
                Outbox::<T>::insert((dst_chain_id, channel_id, next_outbox_nonce), msg);
                OutboxMessageCount::<T>::try_mutate(
                    (dst_chain_id, channel_id),
                    |count| -> Result<(), DispatchError> {
                        *count = count
                            .checked_add(1u32)
                            .ok_or(Error::<T>::MessageCountOverflow)?;
                        Ok(())
                    },
                )?;

                // update channel state
                channel.next_outbox_nonce = next_outbox_nonce
                    .checked_add(Nonce::one())
                    .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

                MessageWeightTagStore::<T>::mutate(|maybe_messages| {
                    let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
                    messages
                        .outbox
                        .insert((dst_chain_id, (channel_id, next_outbox_nonce)), weight_tag);
                    *maybe_messages = Some(messages)
                });

                // emit event to notify relayer
                Self::deposit_event(Event::OutboxMessage {
                    chain_id: dst_chain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                });
                Ok(next_outbox_nonce)
            },
        )
    }

    /// Process the incoming messages from given chain_id and channel_id.
    pub(crate) fn process_inbox_messages(
        msg: Message<BalanceOf<T>>,
        msg_weight_tag: MessageWeightTag,
    ) -> DispatchResult {
        let (dst_chain_id, channel_id, nonce) = (msg.src_chain_id, msg.channel_id, msg.nonce);
        let channel =
            Channels::<T>::get(dst_chain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;

        assert_eq!(
            nonce,
            channel.next_inbox_nonce,
            "The message nonce and the channel next inbox nonce must be the same as checked in pre_dispatch; qed"
        );

        let response = match msg.payload {
            // process incoming protocol message.
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(req))) => {
                Payload::Protocol(RequestResponse::Response(
                    Self::process_incoming_protocol_message_req(
                        dst_chain_id,
                        channel_id,
                        req,
                        &msg_weight_tag,
                    ),
                ))
            }

            // process incoming endpoint message.
            VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))) => {
                // Firstly, store fees for inbox message execution regardless what the execution result is,
                // since the fee is already charged from the sender of the src chain and processing of the
                // XDM in this end is finished.
                Self::store_fees_for_inbox_message(
                    (dst_chain_id, (channel_id, nonce)),
                    &channel.fee,
                    &req.src_endpoint,
                );
                let response =
                    if let Some(endpoint_handler) = T::get_endpoint_handler(&req.dst_endpoint) {
                        Self::process_incoming_endpoint_message_req(
                            dst_chain_id,
                            req,
                            channel_id,
                            nonce,
                            &msg_weight_tag,
                            endpoint_handler,
                        )
                    } else {
                        Err(Error::<T>::NoMessageHandler.into())
                    };

                Payload::Endpoint(RequestResponse::Response(response))
            }

            // return error for all the remaining branches
            VersionedPayload::V0(payload) => match payload {
                Payload::Protocol(_) => Payload::Protocol(RequestResponse::Response(Err(
                    Error::<T>::InvalidMessagePayload.into(),
                ))),
                Payload::Endpoint(_) => Payload::Endpoint(RequestResponse::Response(Err(
                    Error::<T>::InvalidMessagePayload.into(),
                ))),
            },
        };

        let resp_payload = VersionedPayload::V0(response);
        let weight_tag = MessageWeightTag::inbox_response(msg_weight_tag, &resp_payload);

        InboxResponses::<T>::insert(
            (dst_chain_id, channel_id, nonce),
            Message {
                src_chain_id: T::SelfChainId::get(),
                dst_chain_id,
                channel_id,
                nonce,
                payload: resp_payload,
                // this nonce is not considered in response context.
                last_delivered_message_response_nonce: None,
            },
        );

        MessageWeightTagStore::<T>::mutate(|maybe_messages| {
            let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
            messages
                .inbox_responses
                .insert((dst_chain_id, (channel_id, nonce)), weight_tag);
            *maybe_messages = Some(messages)
        });

        Channels::<T>::mutate(
            dst_chain_id,
            channel_id,
            |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                channel.next_inbox_nonce = nonce
                    .checked_add(Nonce::one())
                    .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
                Ok(())
            },
        )?;

        UpdatedChannels::<T>::mutate(|updated_channels| {
            updated_channels.insert((dst_chain_id, channel_id))
        });

        // reward relayers for relaying message responses to src_chain.
        // clean any delivered inbox responses
        Self::reward_operators_for_inbox_execution(
            dst_chain_id,
            channel_id,
            msg.last_delivered_message_response_nonce,
        )?;

        Self::deposit_event(Event::InboxMessageResponse {
            chain_id: dst_chain_id,
            channel_id,
            nonce,
        });

        Ok(())
    }

    fn process_incoming_endpoint_message_req(
        dst_chain_id: ChainId,
        req: EndpointRequest,
        channel_id: ChannelId,
        nonce: Nonce,
        msg_weight_tag: &MessageWeightTag,
        endpoint_handler: Box<dyn sp_messenger::endpoint::EndpointHandler<MessageId>>,
    ) -> EndpointResponse {
        if !ChainAllowlist::<T>::get().contains(&dst_chain_id) {
            return Err(Error::<T>::ChainNotAllowed.into());
        }

        if msg_weight_tag != &MessageWeightTag::EndpointRequest(req.dst_endpoint.clone()) {
            return Err(Error::<T>::WeightTagNotMatch.into());
        }

        let channel =
            Channels::<T>::get(dst_chain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;
        if channel.state != ChannelState::Open {
            return Err(Error::<T>::InvalidChannelState.into());
        }

        endpoint_handler.message(dst_chain_id, (channel_id, nonce), req)
    }

    fn process_incoming_protocol_message_req(
        chain_id: ChainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<BalanceOf<T>>,
        weight_tag: &MessageWeightTag,
    ) -> Result<(), DispatchError> {
        let is_chain_allowed = ChainAllowlist::<T>::get().contains(&chain_id);
        match req {
            ProtocolMessageRequest::ChannelOpen(_) => {
                if !is_chain_allowed {
                    return Err(Error::<T>::ChainNotAllowed.into());
                }

                if weight_tag != &MessageWeightTag::ProtocolChannelOpen {
                    return Err(Error::<T>::WeightTagNotMatch.into());
                }
                Self::do_open_channel(chain_id, channel_id)
            }
            ProtocolMessageRequest::ChannelClose => {
                if weight_tag != &MessageWeightTag::ProtocolChannelClose {
                    return Err(Error::<T>::WeightTagNotMatch.into());
                }
                // closing of this channel is coming from the other chain
                // so safe to close it as Sudo here
                Self::do_close_channel(chain_id, channel_id, CloseChannelBy::Sudo)
            }
        }
    }

    fn process_incoming_protocol_message_response(
        chain_id: ChainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<BalanceOf<T>>,
        resp: ProtocolMessageResponse,
        weight_tag: &MessageWeightTag,
    ) -> DispatchResult {
        match (req, resp) {
            // channel open request is accepted by dst_chain.
            // open channel on our end.
            (ProtocolMessageRequest::ChannelOpen(_), Ok(_)) => {
                if weight_tag != &MessageWeightTag::ProtocolChannelOpen {
                    return Err(Error::<T>::WeightTagNotMatch.into());
                }
                Self::do_open_channel(chain_id, channel_id)
            }

            // for rest of the branches we dont care about the outcome and return Ok
            // for channel close request, we do not care about the response as channel is already closed.
            // for channel open request and request is rejected, channel is left in init state and no new messages are accepted.
            _ => Ok(()),
        }
    }

    fn process_incoming_endpoint_message_response(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        nonce: Nonce,
        resp_msg_weight_tag: &MessageWeightTag,
        req: EndpointRequest,
        resp: EndpointResponse,
        endpoint_handler: Box<dyn EndpointHandler<MessageId>>,
    ) -> DispatchResult {
        if resp_msg_weight_tag != &MessageWeightTag::EndpointResponse(req.dst_endpoint.clone()) {
            return Err(Error::<T>::WeightTagNotMatch.into());
        }

        endpoint_handler.message_response(dst_chain_id, (channel_id, nonce), req, resp)
    }

    pub(crate) fn process_outbox_message_responses(
        resp_msg: Message<BalanceOf<T>>,
        resp_msg_weight_tag: MessageWeightTag,
    ) -> DispatchResult {
        let (dst_chain_id, channel_id, nonce) =
            (resp_msg.src_chain_id, resp_msg.channel_id, resp_msg.nonce);
        let channel =
            Channels::<T>::get(dst_chain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;

        assert_eq!(
            nonce,
            channel.latest_response_received_message_nonce
                .and_then(|nonce| nonce.checked_add(Nonce::one()))
                .unwrap_or(Nonce::zero()),
            "The message nonce and the channel last msg response nonce must be the same as checked in pre_dispatch; qed"
        );

        // fetch original request
        let req_msg = Outbox::<T>::take((dst_chain_id, channel_id, nonce))
            .ok_or(Error::<T>::MissingMessage)?;

        OutboxMessageCount::<T>::try_mutate(
            (dst_chain_id, channel_id),
            |count| -> Result<(), DispatchError> {
                *count = count
                    .checked_sub(1u32)
                    .ok_or(Error::<T>::MessageCountUnderflow)?;
                Ok(())
            },
        )?;

        // clear out box message weight tag
        MessageWeightTagStore::<T>::mutate(|maybe_messages| {
            let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
            messages.outbox.remove(&(dst_chain_id, (channel_id, nonce)));
            *maybe_messages = Some(messages)
        });

        let resp = match (req_msg.payload, resp_msg.payload) {
            // process incoming protocol outbox message response.
            (
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(req))),
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(resp))),
            ) => Self::process_incoming_protocol_message_response(
                dst_chain_id,
                channel_id,
                req,
                resp,
                &resp_msg_weight_tag,
            ),

            // process incoming endpoint outbox message response.
            (
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))),
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(resp))),
            ) => {
                // Firstly, distribute the fees for outbox message execution regardless what the result is,
                // since the fee is already charged from the sender and the processing of the XDM is finished.
                Self::reward_operators_for_outbox_execution(dst_chain_id, (channel_id, nonce));

                if let Some(endpoint_handler) = T::get_endpoint_handler(&req.dst_endpoint) {
                    Self::process_incoming_endpoint_message_response(
                        dst_chain_id,
                        channel_id,
                        nonce,
                        &resp_msg_weight_tag,
                        req,
                        resp,
                        endpoint_handler,
                    )
                } else {
                    Err(Error::<T>::NoMessageHandler.into())
                }
            }

            (_, _) => Err(Error::<T>::InvalidMessagePayload.into()),
        };

        Channels::<T>::mutate(
            dst_chain_id,
            channel_id,
            |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                channel.latest_response_received_message_nonce = Some(nonce);
                Ok(())
            },
        )?;

        UpdatedChannels::<T>::mutate(|updated_channels| {
            updated_channels.insert((dst_chain_id, channel_id))
        });

        // deposit event notifying the message status.
        match resp {
            Ok(_) => Self::deposit_event(Event::OutboxMessageResult {
                chain_id: dst_chain_id,
                channel_id,
                nonce,
                result: OutboxMessageResult::Ok,
            }),
            Err(err) => Self::deposit_event(Event::OutboxMessageResult {
                chain_id: dst_chain_id,
                channel_id,
                nonce,
                result: OutboxMessageResult::Err(err),
            }),
        }

        Ok(())
    }

    pub fn get_block_messages() -> BlockMessagesWithStorageKey {
        let message_weight_tags = match crate::pallet::MessageWeightTags::<T>::get() {
            None => return Default::default(),
            Some(messages) => messages,
        };

        let mut messages_with_storage_key = BlockMessagesWithStorageKey::default();

        // create storage keys for inbox responses
        message_weight_tags.inbox_responses.into_iter().for_each(
            |((chain_id, (channel_id, nonce)), weight_tag)| {
                let storage_key =
                    InboxResponses::<T>::hashed_key_for((chain_id, channel_id, nonce));
                messages_with_storage_key
                    .inbox_responses
                    .push(BlockMessageWithStorageKey {
                        src_chain_id: T::SelfChainId::get(),
                        dst_chain_id: chain_id,
                        channel_id,
                        nonce,
                        storage_key,
                        weight_tag,
                    });
            },
        );

        // create storage keys for outbox
        message_weight_tags.outbox.into_iter().for_each(
            |((chain_id, (channel_id, nonce)), weight_tag)| {
                let storage_key = Outbox::<T>::hashed_key_for((chain_id, channel_id, nonce));
                messages_with_storage_key
                    .outbox
                    .push(BlockMessageWithStorageKey {
                        src_chain_id: T::SelfChainId::get(),
                        dst_chain_id: chain_id,
                        channel_id,
                        nonce,
                        storage_key,
                        weight_tag,
                    })
            },
        );

        messages_with_storage_key
    }
}
