#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::pallet::{
    ChainAllowlist, InboxResponseMessageWeightTags, OutboxMessageCount, OutboxMessageWeightTags,
    UpdatedChannels,
};
use crate::{
    BalanceOf, ChannelId, ChannelState, Channels, CloseChannelBy, Config, Error, Event,
    InboxResponses, Nonce, Outbox, OutboxMessageResult, Pallet,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use frame_support::ensure;
use sp_messenger::endpoint::{EndpointHandler, EndpointRequest, EndpointResponse};
use sp_messenger::messages::{
    BlockMessagesQuery, ChainId, ChannelOpenParamsV1, Message, MessageId, MessageKey,
    MessageNonceWithStorageKey, MessageWeightTag, MessagesWithStorageKey, PayloadV1,
    ProtocolMessageRequest, ProtocolMessageResponse, RequestResponse, VersionedPayload,
};

use sp_messenger::MAX_FUTURE_ALLOWED_NONCES;
use sp_runtime::traits::{Get, One};
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

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

                OutboxMessageWeightTags::<T>::insert(
                    (dst_chain_id, (channel_id, next_outbox_nonce)),
                    weight_tag,
                );

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

        let resp_payload = VersionedPayload::V1(match msg.payload {
            // process incoming protocol message.
            VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(req))) => {
                PayloadV1::Protocol(RequestResponse::Response(
                    Self::process_incoming_protocol_message_req(
                        dst_chain_id,
                        channel_id,
                        req,
                        &msg_weight_tag,
                    ),
                ))
            }

            // process incoming endpoint message.
            VersionedPayload::V1(PayloadV1::Endpoint(RequestResponse::Request(req))) => {
                // Firstly, store fees for inbox message execution regardless what the execution result is,
                // since the fee is already charged from the sender of the src chain and processing of the
                // XDM in this end is finished.

                // since v1 collects fee on behalf of dst_chain, this chain,
                // so we do not recalculate the fee but instead use the collected fee as is
                Self::store_inbox_fee(
                    dst_chain_id,
                    (channel_id, nonce),
                    req.collected_fee.dst_chain_fee,
                )?;

                let response = if let Some(endpoint_handler) =
                    T::get_endpoint_handler(&req.req.dst_endpoint)
                {
                    Self::process_incoming_endpoint_message_req(
                        dst_chain_id,
                        req.req,
                        channel_id,
                        nonce,
                        &msg_weight_tag,
                        endpoint_handler,
                    )
                } else {
                    Err(Error::<T>::NoMessageHandler.into())
                };

                PayloadV1::Endpoint(RequestResponse::Response(response))
            }

            // return error for all the remaining branches
            VersionedPayload::V1(PayloadV1::Protocol(_)) => PayloadV1::Protocol(
                RequestResponse::Response(Err(Error::<T>::InvalidMessagePayload.into())),
            ),
            VersionedPayload::V1(PayloadV1::Endpoint(_)) => PayloadV1::Endpoint(
                RequestResponse::Response(Err(Error::<T>::InvalidMessagePayload.into())),
            ),
        });

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

        InboxResponseMessageWeightTags::<T>::insert(
            (dst_chain_id, (channel_id, nonce)),
            weight_tag,
        );

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
        let dst_endpoint = req.dst_endpoint.clone();
        let pre_check_handler = || {
            ensure!(
                msg_weight_tag == &MessageWeightTag::EndpointRequest(dst_endpoint),
                Error::<T>::WeightTagNotMatch
            );

            let channel =
                Channels::<T>::get(dst_chain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;
            ensure!(
                channel.state == ChannelState::Open,
                Error::<T>::InvalidChannelState
            );

            ensure!(
                ChainAllowlist::<T>::get().contains(&dst_chain_id),
                Error::<T>::ChainNotAllowed
            );

            Ok(())
        };

        endpoint_handler.message(dst_chain_id, (channel_id, nonce), req, pre_check_handler())
    }

    fn process_incoming_protocol_message_req(
        chain_id: ChainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<ChannelOpenParamsV1>,
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
        req: ProtocolMessageRequest<ChannelOpenParamsV1>,
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

        // clear outbox message weight tag
        OutboxMessageWeightTags::<T>::remove((dst_chain_id, (channel_id, nonce)));

        let resp = match (req_msg.payload, resp_msg.payload) {
            // process incoming protocol outbox message response.
            (
                VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(req))),
                VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Response(resp))),
            ) => Self::process_incoming_protocol_message_response(
                dst_chain_id,
                channel_id,
                req,
                resp,
                &resp_msg_weight_tag,
            ),

            // process incoming endpoint outbox message response.
            (
                VersionedPayload::V1(PayloadV1::Endpoint(RequestResponse::Request(req))),
                VersionedPayload::V1(PayloadV1::Endpoint(RequestResponse::Response(resp))),
            ) => {
                // Firstly, distribute the fees for outbox message execution regardless what the result is,
                // since the fee is already charged from the sender and the processing of the XDM is finished.
                Self::reward_operators_for_outbox_execution(dst_chain_id, (channel_id, nonce))?;

                if let Some(endpoint_handler) = T::get_endpoint_handler(&req.req.dst_endpoint) {
                    Self::process_incoming_endpoint_message_response(
                        dst_chain_id,
                        channel_id,
                        nonce,
                        &resp_msg_weight_tag,
                        req.req,
                        resp,
                        endpoint_handler,
                    )
                } else {
                    Err(Error::<T>::NoMessageHandler.into())
                }
            }

            (_, _) => Err(Error::<T>::InvalidMessagePayload.into()),
        };

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

    pub fn get_block_messages(query: BlockMessagesQuery) -> MessagesWithStorageKey {
        let BlockMessagesQuery {
            chain_id,
            channel_id,
            outbox_from,
            inbox_responses_from,
        } = query;

        let inbox_responses_weight_tags = Self::get_weight_tags(
            (chain_id, channel_id, inbox_responses_from),
            InboxResponseMessageWeightTags::<T>::get,
        );

        let outbox_weight_tags = Self::get_weight_tags(
            (chain_id, channel_id, outbox_from),
            OutboxMessageWeightTags::<T>::get,
        );

        if outbox_weight_tags.is_empty() && inbox_responses_weight_tags.is_empty() {
            return Default::default();
        }

        let mut messages_with_storage_key = MessagesWithStorageKey::default();

        // create storage keys for inbox responses
        inbox_responses_weight_tags
            .into_iter()
            .for_each(|(nonce, weight_tag)| {
                let storage_key =
                    InboxResponses::<T>::hashed_key_for((chain_id, channel_id, nonce));
                messages_with_storage_key
                    .inbox_responses
                    .push(MessageNonceWithStorageKey {
                        nonce,
                        storage_key,
                        weight_tag,
                    });
            });

        // create storage keys for outbox
        outbox_weight_tags
            .into_iter()
            .for_each(|(nonce, weight_tag)| {
                let storage_key = Outbox::<T>::hashed_key_for((chain_id, channel_id, nonce));
                messages_with_storage_key
                    .outbox
                    .push(MessageNonceWithStorageKey {
                        nonce,
                        storage_key,
                        weight_tag,
                    })
            });

        messages_with_storage_key
    }

    fn get_weight_tags<WTG>(
        from: MessageKey,
        weight_tag_getter: WTG,
    ) -> BTreeMap<Nonce, MessageWeightTag>
    where
        WTG: Fn((ChainId, MessageId)) -> Option<MessageWeightTag>,
    {
        let (chain_id, channel_id, mut nonce) = from;
        let mut weight_tags = BTreeMap::new();
        while weight_tags.len() as u32 <= MAX_FUTURE_ALLOWED_NONCES {
            match weight_tag_getter((chain_id, (channel_id, nonce))) {
                // if the nonce is already processed, short circuit and return
                None => return weight_tags,
                Some(weight_tag) => {
                    weight_tags.insert(nonce, weight_tag);
                }
            };

            nonce = match nonce.checked_add(One::one()) {
                None => return weight_tags,
                Some(nonce) => nonce,
            }
        }

        weight_tags
    }
}
