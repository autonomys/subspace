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
    BlockMessageWithStorageKey, BlockMessagesWithStorageKey, ChainId, ChannelOpenParams,
    ConvertedPayload, Message, MessageId, MessageWeightTag, Payload, ProtocolMessageRequest,
    ProtocolMessageResponse, RequestResponse, VersionedPayload,
};
use sp_runtime::traits::Get;
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
        let channel =
            Channels::<T>::get(dst_chain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;

        let maybe_collected_fee = msg.payload.maybe_collected_fee();
        let ConvertedPayload { payload, is_v1 } = msg.payload.into_payload_v0();
        let response = match payload {
            // process incoming protocol message.
            Payload::Protocol(RequestResponse::Request(req)) => Payload::Protocol(
                RequestResponse::Response(Self::process_incoming_protocol_message_req(
                    dst_chain_id,
                    channel_id,
                    req,
                    &msg_weight_tag,
                )),
            ),

            // process incoming endpoint message.
            Payload::Endpoint(RequestResponse::Request(req)) => {
                // Firstly, store fees for inbox message execution regardless what the execution result is,
                // since the fee is already charged from the sender of the src chain and processing of the
                // XDM in this end is finished.
                if let Some(collected_fee) = maybe_collected_fee {
                    // since v1 collects fee on behalf of dst_chain, this chain,
                    // so we do not recalculate the fee but instead use the collected fee as is
                    Self::store_inbox_fee(
                        dst_chain_id,
                        (channel_id, nonce),
                        collected_fee.dst_chain_fee,
                    )?;
                } else {
                    // for v0, use the weight to fee conversion to calculate the fee
                    // and store the fee
                    Self::store_fees_for_inbox_message(
                        (dst_chain_id, (channel_id, nonce)),
                        &channel.fee,
                        &req.src_endpoint,
                    );
                }

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
            Payload::Protocol(_) => Payload::Protocol(RequestResponse::Response(Err(
                Error::<T>::InvalidMessagePayload.into(),
            ))),
            Payload::Endpoint(_) => Payload::Endpoint(RequestResponse::Response(Err(
                Error::<T>::InvalidMessagePayload.into(),
            ))),
        };

        let resp_payload = if is_v1 {
            VersionedPayload::V1(response.into())
        } else {
            VersionedPayload::V0(response)
        };

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
        req: ProtocolMessageRequest<ChannelOpenParams<BalanceOf<T>>>,
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
        req: ProtocolMessageRequest<ChannelOpenParams<BalanceOf<T>>>,
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

        let ConvertedPayload {
            payload: req,
            is_v1: is_v1_req,
        } = req_msg.payload.into_payload_v0();
        let ConvertedPayload {
            payload: resp,
            is_v1: is_v1_resp,
        } = resp_msg.payload.into_payload_v0();

        ensure!(is_v1_req == is_v1_resp, Error::<T>::MessageVersionMismatch);

        let resp = match (req, resp) {
            // process incoming protocol outbox message response.
            (
                Payload::Protocol(RequestResponse::Request(req)),
                Payload::Protocol(RequestResponse::Response(resp)),
            ) => Self::process_incoming_protocol_message_response(
                dst_chain_id,
                channel_id,
                req,
                resp,
                &resp_msg_weight_tag,
            ),

            // process incoming endpoint outbox message response.
            (
                Payload::Endpoint(RequestResponse::Request(req)),
                Payload::Endpoint(RequestResponse::Response(resp)),
            ) => {
                // Firstly, distribute the fees for outbox message execution regardless what the result is,
                // since the fee is already charged from the sender and the processing of the XDM is finished.
                Self::reward_operators_for_outbox_execution(dst_chain_id, (channel_id, nonce))?;

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
        let inbox_responses_weight_tags: BTreeMap<(ChainId, MessageId), MessageWeightTag> =
            InboxResponseMessageWeightTags::<T>::iter().collect();
        let outbox_weight_tags: BTreeMap<(ChainId, MessageId), MessageWeightTag> =
            OutboxMessageWeightTags::<T>::iter().collect();

        if outbox_weight_tags.is_empty() && inbox_responses_weight_tags.is_empty() {
            return Default::default();
        }

        let mut messages_with_storage_key = BlockMessagesWithStorageKey::default();

        // create storage keys for inbox responses
        inbox_responses_weight_tags.into_iter().for_each(
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
        outbox_weight_tags
            .into_iter()
            .for_each(|((chain_id, (channel_id, nonce)), weight_tag)| {
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
            });

        messages_with_storage_key
    }
}
