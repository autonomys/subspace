use crate::{
    BalanceOf, ChannelId, Channels, Config, Error, Event, FeeModel, InboxResponses, Nonce, Outbox,
    OutboxMessageResult, Pallet, RelayerMessages,
};
use frame_support::ensure;
use sp_messenger::messages::{
    ChainId, Message, MessageWeightTag, Payload, ProtocolMessageRequest, ProtocolMessageResponse,
    RequestResponse, VersionedPayload,
};
use sp_runtime::traits::Get;
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};

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
                let count = Outbox::<T>::count();
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

                // update channel state
                channel.next_outbox_nonce = next_outbox_nonce
                    .checked_add(Nonce::one())
                    .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

                // get next relayer
                let relayer_id = Self::next_relayer()?;
                RelayerMessages::<T>::mutate(relayer_id.clone(), |maybe_messages| {
                    let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
                    messages.outbox.push((
                        dst_chain_id,
                        (channel_id, next_outbox_nonce),
                        weight_tag,
                    ));
                    *maybe_messages = Some(messages)
                });

                // emit event to notify relayer
                Self::deposit_event(Event::OutboxMessage {
                    chain_id: dst_chain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                    relayer_id,
                });
                Ok(next_outbox_nonce)
            },
        )
    }

    /// Removes messages responses from Inbox responses as the src_chain signalled that responses are delivered.
    /// all the messages with nonce <= latest_confirmed_nonce are deleted.
    fn distribute_rewards_for_delivered_message_responses(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        latest_confirmed_nonce: Option<Nonce>,
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let mut current_nonce = latest_confirmed_nonce;

        while let Some(nonce) = current_nonce {
            // for every inbox response we take, distribute the reward to the relayers.
            if InboxResponses::<T>::take((dst_chain_id, channel_id, nonce)).is_none() {
                return Ok(());
            }

            Self::distribute_reward_to_relayers(fee_model.inbox_fee.relayer_pool_fee)?;
            current_nonce = nonce.checked_sub(Nonce::one())
        }

        Ok(())
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
                let response = if let Some(endpoint_handler) =
                    T::get_endpoint_response_handler(&req.dst_endpoint)
                {
                    if msg_weight_tag != MessageWeightTag::EndpointRequest(req.dst_endpoint.clone())
                    {
                        return Err(Error::<T>::WeightTagNotMatch.into());
                    }
                    endpoint_handler.message(dst_chain_id, (channel_id, nonce), req)
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

        // get the next relayer
        let relayer_id = Self::next_relayer()?;
        RelayerMessages::<T>::mutate(relayer_id.clone(), |maybe_messages| {
            let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
            messages
                .inbox_responses
                .push((dst_chain_id, (channel_id, nonce), weight_tag));
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

        // reward relayers for relaying message responses to src_chain.
        // clean any delivered inbox responses
        Self::distribute_rewards_for_delivered_message_responses(
            dst_chain_id,
            channel_id,
            msg.last_delivered_message_response_nonce,
            &channel.fee,
        )?;

        Self::deposit_event(Event::InboxMessageResponse {
            chain_id: dst_chain_id,
            channel_id,
            nonce,
            relayer_id,
        });

        Ok(())
    }

    fn process_incoming_protocol_message_req(
        chain_id: ChainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<BalanceOf<T>>,
        weight_tag: &MessageWeightTag,
    ) -> Result<(), DispatchError> {
        match req {
            ProtocolMessageRequest::ChannelOpen(_) => {
                if weight_tag != &MessageWeightTag::ProtocolChannelOpen {
                    return Err(Error::<T>::WeightTagNotMatch.into());
                }
                Self::do_open_channel(chain_id, channel_id)
            }
            ProtocolMessageRequest::ChannelClose => {
                if weight_tag != &MessageWeightTag::ProtocolChannelClose {
                    return Err(Error::<T>::WeightTagNotMatch.into());
                }
                Self::do_close_channel(chain_id, channel_id)
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
                if let Some(endpoint_handler) = T::get_endpoint_response_handler(&req.dst_endpoint)
                {
                    if resp_msg_weight_tag
                        != MessageWeightTag::EndpointResponse(req.dst_endpoint.clone())
                    {
                        return Err(Error::<T>::WeightTagNotMatch.into());
                    }
                    endpoint_handler.message_response(dst_chain_id, (channel_id, nonce), req, resp)
                } else {
                    Err(Error::<T>::NoMessageHandler.into())
                }
            }

            (_, _) => Err(Error::<T>::InvalidMessagePayload.into()),
        };

        // distribute rewards to relayers for relaying the outbox messages.
        Self::distribute_reward_to_relayers(channel.fee.outbox_fee.relayer_pool_fee)?;

        Channels::<T>::mutate(
            dst_chain_id,
            channel_id,
            |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                channel.latest_response_received_message_nonce = Some(nonce);
                Ok(())
            },
        )?;

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
}
