use crate::{
    BalanceOf, ChannelId, Channels, Config, Error, Event, FeeModel, Inbox, InboxResponses, Nonce,
    Outbox, OutboxMessageResult, OutboxResponses, Pallet, RelayerMessages,
};
use frame_support::ensure;
use sp_messenger::messages::{
    Message, Payload, ProtocolMessageRequest, ProtocolMessageResponse, RequestResponse,
    VersionedPayload,
};
use sp_runtime::traits::{CheckedMul, Get};
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};

impl<T: Config> Pallet<T> {
    /// Takes a new message destined for dst_domain and adds the message to the outbox.
    pub(crate) fn new_outbox_message(
        src_domain_id: T::DomainId,
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
        payload: VersionedPayload<BalanceOf<T>>,
    ) -> Result<Nonce, DispatchError> {
        Channels::<T>::try_mutate(
            dst_domain_id,
            channel_id,
            |maybe_channel| -> Result<Nonce, DispatchError> {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
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
                    last_delivered_message_response_nonce: channel
                        .latest_response_received_message_nonce,
                };
                Outbox::<T>::insert((dst_domain_id, channel_id, next_outbox_nonce), msg);

                // update channel state
                channel.next_outbox_nonce = next_outbox_nonce
                    .checked_add(Nonce::one())
                    .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

                // get next relayer
                let relayer_id = Self::next_relayer()?;
                RelayerMessages::<T>::mutate(relayer_id.clone(), |maybe_messages| {
                    let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
                    messages
                        .outbox
                        .push((dst_domain_id, (channel_id, next_outbox_nonce)));
                    *maybe_messages = Some(messages)
                });

                // emit event to notify relayer
                Self::deposit_event(Event::OutboxMessage {
                    domain_id: dst_domain_id,
                    channel_id,
                    nonce: next_outbox_nonce,
                    relayer_id,
                });
                Ok(next_outbox_nonce)
            },
        )
    }

    /// Removes messages responses from Inbox responses as the src_domain signalled that responses are delivered.
    /// all the messages with nonce <= latest_confirmed_nonce are deleted.
    fn distribute_rewards_for_delivered_message_responses(
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
        latest_confirmed_nonce: Option<Nonce>,
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let mut current_nonce = latest_confirmed_nonce;

        while let Some(nonce) = current_nonce {
            // for every inbox response we take, distribute the reward to the relayers.
            if InboxResponses::<T>::take((dst_domain_id, channel_id, nonce)).is_none() {
                return Ok(());
            }

            Self::distribute_reward_to_relayers(fee_model.inbox_fee.relayer_pool_fee)?;
            current_nonce = nonce.checked_sub(Nonce::one())
        }

        Ok(())
    }

    /// Process the incoming messages from given domain_id and channel_id.
    pub(crate) fn process_inbox_messages(
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
    ) -> DispatchResult {
        let channel =
            Channels::<T>::get(dst_domain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;
        let mut next_inbox_nonce = channel.next_inbox_nonce;

        // TODO(ved): maybe a bound of number of messages to process in a single call?
        let mut messages_processed = 0;
        while let Some(msg) = Inbox::<T>::take((dst_domain_id, channel_id, next_inbox_nonce)) {
            let response = match msg.payload {
                // process incoming protocol message.
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(req))) => {
                    Payload::Protocol(RequestResponse::Response(
                        Self::process_incoming_protocol_message_req(dst_domain_id, channel_id, req),
                    ))
                }

                // process incoming endpoint message.
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))) => {
                    let response = if let Some(endpoint_handler) =
                        T::get_endpoint_response_handler(&req.dst_endpoint)
                    {
                        endpoint_handler.message(dst_domain_id, (channel_id, next_inbox_nonce), req)
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

            InboxResponses::<T>::insert(
                (dst_domain_id, channel_id, next_inbox_nonce),
                Message {
                    src_domain_id: T::SelfDomainId::get(),
                    dst_domain_id,
                    channel_id,
                    nonce: next_inbox_nonce,
                    payload: VersionedPayload::V0(response),
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
                    .push((dst_domain_id, (channel_id, next_inbox_nonce)));
                *maybe_messages = Some(messages)
            });

            Self::deposit_event(Event::InboxMessageResponse {
                domain_id: dst_domain_id,
                channel_id,
                nonce: next_inbox_nonce,
                relayer_id,
            });

            next_inbox_nonce = next_inbox_nonce
                .checked_add(Nonce::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
            messages_processed += 1;

            // reward relayers for relaying message responses to src_domain.
            // clean any delivered inbox responses
            Self::distribute_rewards_for_delivered_message_responses(
                dst_domain_id,
                channel_id,
                msg.last_delivered_message_response_nonce,
                &channel.fee,
            )?;
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

    fn process_incoming_protocol_message_req(
        domain_id: T::DomainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<BalanceOf<T>>,
    ) -> Result<(), DispatchError> {
        match req {
            ProtocolMessageRequest::ChannelOpen(_) => Self::do_open_channel(domain_id, channel_id),
            ProtocolMessageRequest::ChannelClose => Self::do_close_channel(domain_id, channel_id),
        }
    }

    fn process_incoming_protocol_message_response(
        domain_id: T::DomainId,
        channel_id: ChannelId,
        req: ProtocolMessageRequest<BalanceOf<T>>,
        resp: ProtocolMessageResponse,
    ) -> DispatchResult {
        match (req, resp) {
            // channel open request is accepted by dst_domain.
            // open channel on our end.
            (ProtocolMessageRequest::ChannelOpen(_), Ok(_)) => {
                Self::do_open_channel(domain_id, channel_id)
            }

            // for rest of the branches we dont care about the outcome and return Ok
            // for channel close request, we do not care about the response as channel is already closed.
            // for channel open request and request is rejected, channel is left in init state and no new messages are accepted.
            _ => Ok(()),
        }
    }

    pub(crate) fn process_outbox_message_responses(
        dst_domain_id: T::DomainId,
        channel_id: ChannelId,
    ) -> DispatchResult {
        // fetch the next message response nonce to process
        // starts with nonce 0
        let channel =
            Channels::<T>::get(dst_domain_id, channel_id).ok_or(Error::<T>::MissingChannel)?;
        let mut last_message_response_nonce = channel.latest_response_received_message_nonce;

        let mut next_message_response_nonce = last_message_response_nonce
            .and_then(|nonce| nonce.checked_add(Nonce::one()))
            .unwrap_or(Nonce::zero());

        // TODO(ved): maybe a bound of number of message responses to process in a single call?
        let mut messages_processed = 0u32;
        while let Some(resp_msg) =
            OutboxResponses::<T>::take((dst_domain_id, channel_id, next_message_response_nonce))
        {
            // fetch original request
            let req_msg =
                Outbox::<T>::take((dst_domain_id, channel_id, next_message_response_nonce))
                    .ok_or(Error::<T>::MissingMessage)?;

            let resp = match (req_msg.payload, resp_msg.payload) {
                // process incoming protocol outbox message response.
                (
                    VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(req))),
                    VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(resp))),
                ) => Self::process_incoming_protocol_message_response(
                    dst_domain_id,
                    channel_id,
                    req,
                    resp,
                ),

                // process incoming endpoint outbox message response.
                (
                    VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))),
                    VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(resp))),
                ) => {
                    if let Some(endpoint_handler) =
                        T::get_endpoint_response_handler(&req.dst_endpoint)
                    {
                        endpoint_handler.message_response(
                            dst_domain_id,
                            (channel_id, next_message_response_nonce),
                            req,
                            resp,
                        )
                    } else {
                        Err(Error::<T>::NoMessageHandler.into())
                    }
                }

                (_, _) => Err(Error::<T>::InvalidMessagePayload.into()),
            };

            // deposit event notifying the message status.
            match resp {
                Ok(_) => Self::deposit_event(Event::OutboxMessageResult {
                    domain_id: dst_domain_id,
                    channel_id,
                    nonce: next_message_response_nonce,
                    result: OutboxMessageResult::Ok,
                }),
                Err(err) => Self::deposit_event(Event::OutboxMessageResult {
                    domain_id: dst_domain_id,
                    channel_id,
                    nonce: next_message_response_nonce,
                    result: OutboxMessageResult::Err(err),
                }),
            }

            last_message_response_nonce = Some(next_message_response_nonce);
            next_message_response_nonce = next_message_response_nonce
                .checked_add(Nonce::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
            messages_processed += 1;
        }

        if messages_processed > 0 {
            // distribute rewards to relayers for relaying the outbox messages.
            let reward = BalanceOf::<T>::from(messages_processed)
                .checked_mul(&channel.fee.outbox_fee.relayer_pool_fee)
                .ok_or(ArithmeticError::Overflow)?;

            Self::distribute_reward_to_relayers(reward)?;

            Channels::<T>::mutate(
                dst_domain_id,
                channel_id,
                |maybe_channel| -> DispatchResult {
                    let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                    channel.latest_response_received_message_nonce = last_message_response_nonce;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}
