// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet messenger used to communicate between domains and other blockchains.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

mod fees;
mod messages;
mod relayer;
mod verification;

use codec::{Decode, Encode};
use frame_support::traits::Currency;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;
use sp_messenger::messages::{ChannelId, CrossDomainMessage, FeeModel, Message, Nonce};
use sp_runtime::traits::Hash;
use sp_runtime::DispatchError;

/// State of a channel.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ChannelState {
    /// Channel between domains is initiated but do not yet send or receive messages in this state.
    #[default]
    Initiated,
    /// Channel is open and can send and receive messages.
    Open,
    /// Channel is closed and do not send or receive messages.
    Closed,
}

/// Channel describes a bridge to exchange messages between two domains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Channel<Balance> {
    /// Channel identifier.
    pub(crate) channel_id: ChannelId,
    /// State of the channel.
    pub(crate) state: ChannelState,
    /// Next inbox nonce.
    pub(crate) next_inbox_nonce: Nonce,
    /// Next outbox nonce.
    pub(crate) next_outbox_nonce: Nonce,
    /// Latest outbox message nonce for which response was received from dst_domain.
    pub(crate) latest_response_received_message_nonce: Option<Nonce>,
    /// Maximum outgoing non-delivered messages.
    pub(crate) max_outgoing_messages: u32,
    /// Fee model for this channel between domains.
    pub(crate) fee: FeeModel<Balance>,
}

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub enum OutboxMessageResult {
    /// Message response handler returned Ok.
    Ok,
    /// Message response handler failed with Err.
    Err(DispatchError),
}

pub(crate) type StateRootOf<T> = <<T as frame_system::Config>::Hashing as Hash>::Output;
pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub(crate) struct ValidatedRelayMessage<Balance> {
    msg: Message<Balance>,
    should_init_channel: bool,
}

#[frame_support::pallet]
mod pallet {
    use crate::relayer::{RelayerId, RelayerInfo};
    use crate::verification::{StorageProofVerifier, VerificationError};
    use crate::{
        relayer, BalanceOf, Channel, ChannelId, ChannelState, FeeModel, Nonce, OutboxMessageResult,
        StateRootOf, ValidatedRelayMessage, U256,
    };
    use frame_support::pallet_prelude::*;
    use frame_support::traits::ReservableCurrency;
    use frame_system::pallet_prelude::*;
    use sp_core::storage::StorageKey;
    use sp_domains::DomainId;
    use sp_messenger::endpoint::{Endpoint, EndpointHandler, EndpointRequest, Sender};
    use sp_messenger::messages::{
        CrossDomainMessage, InitiateChannelParams, Message, MessageId, Payload,
        ProtocolMessageRequest, RequestResponse, VersionedPayload,
    };
    use sp_messenger::DomainTracker as DomainTrackerT;
    use sp_runtime::ArithmeticError;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Gets the domain_id that is treated as src_domain for outgoing messages.
        type SelfDomainId: Get<DomainId>;
        /// System domain tracker.
        type DomainTracker: DomainTrackerT<StateRootOf<Self>>;
        /// function to fetch endpoint response handler by Endpoint.
        fn get_endpoint_response_handler(
            endpoint: &Endpoint,
        ) -> Option<Box<dyn EndpointHandler<MessageId>>>;
        /// Currency type pallet uses for fees and deposits.
        type Currency: ReservableCurrency<Self::AccountId>;
        /// Maximum number of relayers that can join this domain.
        type MaximumRelayers: Get<u32>;
        /// Relayer deposit to become a relayer for this Domain.
        type RelayerDeposit: Get<BalanceOf<Self>>;
    }

    /// Pallet messenger used to communicate between domains and other blockchains.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the next channel id for a foreign domain.
    #[pallet::storage]
    #[pallet::getter(fn next_channel_id)]
    pub(super) type NextChannelId<T: Config> =
        StorageMap<_, Identity, DomainId, ChannelId, ValueQuery>;

    /// Stores channel config between two domains.
    /// Key points to the foreign domain wrt own domain's storage name space
    #[pallet::storage]
    #[pallet::getter(fn channels)]
    pub(super) type Channels<T: Config> = StorageDoubleMap<
        _,
        Identity,
        DomainId,
        Identity,
        ChannelId,
        Channel<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Stores the incoming messages that are yet to be processed.
    /// Messages are processed in the inbox nonce order of domain channel.
    #[pallet::storage]
    #[pallet::getter(fn inbox)]
    pub(super) type Inbox<T: Config> = CountedStorageMap<
        _,
        Identity,
        (DomainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Stores the message responses of the incoming processed responses.
    /// Used by the dst_domain to verify the message response.
    #[pallet::storage]
    #[pallet::getter(fn inbox_responses)]
    pub(super) type InboxResponses<T: Config> = CountedStorageMap<
        _,
        Identity,
        (DomainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Stores the outgoing messages that are awaiting message responses from the dst_domain.
    /// Messages are processed in the outbox nonce order of domain channel.
    #[pallet::storage]
    #[pallet::getter(fn outbox)]
    pub(super) type Outbox<T: Config> = CountedStorageMap<
        _,
        Identity,
        (DomainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn outbox_responses)]
    pub(super) type OutboxResponses<T: Config> = CountedStorageMap<
        _,
        Identity,
        (DomainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn relayers_info)]
    pub(super) type RelayersInfo<T: Config> =
        StorageMap<_, Identity, RelayerId<T>, RelayerInfo<T::AccountId, BalanceOf<T>>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn relayers)]
    pub(super) type Relayers<T: Config> =
        StorageValue<_, BoundedVec<RelayerId<T>, T::MaximumRelayers>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_relayer_idx)]
    pub(super) type NextRelayerIdx<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn relayer_messages)]
    pub(super) type RelayerMessages<T: Config> =
        StorageMap<_, Identity, RelayerId<T>, relayer::RelayerMessages, OptionQuery>;

    /// `pallet-messenger` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when a channel between two domains in initiated.
        ChannelInitiated {
            /// Foreign domain id this channel connects to.
            domain_id: DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two domains in closed.
        ChannelClosed {
            /// Foreign domain id this channel connects to.
            domain_id: DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two domains in open.
        ChannelOpen {
            /// Foreign domain id this channel connects to.
            domain_id: DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a new message is added to the outbox.
        OutboxMessage {
            domain_id: DomainId,
            channel_id: ChannelId,
            nonce: Nonce,
            relayer_id: RelayerId<T>,
        },

        /// Emits when a message response is available for Outbox message.
        OutboxMessageResponse {
            /// Destination domain ID.
            domain_id: DomainId,
            /// Channel Is
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits outbox message result.
        OutboxMessageResult {
            domain_id: DomainId,
            channel_id: ChannelId,
            nonce: Nonce,
            result: OutboxMessageResult,
        },

        /// Emits when a new inbox message is validated and added to Inbox.
        InboxMessage {
            domain_id: DomainId,
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits when a message response is available for Inbox message.
        InboxMessageResponse {
            /// Destination domain ID.
            domain_id: DomainId,
            /// Channel Is
            channel_id: ChannelId,
            nonce: Nonce,
            relayer_id: RelayerId<T>,
        },

        /// Emits when a relayer successfully joins the relayer set.
        RelayerJoined {
            /// Owner who controls the relayer.
            owner: T::AccountId,
            /// Relayer address to which rewards are paid.
            relayer_id: RelayerId<T>,
        },

        /// Emits when a relayer exists the relayer set.
        RelayerExited {
            /// Owner who controls the relayer.
            owner: T::AccountId,
            /// Relayer address which exited the set.
            relayer_id: RelayerId<T>,
        },
    }

    type Tag = (DomainId, ChannelId, Nonce);
    fn unsigned_validity<T: Config>(prefix: &'static str, provides: Tag) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(provides)
            .longevity(TransactionLongevity::MAX)
            // We need this extrinsic to be propagated to the farmer nodes.
            .propagate(true)
            .build()
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::relay_message { msg: xdm } => {
                    let ValidatedRelayMessage {
                        msg,
                        should_init_channel,
                    } = Self::do_validate_relay_message(xdm)?;
                    Self::pre_dispatch_relay_message(msg, should_init_channel)
                }
                Call::relay_message_response { msg: xdm } => {
                    let msg = Self::do_validate_relay_message_response(xdm)?;
                    Self::pre_dispatch_relay_message_response(msg)
                }
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        /// Validate unsigned call to this module.
        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::relay_message { msg: xdm } => {
                    let ValidatedRelayMessage {
                        msg,
                        should_init_channel: _,
                    } = Self::do_validate_relay_message(xdm)?;
                    let provides_tag = (msg.dst_domain_id, msg.channel_id, msg.nonce);
                    unsigned_validity::<T>("MessengerInbox", provides_tag)
                }
                Call::relay_message_response { msg: xdm } => {
                    let msg = Self::do_validate_relay_message_response(xdm)?;
                    let provides_tag = (msg.dst_domain_id, msg.channel_id, msg.nonce);
                    unsigned_validity::<T>("MessengerOutboxResponse", provides_tag)
                }
                _ => InvalidTransaction::Call.into(),
            }
        }
    }

    /// `pallet-messenger` errors
    #[pallet::error]
    pub enum Error<T> {
        /// Emits when the domain is neither core domain nor a system domain.
        InvalidDomain,

        /// Emits when there is no channel for a given Channel ID.
        MissingChannel,

        /// Emits when the said channel is not in an open state.
        InvalidChannelState,

        /// Emits when there are no open channels for a domain
        NoOpenChannel,

        /// Emits when there are not message handler with given endpoint ID.
        NoMessageHandler,

        /// Emits when the outbox is full for a channel.
        OutboxFull,

        /// Emits when the message payload is invalid.
        InvalidMessagePayload,

        /// Emits when the message destination is not valid.
        InvalidMessageDestination,

        /// Emits when the message verification failed.
        MessageVerification(VerificationError),

        /// Emits when there is no message available for the given nonce.
        MissingMessage,

        /// Emits when relayer tries to re-join the relayers.
        AlreadyRelayer,

        /// Emits when a non relayer tries to do relayers specific actions.
        NotRelayer,

        /// Emits when there is mismatch between caller and relayer owner.
        NotOwner,

        /// Emits when a relayer tries to join when total relayers already reached maximum count.
        MaximumRelayerCount,

        /// Emits when there are no relayers to relay messages between domains.
        NoRelayersToAssign,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            let results = RelayerMessages::<T>::clear(u32::MAX, None);
            let db_weight = T::DbWeight::get();
            db_weight
                .reads(results.loops as u64)
                .saturating_add(db_weight.writes(1))
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A new Channel is initiated with a foreign domain.
        /// Next Channel ID is used to assign the new channel.
        /// Channel is set to initiated and do not accept or receive any messages.
        /// Only a root user can create the channel.
        #[pallet::weight((10_000, Pays::No))]
        pub fn initiate_channel(
            origin: OriginFor<T>,
            dst_domain_id: DomainId,
            params: InitiateChannelParams<BalanceOf<T>>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // TODO(ved): fee for channel open

            // initiate the channel config
            let channel_id = Self::do_init_channel(dst_domain_id, params)?;

            // send message to dst_domain
            Self::new_outbox_message(
                T::SelfDomainId::get(),
                dst_domain_id,
                channel_id,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelOpen(params),
                ))),
            )?;

            Ok(())
        }

        /// An open channel is closed with a foreign domain.
        /// Channel is set to Closed and do not accept or receive any messages.
        /// Only a root user can close an open channel.
        #[pallet::weight((10_000, Pays::No))]
        pub fn close_channel(
            origin: OriginFor<T>,
            domain_id: DomainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::do_close_channel(domain_id, channel_id)?;
            Self::new_outbox_message(
                T::SelfDomainId::get(),
                domain_id,
                channel_id,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelClose,
                ))),
            )?;

            Ok(())
        }

        /// Receives an Inbox message that needs to be validated and processed.
        #[pallet::weight((10_000, Pays::No))]
        pub fn relay_message(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<StateRootOf<T>>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::process_inbox_messages(msg.src_domain_id, msg.channel_id)?;
            Ok(())
        }

        /// Receives a response from the dst_domain for a message in Outbox.
        #[pallet::weight((10_000, Pays::No))]
        pub fn relay_message_response(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<StateRootOf<T>>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::process_outbox_message_responses(msg.src_domain_id, msg.channel_id)?;
            Ok(())
        }

        /// Declare the desire to become a relayer for this domain by reserving the relayer deposit.
        #[pallet::weight((10_000, Pays::No))]
        pub fn join_relayer_set(origin: OriginFor<T>, relayer_id: RelayerId<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_join_relayer_set(who, relayer_id)?;
            Ok(())
        }

        /// Declare the desire to exit relaying for this domain.
        #[pallet::weight((10_000, Pays::No))]
        pub fn exit_relayer_set(origin: OriginFor<T>, relayer_id: RelayerId<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_exit_relayer_set(who, relayer_id)?;
            Ok(())
        }
    }

    impl<T: Config> Sender<T::AccountId> for Pallet<T> {
        type MessageId = MessageId;

        fn send_message(
            sender: &T::AccountId,
            dst_domain_id: DomainId,
            req: EndpointRequest,
        ) -> Result<Self::MessageId, DispatchError> {
            let (channel_id, fee_model) = Self::get_open_channel_for_domain(dst_domain_id)
                .ok_or(Error::<T>::NoOpenChannel)?;

            // ensure fees are paid by the sender
            Self::ensure_fees_for_outbox_message(sender, &fee_model)?;

            let nonce = Self::new_outbox_message(
                T::SelfDomainId::get(),
                dst_domain_id,
                channel_id,
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))),
            )?;
            Ok((channel_id, nonce))
        }
    }

    impl<T: Config> Pallet<T> {
        /// Returns the last open channel for a given domain.
        fn get_open_channel_for_domain(
            dst_domain_id: DomainId,
        ) -> Option<(ChannelId, FeeModel<BalanceOf<T>>)> {
            let mut next_channel_id = NextChannelId::<T>::get(dst_domain_id);

            // loop through channels in descending order until open channel is found.
            // we always prefer latest opened channel.
            while let Some(channel_id) = next_channel_id.checked_sub(ChannelId::one()) {
                if let Some(channel) = Channels::<T>::get(dst_domain_id, channel_id) {
                    if channel.state == ChannelState::Open {
                        return Some((channel_id, channel.fee));
                    }
                }

                next_channel_id = channel_id
            }

            None
        }

        /// Opens an initiated channel.
        pub(crate) fn do_open_channel(
            domain_id: DomainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            Channels::<T>::try_mutate(domain_id, channel_id, |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;

                ensure!(
                    channel.state == ChannelState::Initiated,
                    Error::<T>::InvalidChannelState
                );

                channel.state = ChannelState::Open;
                Ok(())
            })?;

            Self::deposit_event(Event::ChannelOpen {
                domain_id,
                channel_id,
            });

            Ok(())
        }

        pub(crate) fn do_close_channel(
            domain_id: DomainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            Channels::<T>::try_mutate(domain_id, channel_id, |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;

                ensure!(
                    channel.state == ChannelState::Open,
                    Error::<T>::InvalidChannelState
                );

                channel.state = ChannelState::Closed;
                Ok(())
            })?;

            Self::deposit_event(Event::ChannelClosed {
                domain_id,
                channel_id,
            });

            Ok(())
        }

        pub(crate) fn do_init_channel(
            dst_domain_id: DomainId,
            init_params: InitiateChannelParams<BalanceOf<T>>,
        ) -> Result<ChannelId, DispatchError> {
            // ensure domain is either system domain or core domain
            ensure!(
                dst_domain_id.is_core() || dst_domain_id.is_system(),
                Error::<T>::InvalidDomain,
            );

            let channel_id = NextChannelId::<T>::get(dst_domain_id);
            let next_channel_id = channel_id
                .checked_add(U256::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

            Channels::<T>::insert(
                dst_domain_id,
                channel_id,
                Channel {
                    channel_id,
                    state: ChannelState::Initiated,
                    next_inbox_nonce: Default::default(),
                    next_outbox_nonce: Default::default(),
                    latest_response_received_message_nonce: Default::default(),
                    max_outgoing_messages: init_params.max_outgoing_messages,
                    fee: init_params.fee_model,
                },
            );

            NextChannelId::<T>::insert(dst_domain_id, next_channel_id);
            Self::deposit_event(Event::ChannelInitiated {
                domain_id: dst_domain_id,
                channel_id,
            });
            Ok(channel_id)
        }

        pub(crate) fn do_validate_relay_message(
            xdm: &CrossDomainMessage<StateRootOf<T>>,
        ) -> Result<ValidatedRelayMessage<BalanceOf<T>>, TransactionValidityError> {
            let mut should_init_channel = false;
            let next_nonce = match Channels::<T>::get(xdm.src_domain_id, xdm.channel_id) {
                None => {
                    // if there is no channel config, this must the Channel open request.
                    // so nonce is 0
                    should_init_channel = true;
                    // TODO(ved): collect fees to open channel
                    Nonce::zero()
                }
                Some(channel) => {
                    // Ensure channel is ready to receive messages
                    ensure!(
                        channel.state == ChannelState::Open,
                        InvalidTransaction::Call
                    );

                    // ensure the fees are deposited to the messenger account to pay
                    // for relayer set.
                    Self::ensure_fees_for_inbox_message(&channel.fee).map_err(|_| {
                        TransactionValidityError::Invalid(InvalidTransaction::Payment)
                    })?;
                    channel.next_inbox_nonce
                }
            };

            // derive the key as stored on the src_domain.
            let key = StorageKey(Outbox::<T>::hashed_key_for((
                T::SelfDomainId::get(),
                xdm.channel_id,
                xdm.nonce,
            )));

            // verify and decode message
            let msg = Self::do_verify_xdm(next_nonce, key, xdm)?;
            Ok(ValidatedRelayMessage {
                msg,
                should_init_channel,
            })
        }

        pub(crate) fn pre_dispatch_relay_message(
            msg: Message<BalanceOf<T>>,
            should_init_channel: bool,
        ) -> Result<(), TransactionValidityError> {
            if should_init_channel {
                if let VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelOpen(params),
                ))) = msg.payload
                {
                    Self::do_init_channel(msg.src_domain_id, params)
                        .map_err(|_| InvalidTransaction::Call)?;
                } else {
                    return Err(InvalidTransaction::Call.into());
                }
            }

            Self::deposit_event(Event::InboxMessage {
                domain_id: msg.src_domain_id,
                channel_id: msg.channel_id,
                nonce: msg.nonce,
            });
            Inbox::<T>::insert((msg.src_domain_id, msg.channel_id, msg.nonce), msg);
            Ok(())
        }

        pub(crate) fn do_validate_relay_message_response(
            xdm: &CrossDomainMessage<StateRootOf<T>>,
        ) -> Result<Message<BalanceOf<T>>, TransactionValidityError> {
            // channel should be open and message should be present in outbox
            let next_nonce = match Channels::<T>::get(xdm.src_domain_id, xdm.channel_id) {
                // unknown channel. return
                None => return Err(InvalidTransaction::Call.into()),
                // verify if channel can receive messages
                Some(channel) => {
                    match channel.latest_response_received_message_nonce {
                        None => {
                            // this is the first message response.
                            // ensure channel is in init state
                            ensure!(
                                channel.state == ChannelState::Initiated,
                                InvalidTransaction::Call
                            );
                            Some(Nonce::zero())
                        }
                        Some(last_nonce) => last_nonce.checked_add(Nonce::one()),
                    }
                }
            }
            .ok_or(TransactionValidityError::Invalid(InvalidTransaction::Call))?;

            // derive the key as stored on the src_domain.
            let key = StorageKey(InboxResponses::<T>::hashed_key_for((
                T::SelfDomainId::get(),
                xdm.channel_id,
                xdm.nonce,
            )));

            // verify, decode, and store the message
            Self::do_verify_xdm(next_nonce, key, xdm)
        }

        pub(crate) fn pre_dispatch_relay_message_response(
            msg: Message<BalanceOf<T>>,
        ) -> Result<(), TransactionValidityError> {
            Self::deposit_event(Event::OutboxMessageResponse {
                domain_id: msg.src_domain_id,
                channel_id: msg.channel_id,
                nonce: msg.nonce,
            });

            OutboxResponses::<T>::insert((msg.src_domain_id, msg.channel_id, msg.nonce), msg);
            Ok(())
        }

        pub(crate) fn do_verify_xdm(
            next_nonce: Nonce,
            storage_key: StorageKey,
            xdm: &CrossDomainMessage<StateRootOf<T>>,
        ) -> Result<Message<BalanceOf<T>>, TransactionValidityError> {
            // fetch state roots from System domain tracker
            let state_roots = T::DomainTracker::system_domain_state_roots();
            if !state_roots.contains(&xdm.proof.state_root) {
                return Err(TransactionValidityError::Invalid(
                    InvalidTransaction::BadProof,
                ));
            }

            // verify intermediate core domain proof and retrieve state root of the message.
            let core_domain_state_root_proof = xdm.proof.core_domain_proof.clone();
            let state_root = {
                // if the src_domain is a system domain, return the state root as is since message is on system domain runtime
                if xdm.src_domain_id.is_system() && xdm.proof.core_domain_proof.is_none() {
                    Ok(xdm.proof.state_root)
                }
                // if the src_domain is a core domain, then return the state root of the core domain by verifying the core domain proof.
                else if xdm.src_domain_id.is_core() && core_domain_state_root_proof.is_some() {
                    let core_domain_state_root_key =
                        T::DomainTracker::domain_state_root_storage_key(xdm.src_domain_id);
                    StorageProofVerifier::<T::Hashing>::verify_and_get_value::<StateRootOf<T>>(
                        &xdm.proof.state_root,
                        core_domain_state_root_proof.expect("checked for existence value above"),
                        core_domain_state_root_key,
                    )
                    .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::BadProof))
                } else {
                    Err(TransactionValidityError::Invalid(
                        InvalidTransaction::BadProof,
                    ))
                }
            }?;

            // channel should be either already be created or match the next channelId for domain.
            let next_channel_id = NextChannelId::<T>::get(xdm.dst_domain_id);
            ensure!(xdm.channel_id <= next_channel_id, InvalidTransaction::Call);

            // verify nonce
            // nonce should be either be next or in future.
            ensure!(xdm.nonce >= next_nonce, InvalidTransaction::BadProof);

            // verify and decode the message
            let msg = StorageProofVerifier::<T::Hashing>::verify_and_get_value::<
                Message<BalanceOf<T>>,
            >(&state_root, xdm.proof.message_proof.clone(), storage_key)
            .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::BadProof))?;

            Ok(msg)
        }
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    pub fn submit_outbox_message_unsigned(msg: CrossDomainMessage<StateRootOf<T>>) {
        let call = Call::relay_message { msg };
        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::messenger", "Submitted outbox message");
            }
            Err(()) => {
                log::error!(
                    target: "runtime::messenger",
                    "Error submitting outbox message",
                );
            }
        }
    }

    pub fn submit_inbox_response_message_unsigned(msg: CrossDomainMessage<StateRootOf<T>>) {
        let call = Call::relay_message_response { msg };
        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::messenger", "Submitted inbox response message");
            }
            Err(()) => {
                log::error!(
                    target: "runtime::messenger",
                    "Error submitting inbox response message",
                );
            }
        }
    }
}
