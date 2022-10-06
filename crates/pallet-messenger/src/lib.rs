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
// TODO(ved): remove once all the types and traits are connected
#![allow(dead_code)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

mod messages;
mod verification;

use codec::{Decode, Encode};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;
use sp_runtime::traits::Hash;

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

/// Channel identity.
pub type ChannelId = U256;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Channel describes a bridge to exchange messages between two domains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Channel {
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
}

#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct InitiateChannelParams {
    max_outgoing_messages: u32,
}

pub(crate) type StateRootOf<T> = <<T as frame_system::Config>::Hashing as Hash>::Output;

#[frame_support::pallet]
mod pallet {
    use crate::messages::{
        CrossDomainMessage, Message, Payload, ProtocolMessageRequest, RequestResponse,
        VersionedPayload,
    };
    use crate::verification::{StorageProofVerifier, VerificationError};
    use crate::{
        Channel, ChannelId, ChannelState, InitiateChannelParams, Nonce, StateRootOf, U256,
    };
    use frame_support::pallet_prelude::*;
    use frame_support::transactional;
    use frame_system::pallet_prelude::*;
    use sp_core::storage::StorageKey;
    use sp_messenger::SystemDomainTracker;
    use sp_runtime::ArithmeticError;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// Domain ID uniquely identifies a Domain.
        type DomainId: Parameter + Member + Default + Copy + MaxEncodedLen;
        /// Gets the domain_id that is treated as src_domain for outgoing messages.
        type SelfDomainId: Get<Self::DomainId>;
        /// System domain tracker.
        type SystemDomainTracker: SystemDomainTracker<StateRootOf<Self>>;
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
        StorageMap<_, Identity, T::DomainId, ChannelId, ValueQuery>;

    /// Stores channel config between two domains.
    /// Key points to the foreign domain wrt own domain's storage name space
    #[pallet::storage]
    #[pallet::getter(fn channels)]
    pub(super) type Channels<T: Config> =
        StorageDoubleMap<_, Identity, T::DomainId, Identity, ChannelId, Channel, OptionQuery>;

    /// Stores the incoming messages that are yet to be processed.
    /// Messages are processed in the inbox nonce order of domain channel.
    #[pallet::storage]
    #[pallet::getter(fn inbox)]
    pub(super) type Inbox<T: Config> = CountedStorageMap<
        _,
        Identity,
        (T::DomainId, ChannelId, Nonce),
        Message<T::DomainId>,
        OptionQuery,
    >;

    /// Stores the message responses of the incoming processed responses.
    /// Used by the dst_domain to verify the message response.
    #[pallet::storage]
    #[pallet::getter(fn inbox_message_responses)]
    pub(super) type InboxMessageResponses<T: Config> = CountedStorageMap<
        _,
        Identity,
        (T::DomainId, ChannelId, Nonce),
        Message<T::DomainId>,
        OptionQuery,
    >;

    /// Stores the outgoing messages that are awaiting message responses from the dst_domain.
    /// Messages are processed in the outbox nonce order of domain channel.
    #[pallet::storage]
    #[pallet::getter(fn outbox)]
    pub(super) type Outbox<T: Config> = CountedStorageMap<
        _,
        Identity,
        (T::DomainId, ChannelId, Nonce),
        Message<T::DomainId>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn outbox_message_responses)]
    pub(super) type OutboxMessageResponses<T: Config> = CountedStorageMap<
        _,
        Identity,
        (T::DomainId, ChannelId, Nonce),
        Message<T::DomainId>,
        OptionQuery,
    >;

    /// `pallet-messenger` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when a channel between two domains in initiated.
        ChannelInitiated {
            /// Foreign domain id this channel connects to.
            domain_id: T::DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two domains in closed.
        ChannelClosed {
            /// Foreign domain id this channel connects to.
            domain_id: T::DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two domains in open.
        ChannelOpen {
            /// Foreign domain id this channel connects to.
            domain_id: T::DomainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a new message is added to the outbox.
        OutboxMessage {
            domain_id: T::DomainId,
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits when a message response is available for Inbox message.
        InboxMessageResponse {
            /// Destination domain ID.
            domain_id: T::DomainId,
            /// Channel Is
            channel_id: ChannelId,
            nonce: Nonce,
        },
    }

    type Tag<DomainId> = (DomainId, ChannelId, Nonce);
    fn unsigned_validity<T: Config>(
        prefix: &'static str,
        provides: Tag<T::DomainId>,
    ) -> TransactionValidity {
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

        /// Validate unsigned call to this module.
        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // Firstly let's check that we call the right function.
            if let Call::relay_message { msg: bundled_msg } = call {
                // fetch state roots from System domain tracker
                let state_roots = T::SystemDomainTracker::latest_state_roots();
                if !state_roots.contains(&bundled_msg.proof.state_root) {
                    return InvalidTransaction::BadProof.into();
                }

                // channel should be either already be created or match the next channelId for domain.
                let next_channel_id = NextChannelId::<T>::get(bundled_msg.dst_domain_id);
                ensure!(
                    bundled_msg.channel_id <= next_channel_id,
                    InvalidTransaction::Call
                );

                // verify nonce
                let mut should_init_channel = false;
                let next_nonce =
                    match Channels::<T>::get(bundled_msg.src_domain_id, bundled_msg.channel_id) {
                        None => {
                            // if there is no channel config, this must the Channel open request.
                            // ensure nonce is 0
                            should_init_channel = true;
                            Nonce::zero()
                        }
                        Some(channel) => channel.next_inbox_nonce,
                    };
                // nonce should be either be next or in future.
                ensure!(
                    bundled_msg.nonce >= next_nonce,
                    InvalidTransaction::BadProof
                );

                // derive the key as stored on the src_domain.
                let key = Outbox::<T>::hashed_key_for((
                    T::SelfDomainId::get(),
                    bundled_msg.channel_id,
                    next_nonce,
                ));

                // verify, decode, and store the message
                let msg = StorageProofVerifier::<T::Hashing>::verify_and_get_value::<
                    Message<T::DomainId>,
                >(bundled_msg.proof.clone(), StorageKey(key))
                .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::BadProof))?;

                if should_init_channel {
                    if let VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                        ProtocolMessageRequest::ChannelOpen(params),
                    ))) = msg.payload
                    {
                        Self::do_init_channel(msg.src_domain_id, params)
                            .map_err(|_| InvalidTransaction::Call)?;
                    } else {
                        return InvalidTransaction::Call.into();
                    }
                }

                let provides_tag = (msg.dst_domain_id, msg.channel_id, next_nonce);
                Inbox::<T>::insert(
                    (
                        bundled_msg.src_domain_id,
                        bundled_msg.channel_id,
                        next_nonce,
                    ),
                    msg,
                );

                unsigned_validity::<T>("MessengerInbox", provides_tag)
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }

    /// `pallet-messenger` errors
    #[pallet::error]
    pub enum Error<T> {
        /// Emits when there is no channel for a given Channel ID.
        MissingChannel,

        /// Emits when the said channel is not in an open state.
        InvalidChannelState,

        /// Emits when the outbox is full for a channel.
        OutboxFull,

        /// Emits when the message payload is invalid.
        InvalidMessagePayload,

        /// Emits when the message verification failed.
        MessageVerification(VerificationError),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A new Channel is initiated with a foreign domain.
        /// Next Channel ID is used to assign the new channel.
        /// Channel is set to initiated and do not accept or receive any messages.
        /// Only a root user can create the channel.
        #[pallet::weight((10_000, Pays::No))]
        #[transactional]
        pub fn initiate_channel(
            origin: OriginFor<T>,
            dst_domain_id: T::DomainId,
            params: InitiateChannelParams,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // TODO(ved): test validity of the domain

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
        #[transactional]
        pub fn close_channel(
            origin: OriginFor<T>,
            domain_id: T::DomainId,
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
            msg: CrossDomainMessage<T::DomainId, StateRootOf<T>>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::process_inbox_messages(msg.src_domain_id, msg.nonce)?;
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Opens an initiated channel.
        pub(crate) fn do_open_channel(
            domain_id: T::DomainId,
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
            domain_id: T::DomainId,
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
            dst_domain_id: T::DomainId,
            init_params: InitiateChannelParams,
        ) -> Result<ChannelId, DispatchError> {
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
                },
            );

            NextChannelId::<T>::insert(dst_domain_id, next_channel_id);
            Self::deposit_event(Event::ChannelInitiated {
                domain_id: dst_domain_id,
                channel_id,
            });
            Ok(channel_id)
        }
    }
}
