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

use codec::{Decode, Encode, MaxEncodedLen};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;

/// State of a channel.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
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
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
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
    pub(crate) latest_response_received_message_nonce: Nonce,
    /// Maximum outgoing non-delivered messages.
    pub(crate) max_outgoing_messages: u64,
}

#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct InitiateChannelParams {
    max_outgoing_messages: u64,
}

#[frame_support::pallet]
mod pallet {
    use crate::{Channel, ChannelId, ChannelState, InitiateChannelParams, U256};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_messenger::SystemDomainTracker;
    use sp_runtime::traits::Hash;
    use sp_runtime::ArithmeticError;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// Domain ID uniquely identifies a Domain.
        type DomainId: Parameter + Member + Default + Copy + MaxEncodedLen;
        /// System domain tracker.
        type SystemDomainTracker: SystemDomainTracker<
            <<Self as frame_system::Config>::Hashing as Hash>::Output,
        >;
    }

    /// Pallet messenger used to communicate between domains and other blockchains.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
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
    }

    /// `pallet-messenger` errors
    #[pallet::error]
    pub enum Error<T> {
        /// Emits when there is no channel for a given Channel ID.
        MissingChannel,

        /// Emits when the said channel is not in an open state.
        InvalidChannelState,
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
            domain_id: T::DomainId,
            params: InitiateChannelParams,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // TODO(ved): test validity of the domain

            let channel_id = NextChannelId::<T>::get(domain_id);
            let next_channel_id = channel_id
                .checked_add(U256::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

            Channels::<T>::insert(
                domain_id,
                channel_id,
                Channel {
                    channel_id,
                    state: ChannelState::Initiated,
                    next_inbox_nonce: Default::default(),
                    next_outbox_nonce: Default::default(),
                    latest_response_received_message_nonce: Default::default(),
                    max_outgoing_messages: params.max_outgoing_messages,
                },
            );

            NextChannelId::<T>::insert(domain_id, next_channel_id);
            Self::deposit_event(Event::ChannelInitiated {
                domain_id,
                channel_id,
            });

            Ok(())
        }

        /// An open channel is closed with a foreign domain.
        /// Channel is set to Closed and do not accept or receive any messages.
        /// Only a root user can close an open channel.
        #[pallet::weight((10_000, Pays::No))]
        pub fn close_channel(
            origin: OriginFor<T>,
            domain_id: T::DomainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            ensure_root(origin)?;
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
    }

    impl<T: Config> Pallet<T> {
        /// Opens an initiated channel.
        pub(crate) fn open_channel(
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
    }
}
