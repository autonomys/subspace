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

//! Pallet transporter used to move funds between domains.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use codec::{Decode, Encode};
use frame_support::traits::Currency;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Nonce used as strictly increasing unique id for a transfer between two domains.
pub type Nonce = U256;

/// Location that either sends or receives transfers between domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Location<DomainId, AccountId> {
    /// Unique identity of domain.
    pub domain_id: DomainId,
    /// Unique account on domain.
    pub account_id: AccountId,
}

/// Transfer status.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Transfer<DomainId, Address, Balance> {
    /// Unique nonce of this transfer between sender and receiver.
    pub nonce: Nonce,
    /// Amount being transferred between entities.
    pub amount: Balance,
    /// Sender location of the transfer.
    pub sender: Location<DomainId, Address>,
    /// Receiver location of the transfer.
    pub receiver: Location<DomainId, Address>,
}

/// Balance type used by the pallet.
pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[frame_support::pallet]
mod pallet {
    use crate::{BalanceOf, Location, Nonce, Transfer};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
    use frame_system::pallet_prelude::*;
    use sp_runtime::ArithmeticError;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Domain ID uniquely identifies a Domain.
        type DomainId: Parameter + Member + Default + Copy + MaxEncodedLen;

        /// Gets the domain_id of the current execution environment.
        type SelfDomainId: Get<Self::DomainId>;

        /// Currency used by this pallet.
        type Currency: Currency<Self::AccountId>;
    }

    /// Pallet transporter to move funds between domains.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the next outgoing transfer nonce.
    #[pallet::storage]
    #[pallet::getter(fn next_outgoing_transfer_nonce)]
    pub(super) type NextOutgoingTransferNonce<T: Config> =
        StorageMap<_, Identity, T::DomainId, Nonce, ValueQuery>;

    /// All the outgoing transfers on this execution environment.
    #[pallet::storage]
    #[pallet::getter(fn outgoing_transfers)]
    pub(super) type OutgoingTransfers<T: Config> = StorageDoubleMap<
        _,
        Identity,
        T::DomainId,
        Identity,
        Nonce,
        Transfer<T::DomainId, T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Stores the next incoming transfer nonce.
    #[pallet::storage]
    #[pallet::getter(fn next_incoming_transfer_nonce)]
    pub(super) type NextIncomingTransferNonce<T: Config> =
        StorageMap<_, Identity, T::DomainId, Nonce, ValueQuery>;

    /// All the incoming transfers on this execution environment.
    #[pallet::storage]
    #[pallet::getter(fn incoming_transfers)]
    pub(super) type IncomingTransfers<T: Config> = StorageDoubleMap<
        _,
        Identity,
        T::DomainId,
        Identity,
        Nonce,
        Transfer<T::DomainId, T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Events emitted by pallet-transporter.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when there is a new outgoing transfer.
        OutgoingTransfer {
            /// Destination domain the transfer is bound to.
            domain_id: T::DomainId,
            /// Nonce of the transfer.
            nonce: Nonce,
        },
    }

    /// Errors emitted by pallet-transporter.
    #[pallet::error]
    pub enum Error<T> {
        LowBalance,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Initiates transfer of funds from account on src_domain to account on dst_domain.
        /// Funds are burned on src_domain first and are minted on dst_domain using Messenger.
        #[pallet::weight((10_000, Pays::No))]
        pub fn transfer(
            origin: OriginFor<T>,
            dst_location: Location<T::DomainId, T::AccountId>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            T::Currency::withdraw(
                &sender,
                amount,
                WithdrawReasons::TRANSFER,
                ExistenceRequirement::AllowDeath,
            )
            .map_err(|_| Error::<T>::LowBalance)?;

            let dst_domain_id = dst_location.domain_id;
            let nonce = NextOutgoingTransferNonce::<T>::get(dst_domain_id);
            let next_nonce = nonce
                .checked_add(Nonce::one())
                .ok_or(ArithmeticError::Overflow)?;

            let transfer = Transfer {
                nonce,
                amount,
                sender: Location {
                    domain_id: T::SelfDomainId::get(),
                    account_id: sender,
                },
                receiver: dst_location,
            };

            OutgoingTransfers::<T>::insert(dst_domain_id, nonce, transfer);
            NextOutgoingTransferNonce::<T>::insert(dst_domain_id, next_nonce);
            Self::deposit_event(Event::<T>::OutgoingTransfer {
                domain_id: dst_domain_id,
                nonce,
            });
            Ok(())
        }
    }
}
