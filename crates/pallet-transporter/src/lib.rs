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

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Location that either sends or receives transfers between domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Location<DomainId, AccountId> {
    /// Unique identity of domain.
    pub domain_id: DomainId,
    /// Unique account on domain.
    pub account_id: AccountId,
}

/// Transfer of funds from one domain to another.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Transfer<DomainId, AccountId, Balance> {
    /// Amount being transferred between entities.
    pub amount: Balance,
    /// Sender location of the transfer.
    pub sender: Location<DomainId, AccountId>,
    /// Receiver location of the transfer.
    pub receiver: Location<DomainId, AccountId>,
}

/// Balance type used by the pallet.
pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type MessageIdOf<T> =
    <<T as Config>::Sender as sp_messenger::endpoint::Sender<<T as Config>::DomainId>>::MessageId;

#[frame_support::pallet]
mod pallet {
    use crate::{BalanceOf, Location, MessageIdOf, Transfer};
    use codec::{Decode, Encode};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
    use frame_system::pallet_prelude::*;
    use sp_messenger::endpoint::{
        Endpoint, EndpointHandler as EndpointHandlerT, EndpointId, EndpointRequest,
        EndpointResponse, Sender,
    };

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Domain ID uniquely identifies a Domain.
        type DomainId: Parameter + Member + Default + Copy + MaxEncodedLen;

        /// Gets the domain_id of the current execution environment.
        type SelfDomainId: Get<Self::DomainId>;

        /// Gets the endpoint_id of the this pallet in a given execution environment.
        type SelfEndpointId: Get<EndpointId>;

        /// Currency used by this pallet.
        type Currency: Currency<Self::AccountId>;

        /// Sender used to transfer funds.
        type Sender: Sender<Self::DomainId>;
    }

    /// Pallet transporter to move funds between domains.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// All the outgoing transfers on this execution environment.
    #[pallet::storage]
    #[pallet::getter(fn outgoing_transfers)]
    pub(super) type OutgoingTransfers<T: Config> = StorageDoubleMap<
        _,
        Identity,
        T::DomainId,
        Identity,
        MessageIdOf<T>,
        Transfer<T::DomainId, T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Events emitted by pallet-transporter.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when there is a new outgoing transfer.
        OutgoingTransferInitiated {
            /// Destination domain the transfer is bound to.
            domain_id: T::DomainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
        },

        /// Emits when a given outgoing transfer was failed on dst_domain.
        OutgoingTransferFailed {
            /// Destination domain the transfer is bound to.
            domain_id: T::DomainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
            /// Error from dst_domain endpoint.
            err: DispatchError,
        },

        /// Emits when a given outgoing transfer was successful.
        OutgoingTransferSuccessful {
            /// Destination domain the transfer is bound to.
            domain_id: T::DomainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
        },

        /// Emits when a given incoming transfer was successfully processed.
        IncomingTransferSuccessful {
            /// Source domain the transfer is coming from.
            domain_id: T::DomainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
        },
    }

    /// Errors emitted by pallet-transporter.
    #[pallet::error]
    pub enum Error<T> {
        /// Emits when the account has low balance to make a transfer.
        LowBalance,
        /// Failed to decode transfer payload.
        InvalidPayload,
        /// Emits when the request for a response received is missing.
        MissingTransferRequest,
        /// Emits when the request doesn't match the expected one..
        InvalidTransferRequest,
        /// Emits when the incoming message is not bound to this domain.
        UnexpectedMessage,
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

            // burn transfer amount
            T::Currency::withdraw(
                &sender,
                amount,
                WithdrawReasons::TRANSFER,
                ExistenceRequirement::AllowDeath,
            )
            .map_err(|_| Error::<T>::LowBalance)?;

            // initiate transfer
            let dst_domain_id = dst_location.domain_id;
            let transfer = Transfer {
                amount,
                sender: Location {
                    domain_id: T::SelfDomainId::get(),
                    account_id: sender,
                },
                receiver: dst_location,
            };

            // send message
            let message_id = T::Sender::send_message(
                dst_domain_id,
                EndpointRequest {
                    src_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
                    // destination endpoint must be transporter with same id
                    dst_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
                    payload: transfer.encode(),
                },
            )?;

            OutgoingTransfers::<T>::insert(dst_domain_id, message_id, transfer);
            Self::deposit_event(Event::<T>::OutgoingTransferInitiated {
                domain_id: dst_domain_id,
                message_id,
            });
            Ok(())
        }
    }

    /// Endpoint handler implementation for pallet transporter.
    #[derive(Debug)]
    pub struct EndpointHandler<T>(pub PhantomData<T>);

    impl<T: Config> EndpointHandlerT<T::DomainId, MessageIdOf<T>> for EndpointHandler<T> {
        fn message(
            &self,
            src_domain_id: T::DomainId,
            message_id: MessageIdOf<T>,
            req: EndpointRequest,
        ) -> EndpointResponse {
            //TODO(ved): check if we allow messages from src_domain

            // ensure message is not from the self
            ensure!(
                T::SelfDomainId::get() != src_domain_id,
                Error::<T>::InvalidTransferRequest
            );

            // check the endpoint id
            ensure!(
                req.dst_endpoint == Endpoint::Id(T::SelfEndpointId::get()),
                Error::<T>::UnexpectedMessage
            );

            // decode payload and process message
            let req = match Transfer::<T::DomainId, _, _>::decode(&mut req.payload.as_slice()) {
                Ok(req) => req,
                Err(_) => return Err(Error::<T>::InvalidPayload.into()),
            };

            // mint the funds to dst_account
            T::Currency::deposit_creating(&req.receiver.account_id, req.amount);
            frame_system::Pallet::<T>::deposit_event(Into::<<T as Config>::Event>::into(
                Event::<T>::IncomingTransferSuccessful {
                    domain_id: src_domain_id,
                    message_id,
                },
            ));
            Ok(vec![])
        }

        fn message_response(
            &self,
            dst_domain_id: T::DomainId,
            message_id: MessageIdOf<T>,
            req: EndpointRequest,
            resp: EndpointResponse,
        ) -> DispatchResult {
            // ensure request is valid
            let transfer = OutgoingTransfers::<T>::take(dst_domain_id, message_id)
                .ok_or(Error::<T>::MissingTransferRequest)?;
            ensure!(
                req.payload == transfer.encode(),
                Error::<T>::InvalidTransferRequest
            );

            // process response
            match resp {
                Ok(_) => {
                    // transfer is successful
                    frame_system::Pallet::<T>::deposit_event(Into::<<T as Config>::Event>::into(
                        Event::<T>::OutgoingTransferSuccessful {
                            domain_id: dst_domain_id,
                            message_id,
                        },
                    ));
                }
                Err(err) => {
                    // transfer failed
                    // revert burned funds
                    T::Currency::deposit_creating(&transfer.sender.account_id, transfer.amount);
                    frame_system::Pallet::<T>::deposit_event(Into::<<T as Config>::Event>::into(
                        Event::<T>::OutgoingTransferFailed {
                            domain_id: dst_domain_id,
                            message_id,
                            err,
                        },
                    ));
                }
            }

            Ok(())
        }
    }
}
