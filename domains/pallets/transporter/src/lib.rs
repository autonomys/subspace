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

//! Pallet transporter used to move funds between chains.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use codec::{Decode, Encode};
use domain_runtime_primitives::{MultiAccountId, TryConvertBack};
use frame_support::ensure;
use frame_support::traits::Currency;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_domains::DomainId;
use sp_messenger::messages::ChainId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, Get};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

/// Location that either sends or receives transfers between chains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Location {
    /// Unique identity of chain.
    pub chain_id: ChainId,
    /// Unique account on chain.
    pub account_id: MultiAccountId,
}

/// Transfer of funds from one chain to another.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Transfer<Balance> {
    /// Amount being transferred between entities.
    pub amount: Balance,
    /// Sender location of the transfer.
    pub sender: Location,
    /// Receiver location of the transfer.
    pub receiver: Location,
}

/// Balance type used by the pallet.
pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type MessageIdOf<T> = <<T as Config>::Sender as sp_messenger::endpoint::Sender<
    <T as frame_system::Config>::AccountId,
>>::MessageId;

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use crate::{BalanceOf, Location, MessageIdOf, MultiAccountId, Transfer, TryConvertBack};
    use codec::{Decode, Encode};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
    use frame_support::weights::Weight;
    use frame_system::pallet_prelude::*;
    use sp_domains::{DomainId, Transfers};
    use sp_messenger::endpoint::{
        Endpoint, EndpointHandler as EndpointHandlerT, EndpointId, EndpointRequest,
        EndpointResponse, Sender,
    };
    use sp_messenger::messages::ChainId;
    use sp_runtime::traits::{CheckedAdd, Convert};
    use sp_std::vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Gets the chain_id of the current execution environment.
        type SelfChainId: Get<ChainId>;

        /// Gets the endpoint_id of this pallet in a given execution environment.
        type SelfEndpointId: Get<EndpointId>;

        /// Currency used by this pallet.
        type Currency: Currency<Self::AccountId>;

        /// Sender used to transfer funds.
        type Sender: Sender<Self::AccountId>;

        /// MultiAccountID <> T::AccountId converter.
        type AccountIdConverter: TryConvertBack<Self::AccountId, MultiAccountId>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    /// Pallet transporter to move funds between chains.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// All the outgoing transfers on this execution environment.
    #[pallet::storage]
    #[pallet::getter(fn outgoing_transfers)]
    pub(super) type OutgoingTransfers<T: Config> = StorageDoubleMap<
        _,
        Identity,
        ChainId,
        Identity,
        MessageIdOf<T>,
        Transfer<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Domain balances.
    #[pallet::storage]
    #[pallet::getter(fn domain_balances)]
    pub(super) type DomainBalances<T: Config> =
        StorageMap<_, Identity, DomainId, BalanceOf<T>, ValueQuery>;

    /// A temporary storage that tracks total transfers from this chain.
    /// Clears on on_initialize for every block.
    #[pallet::storage]
    #[pallet::getter(fn chain_transfers)]
    pub(super) type ChainTransfers<T: Config> =
        StorageValue<_, Transfers<BalanceOf<T>>, ValueQuery>;

    /// Events emitted by pallet-transporter.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when there is a new outgoing transfer.
        OutgoingTransferInitiated {
            /// Destination chain the transfer is bound to.
            chain_id: ChainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
        },

        /// Emits when a given outgoing transfer was failed on dst_chain.
        OutgoingTransferFailed {
            /// Destination chain the transfer is bound to.
            chain_id: ChainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
            /// Error from dst_chain endpoint.
            err: DispatchError,
        },

        /// Emits when a given outgoing transfer was successful.
        OutgoingTransferSuccessful {
            /// Destination chain the transfer is bound to.
            chain_id: ChainId,
            /// Id of the transfer.
            message_id: MessageIdOf<T>,
        },

        /// Emits when a given incoming transfer was successfully processed.
        IncomingTransferSuccessful {
            /// Source chain the transfer is coming from.
            chain_id: ChainId,
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
        /// Emits when the incoming message is not bound to this chain.
        UnexpectedMessage,
        /// Emits when the account id type is invalid.
        InvalidAccountId,
        /// Emits when from_chain do not have enough funds to finalize the transfer.
        LowBalanceOnDomain,
        /// Emits when the transfer tracking was called from non-consensus chain
        NonConsensusChain,
        /// Emits when balance overflow
        BalanceOverflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Initiates transfer of funds from account on src_chain to account on dst_chain.
        /// Funds are burned on src_chain first and are minted on dst_chain using Messenger.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::transfer())]
        pub fn transfer(
            origin: OriginFor<T>,
            dst_location: Location,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // burn transfer amount
            let _imbalance = T::Currency::withdraw(
                &sender,
                amount,
                WithdrawReasons::TRANSFER,
                ExistenceRequirement::AllowDeath,
            )
            .map_err(|_| Error::<T>::LowBalance)?;

            // initiate transfer
            let dst_chain_id = dst_location.chain_id;
            let transfer = Transfer {
                amount,
                sender: Location {
                    chain_id: T::SelfChainId::get(),
                    account_id: T::AccountIdConverter::convert(sender.clone()),
                },
                receiver: dst_location,
            };

            // send message
            let message_id = T::Sender::send_message(
                &sender,
                dst_chain_id,
                EndpointRequest {
                    src_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
                    // destination endpoint must be transporter with same id
                    dst_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
                    payload: transfer.encode(),
                },
            )?;

            OutgoingTransfers::<T>::insert(dst_chain_id, message_id, transfer);
            Self::deposit_event(Event::<T>::OutgoingTransferInitiated {
                chain_id: dst_chain_id,
                message_id,
            });

            ChainTransfers::<T>::try_mutate(|transfers| {
                transfers.transfers_out = transfers
                    .transfers_out
                    .checked_add(&amount)
                    .ok_or(Error::<T>::BalanceOverflow)?;
                Ok::<(), Error<T>>(())
            })?;

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            ChainTransfers::<T>::kill();
            T::DbWeight::get().writes(1)
        }
    }

    /// Endpoint handler implementation for pallet transporter.
    #[derive(Debug)]
    pub struct EndpointHandler<T>(pub PhantomData<T>);

    impl<T: Config> EndpointHandlerT<MessageIdOf<T>> for EndpointHandler<T> {
        fn message(
            &self,
            src_chain_id: ChainId,
            message_id: MessageIdOf<T>,
            req: EndpointRequest,
        ) -> EndpointResponse {
            // ensure message is not from the self
            ensure!(
                T::SelfChainId::get() != src_chain_id,
                Error::<T>::InvalidTransferRequest
            );

            // check the endpoint id
            ensure!(
                req.dst_endpoint == Endpoint::Id(T::SelfEndpointId::get()),
                Error::<T>::UnexpectedMessage
            );

            // decode payload and process message
            let req = match Transfer::decode(&mut req.payload.as_slice()) {
                Ok(req) => req,
                Err(_) => return Err(Error::<T>::InvalidPayload.into()),
            };

            // mint the funds to dst_account
            let account_id = T::AccountIdConverter::try_convert_back(req.receiver.account_id)
                .ok_or(Error::<T>::InvalidAccountId)?;

            let _imbalance = T::Currency::deposit_creating(&account_id, req.amount);

            ChainTransfers::<T>::try_mutate(|transfers| {
                transfers.transfers_in = transfers
                    .transfers_in
                    .checked_add(&req.amount)
                    .ok_or(Error::<T>::BalanceOverflow)?;
                Ok::<(), Error<T>>(())
            })?;

            frame_system::Pallet::<T>::deposit_event(Into::<<T as Config>::RuntimeEvent>::into(
                Event::<T>::IncomingTransferSuccessful {
                    chain_id: src_chain_id,
                    message_id,
                },
            ));
            Ok(vec![])
        }

        fn message_weight(&self) -> Weight {
            T::WeightInfo::message()
        }

        fn message_response(
            &self,
            dst_chain_id: ChainId,
            message_id: MessageIdOf<T>,
            req: EndpointRequest,
            resp: EndpointResponse,
        ) -> DispatchResult {
            // ensure request is valid
            let transfer = OutgoingTransfers::<T>::take(dst_chain_id, message_id)
                .ok_or(Error::<T>::MissingTransferRequest)?;
            ensure!(
                req.payload == transfer.encode(),
                Error::<T>::InvalidTransferRequest
            );

            // process response
            match resp {
                Ok(_) => {
                    // transfer is successful
                    frame_system::Pallet::<T>::deposit_event(
                        Into::<<T as Config>::RuntimeEvent>::into(
                            Event::<T>::OutgoingTransferSuccessful {
                                chain_id: dst_chain_id,
                                message_id,
                            },
                        ),
                    );
                }
                Err(err) => {
                    // transfer failed
                    // revert burned funds
                    let account_id =
                        T::AccountIdConverter::try_convert_back(transfer.sender.account_id)
                            .ok_or(Error::<T>::InvalidAccountId)?;
                    let _imbalance = T::Currency::deposit_creating(&account_id, transfer.amount);

                    ChainTransfers::<T>::try_mutate(|transfers| {
                        transfers.transfers_in = transfers
                            .transfers_in
                            .checked_add(&transfer.amount)
                            .ok_or(Error::<T>::BalanceOverflow)?;
                        Ok::<(), Error<T>>(())
                    })?;

                    frame_system::Pallet::<T>::deposit_event(
                        Into::<<T as Config>::RuntimeEvent>::into(
                            Event::<T>::OutgoingTransferFailed {
                                chain_id: dst_chain_id,
                                message_id,
                                err,
                            },
                        ),
                    );
                }
            }

            Ok(())
        }

        fn message_response_weight(&self) -> Weight {
            T::WeightInfo::message_response()
        }
    }
}

impl<T: Config> sp_domains::DomainsTransfersTracker<BalanceOf<T>> for Pallet<T> {
    type Error = Error<T>;

    fn balance_on_domain(domain_id: DomainId) -> Result<BalanceOf<T>, Self::Error> {
        ensure!(
            T::SelfChainId::get().is_consensus_chain(),
            Error::NonConsensusChain
        );

        Ok(DomainBalances::<T>::get(domain_id))
    }

    fn transfer_in(domain_id: DomainId, amount: BalanceOf<T>) -> Result<(), Self::Error> {
        ensure!(
            T::SelfChainId::get().is_consensus_chain(),
            Error::NonConsensusChain
        );

        DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
            *current_balance = current_balance
                .checked_add(&amount)
                .ok_or(Error::BalanceOverflow)?;
            Ok(())
        })
    }

    fn transfer_out(domain_id: DomainId, amount: BalanceOf<T>) -> Result<(), Self::Error> {
        ensure!(
            T::SelfChainId::get().is_consensus_chain(),
            Error::NonConsensusChain
        );

        DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
            *current_balance = current_balance
                .checked_sub(&amount)
                .ok_or(Error::LowBalanceOnDomain)?;
            Ok(())
        })
    }
}
