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

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

#[cfg(not(feature = "std"))]
extern crate alloc;

use codec::{Decode, Encode};
use domain_runtime_primitives::{MultiAccountId, TryConvertBack};
use frame_support::dispatch::DispatchResult;
use frame_support::ensure;
use frame_support::traits::Currency;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_domains::{DomainId, DomainsTransfersTracker, Transfers};
use sp_messenger::endpoint::EndpointResponse;
use sp_messenger::messages::ChainId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, Get};
use sp_std::vec;

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
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use codec::{Decode, Encode};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
    use frame_support::weights::Weight;
    use frame_system::pallet_prelude::*;
    use sp_domains::{DomainId, DomainsTransfersTracker, Transfers};
    use sp_messenger::endpoint::{
        Endpoint, EndpointHandler as EndpointHandlerT, EndpointId, EndpointRequest,
        EndpointResponse, Sender,
    };
    use sp_messenger::messages::ChainId;
    use sp_runtime::traits::Convert;
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

    /// Storage to track unconfirmed transfers between different chains.
    #[pallet::storage]
    #[pallet::getter(fn unconfirmed_transfers)]
    pub(super) type UnconfirmedTransfers<T: Config> =
        StorageDoubleMap<_, Identity, ChainId, Identity, ChainId, BalanceOf<T>, ValueQuery>;

    /// Storage to track cancelled transfers between different chains.
    #[pallet::storage]
    #[pallet::getter(fn cancelled_transfers)]
    pub(super) type CancelledTransfers<T: Config> =
        StorageDoubleMap<_, Identity, ChainId, Identity, ChainId, BalanceOf<T>, ValueQuery>;

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
        /// Emits when balance underflow
        BalanceUnderflow,
        /// Emits when domain balance is already initialized
        DomainBalanceAlreadyInitialized,
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

            // if this is consensus chain, then note the transfer
            // else add transfer to storage to send through ER to consensus chain
            if T::SelfChainId::get().is_consensus_chain() {
                Self::note_transfer(T::SelfChainId::get(), dst_chain_id, amount)?
            } else {
                ChainTransfers::<T>::try_mutate(|transfers| {
                    Self::update_transfer_out(transfers, dst_chain_id, amount)
                })?;
            }

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // NOTE: set the `ChainTransfers` to an empty value instead of removing the value completely
            // so we can generate a storage proof to prove the empty value, which is required by the fraud
            // proof.
            ChainTransfers::<T>::set(Default::default());
            T::DbWeight::get().writes(1)
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn transfers_storage_key() -> Vec<u8> {
            use frame_support::storage::generator::StorageValue;
            ChainTransfers::<T>::storage_value_final_key().to_vec()
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

            let amount = req.amount;
            let response = Pallet::<T>::finalize_transfer(src_chain_id, message_id, req);
            if response.is_err() {
                // if this is consensus chain, then reject the transfer
                // else update the Transfers storage with rejected transfer
                if T::SelfChainId::get().is_consensus_chain() {
                    Pallet::<T>::reject_transfer(src_chain_id, T::SelfChainId::get(), amount)?;
                } else {
                    ChainTransfers::<T>::try_mutate(|transfers| {
                        Pallet::<T>::update_transfer_rejected(transfers, src_chain_id, amount)
                    })?;
                }
            }

            response
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

                    // if this is consensus chain, then revert the transfer
                    // else update the Transfers storage with reverted transfer
                    if T::SelfChainId::get().is_consensus_chain() {
                        Pallet::<T>::claim_rejected_transfer(
                            T::SelfChainId::get(),
                            dst_chain_id,
                            transfer.amount,
                        )?;
                    } else {
                        ChainTransfers::<T>::try_mutate(|transfers| {
                            Pallet::<T>::update_transfer_revert(
                                transfers,
                                dst_chain_id,
                                transfer.amount,
                            )
                        })?;
                    }

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

    fn initialize_domain_balance(
        domain_id: DomainId,
        amount: BalanceOf<T>,
    ) -> Result<(), Self::Error> {
        Self::ensure_consensus_chain()?;

        ensure!(
            !DomainBalances::<T>::contains_key(domain_id),
            Error::DomainBalanceAlreadyInitialized
        );

        DomainBalances::<T>::set(domain_id, amount);
        Ok(())
    }

    fn note_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> Result<(), Self::Error> {
        Self::ensure_consensus_chain()?;

        if let Some(domain_id) = from_chain_id.maybe_domain_chain() {
            DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
                *current_balance = current_balance
                    .checked_sub(&amount)
                    .ok_or(Error::LowBalanceOnDomain)?;
                Ok(())
            })?;
        }

        UnconfirmedTransfers::<T>::try_mutate(from_chain_id, to_chain_id, |total_amount| {
            *total_amount = total_amount
                .checked_add(&amount)
                .ok_or(Error::BalanceOverflow)?;
            Ok(())
        })?;

        Ok(())
    }

    fn confirm_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> Result<(), Self::Error> {
        Self::ensure_consensus_chain()?;
        UnconfirmedTransfers::<T>::try_mutate(from_chain_id, to_chain_id, |total_amount| {
            *total_amount = total_amount
                .checked_sub(&amount)
                .ok_or(Error::BalanceUnderflow)?;
            Ok(())
        })?;

        if let Some(domain_id) = to_chain_id.maybe_domain_chain() {
            DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
                *current_balance = current_balance
                    .checked_add(&amount)
                    .ok_or(Error::BalanceOverflow)?;
                Ok(())
            })?;
        }

        Ok(())
    }

    fn claim_rejected_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> Result<(), Self::Error> {
        Self::ensure_consensus_chain()?;
        CancelledTransfers::<T>::try_mutate(from_chain_id, to_chain_id, |total_amount| {
            *total_amount = total_amount
                .checked_sub(&amount)
                .ok_or(Error::BalanceUnderflow)?;
            Ok(())
        })?;

        if let Some(domain_id) = from_chain_id.maybe_domain_chain() {
            DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
                *current_balance = current_balance
                    .checked_add(&amount)
                    .ok_or(Error::BalanceOverflow)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    fn reject_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> Result<(), Self::Error> {
        Self::ensure_consensus_chain()?;
        UnconfirmedTransfers::<T>::try_mutate(from_chain_id, to_chain_id, |total_amount| {
            *total_amount = total_amount
                .checked_sub(&amount)
                .ok_or(Error::BalanceUnderflow)?;
            Ok(())
        })?;

        CancelledTransfers::<T>::try_mutate(from_chain_id, to_chain_id, |total_amount| {
            *total_amount = total_amount
                .checked_add(&amount)
                .ok_or(Error::BalanceOverflow)?;
            Ok(())
        })?;
        Ok(())
    }

    fn reduce_domain_balance(domain_id: DomainId, amount: BalanceOf<T>) -> Result<(), Self::Error> {
        DomainBalances::<T>::try_mutate(domain_id, |current_balance| {
            *current_balance = current_balance
                .checked_sub(&amount)
                .ok_or(Error::LowBalanceOnDomain)?;
            Ok(())
        })
    }
}

impl<T: Config> Pallet<T> {
    fn ensure_consensus_chain() -> Result<(), Error<T>> {
        ensure!(
            T::SelfChainId::get().is_consensus_chain(),
            Error::NonConsensusChain
        );

        Ok(())
    }

    fn finalize_transfer(
        src_chain_id: ChainId,
        message_id: MessageIdOf<T>,
        req: Transfer<BalanceOf<T>>,
    ) -> EndpointResponse {
        // mint the funds to dst_account
        let account_id = T::AccountIdConverter::try_convert_back(req.receiver.account_id)
            .ok_or(Error::<T>::InvalidAccountId)?;

        let _imbalance = T::Currency::deposit_creating(&account_id, req.amount);

        // if this is consensus chain, then confirm the transfer
        // else add transfer to storage to send through ER to consensus chain
        if T::SelfChainId::get().is_consensus_chain() {
            Pallet::<T>::confirm_transfer(src_chain_id, T::SelfChainId::get(), req.amount)?
        } else {
            ChainTransfers::<T>::try_mutate(|transfers| {
                Pallet::<T>::update_transfer_in(transfers, src_chain_id, req.amount)
            })?;
        }

        frame_system::Pallet::<T>::deposit_event(Into::<<T as Config>::RuntimeEvent>::into(
            Event::<T>::IncomingTransferSuccessful {
                chain_id: src_chain_id,
                message_id,
            },
        ));
        Ok(vec![])
    }

    fn update_transfer_out(
        transfers: &mut Transfers<BalanceOf<T>>,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> DispatchResult {
        let total_transfer =
            if let Some(current_transfer_amount) = transfers.transfers_out.get(&to_chain_id) {
                current_transfer_amount
                    .checked_add(&amount)
                    .ok_or(Error::<T>::BalanceOverflow)?
            } else {
                amount
            };
        transfers.transfers_out.insert(to_chain_id, total_transfer);
        Ok(())
    }

    fn update_transfer_in(
        transfers: &mut Transfers<BalanceOf<T>>,
        from_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> DispatchResult {
        let total_transfer =
            if let Some(current_transfer_amount) = transfers.transfers_in.get(&from_chain_id) {
                current_transfer_amount
                    .checked_add(&amount)
                    .ok_or(Error::<T>::BalanceOverflow)?
            } else {
                amount
            };
        transfers.transfers_in.insert(from_chain_id, total_transfer);
        Ok(())
    }

    fn update_transfer_revert(
        transfers: &mut Transfers<BalanceOf<T>>,
        to_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> DispatchResult {
        let total_transfer = if let Some(current_transfer_amount) =
            transfers.rejected_transfers_claimed.get(&to_chain_id)
        {
            current_transfer_amount
                .checked_add(&amount)
                .ok_or(Error::<T>::BalanceOverflow)?
        } else {
            amount
        };
        transfers
            .rejected_transfers_claimed
            .insert(to_chain_id, total_transfer);
        Ok(())
    }

    fn update_transfer_rejected(
        transfers: &mut Transfers<BalanceOf<T>>,
        from_chain_id: ChainId,
        amount: BalanceOf<T>,
    ) -> DispatchResult {
        let total_transfer = if let Some(current_transfer_amount) =
            transfers.transfers_rejected.get(&from_chain_id)
        {
            current_transfer_amount
                .checked_add(&amount)
                .ok_or(Error::<T>::BalanceOverflow)?
        } else {
            amount
        };
        transfers
            .transfers_rejected
            .insert(from_chain_id, total_transfer);
        Ok(())
    }
}
