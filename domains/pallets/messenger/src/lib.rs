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
#![feature(let_chains, variant_count)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod fees;
mod messages;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

#[cfg(not(feature = "std"))]
extern crate alloc;

use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, InspectHold};
use frame_system::pallet_prelude::BlockNumberFor;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;
use sp_domains::{DomainAllowlistUpdates, DomainId};
use sp_messenger::messages::{
    ChainId, ChannelId, CrossDomainMessage, FeeModel, Message, MessageId, Nonce,
};
use sp_runtime::traits::{Extrinsic, Hash};
use sp_runtime::DispatchError;

/// State of a channel.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ChannelState {
    /// Channel between chains is initiated but do not yet send or receive messages in this state.
    #[default]
    Initiated,
    /// Channel is open and can send and receive messages.
    Open,
    /// Channel is closed and do not send or receive messages.
    Closed,
}

/// Channel describes a bridge to exchange messages between two chains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Channel<Balance, AccountId> {
    /// Channel identifier.
    pub(crate) channel_id: ChannelId,
    /// State of the channel.
    pub(crate) state: ChannelState,
    /// Next inbox nonce.
    pub(crate) next_inbox_nonce: Nonce,
    /// Next outbox nonce.
    pub(crate) next_outbox_nonce: Nonce,
    /// Latest outbox message nonce for which response was received from dst_chain.
    pub(crate) latest_response_received_message_nonce: Option<Nonce>,
    /// Maximum outgoing non-delivered messages.
    pub(crate) max_outgoing_messages: u32,
    /// Fee model for this channel between the chains.
    pub(crate) fee: FeeModel<Balance>,
    /// Owner of the channel
    /// Owner maybe None if the channel was initiated on the other chain.
    pub(crate) maybe_owner: Option<AccountId>,
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
    <<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;
pub(crate) type FungibleHoldId<T> =
    <<T as Config>::Currency as InspectHold<<T as frame_system::Config>::AccountId>>::Reason;

/// A validated relay message.
#[derive(Debug)]
pub struct ValidatedRelayMessage<Balance> {
    msg: Message<Balance>,
    next_nonce: Nonce,
    should_init_channel: bool,
}

/// Parameter to update chain allow list.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub enum ChainAllowlistUpdate {
    Add(ChainId),
    Remove(ChainId),
}

impl ChainAllowlistUpdate {
    fn chain_id(&self) -> ChainId {
        match self {
            ChainAllowlistUpdate::Add(chain_id) => *chain_id,
            ChainAllowlistUpdate::Remove(chain_id) => *chain_id,
        }
    }
}

/// Channel can be closed either by Channel owner or Sudo
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub(crate) enum CloseChannelBy<AccountId> {
    Owner(AccountId),
    Sudo,
}

/// Hold identifier trait for messenger specific balance holds
pub trait HoldIdentifier<T: Config> {
    fn messenger_channel(dst_chain_id: ChainId, channel_id: ChannelId) -> FungibleHoldId<T>;
}

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use crate::{
        BalanceOf, ChainAllowlistUpdate, Channel, ChannelId, ChannelState, CloseChannelBy,
        FeeModel, HoldIdentifier, Nonce, OutboxMessageResult, StateRootOf, ValidatedRelayMessage,
        U256,
    };
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use frame_support::ensure;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::fungible::{Inspect, InspectHold, Mutate, MutateHold};
    use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
    use frame_support::weights::WeightToFee;
    use frame_system::pallet_prelude::*;
    use sp_core::storage::StorageKey;
    use sp_domains::proof_provider_and_verifier::{StorageProofVerifier, VerificationError};
    use sp_domains::{DomainAllowlistUpdates, DomainId, DomainOwner};
    use sp_messenger::endpoint::{Endpoint, EndpointHandler, EndpointRequest, Sender};
    use sp_messenger::messages::{
        ChainId, CrossDomainMessage, InitiateChannelParams, Message, MessageId, MessageKey,
        MessageWeightTag, Payload, ProtocolMessageRequest, RequestResponse, VersionedPayload,
    };
    use sp_messenger::{
        InherentError, InherentType, OnXDMRewards, StorageKeys, INHERENT_IDENTIFIER,
    };
    use sp_runtime::ArithmeticError;
    use sp_subspace_mmr::MmrProofVerifier;
    #[cfg(feature = "std")]
    use std::collections::BTreeSet;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Gets the chain_id that is treated as src_chain_id for outgoing messages.
        type SelfChainId: Get<ChainId>;
        /// function to fetch endpoint response handler by Endpoint.
        fn get_endpoint_handler(endpoint: &Endpoint)
            -> Option<Box<dyn EndpointHandler<MessageId>>>;
        /// Currency type pallet uses for fees and deposits.
        type Currency: Mutate<Self::AccountId>
            + InspectHold<Self::AccountId>
            + MutateHold<Self::AccountId>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
        /// Weight to fee conversion.
        type WeightToFee: WeightToFee<Balance = BalanceOf<Self>>;
        /// Handle XDM rewards.
        type OnXDMRewards: OnXDMRewards<BalanceOf<Self>>;
        /// Hash type of MMR
        type MmrHash: Parameter + Member + Default + Clone;
        /// MMR proof verifier
        type MmrProofVerifier: MmrProofVerifier<
            Self::MmrHash,
            BlockNumberFor<Self>,
            StateRootOf<Self>,
        >;
        /// Storage key provider.
        type StorageKeys: StorageKeys;
        /// Domain owner provider.
        type DomainOwner: DomainOwner<Self::AccountId>;
        /// A variation of the Identifier used for holding the funds used for Messenger
        type HoldIdentifier: HoldIdentifier<Self>;
        /// Channel reserve fee to open a channel.
        #[pallet::constant]
        type ChannelReserveFee: Get<BalanceOf<Self>>;
    }

    /// Pallet messenger used to communicate between chains and other blockchains.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the next channel id for a foreign chain.
    #[pallet::storage]
    #[pallet::getter(fn next_channel_id)]
    pub(super) type NextChannelId<T: Config> =
        StorageMap<_, Identity, ChainId, ChannelId, ValueQuery>;

    /// Stores channel config between two chains.
    /// Key points to the foreign chain wrt own chain's storage name space
    #[pallet::storage]
    #[pallet::getter(fn channels)]
    pub(super) type Channels<T: Config> = StorageDoubleMap<
        _,
        Identity,
        ChainId,
        Identity,
        ChannelId,
        Channel<BalanceOf<T>, T::AccountId>,
        OptionQuery,
    >;

    /// A temporary storage for storing decoded inbox message between `pre_dispatch_relay_message`
    /// and `relay_message`.
    #[pallet::storage]
    #[pallet::getter(fn inbox)]
    pub(super) type Inbox<T: Config> = StorageValue<_, Message<BalanceOf<T>>, OptionQuery>;

    /// A temporary storage of fees for executing an inbox message.
    /// The storage is cleared when the acknowledgement of inbox response is received
    /// from the src_chain.
    #[pallet::storage]
    #[pallet::getter(fn inbox_fees)]
    pub(super) type InboxFee<T: Config> =
        StorageMap<_, Identity, (ChainId, MessageId), BalanceOf<T>, OptionQuery>;

    /// A temporary storage of fees for executing an outbox message and its response from dst_chain.
    /// The storage is cleared when src_chain receives the response from dst_chain.
    #[pallet::storage]
    #[pallet::getter(fn outbox_fees)]
    pub(super) type OutboxFee<T: Config> =
        StorageMap<_, Identity, (ChainId, MessageId), BalanceOf<T>, OptionQuery>;

    /// Stores the message responses of the incoming processed responses.
    /// Used by the dst_chains to verify the message response.
    #[pallet::storage]
    #[pallet::getter(fn inbox_responses)]
    pub(super) type InboxResponses<T: Config> = CountedStorageMap<
        _,
        Identity,
        (ChainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Stores the outgoing messages that are awaiting message responses from the dst_chain.
    /// Messages are processed in the outbox nonce order of chain's channel.
    #[pallet::storage]
    #[pallet::getter(fn outbox)]
    pub(super) type Outbox<T: Config> = CountedStorageMap<
        _,
        Identity,
        (ChainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    /// A temporary storage for storing decoded outbox response message between `pre_dispatch_relay_message_response`
    /// and `relay_message_response`.
    #[pallet::storage]
    #[pallet::getter(fn outbox_responses)]
    pub(super) type OutboxResponses<T: Config> =
        StorageValue<_, Message<BalanceOf<T>>, OptionQuery>;

    /// A temporary storage to store all the messages to be relayed in this block.
    /// Will be cleared on the initialization on next block.
    #[pallet::storage]
    #[pallet::getter(fn block_messages)]
    pub(super) type BlockMessages<T: Config> =
        StorageValue<_, crate::messages::BlockMessages, OptionQuery>;

    /// An allowlist of chains that can open channel with this chain.
    #[pallet::storage]
    #[pallet::getter(fn chain_allowlist)]
    pub(super) type ChainAllowlist<T: Config> = StorageValue<_, BTreeSet<ChainId>, ValueQuery>;

    /// A storage to store any allowlist updates to domain. The updates will be cleared in the next block
    /// once the previous block has a domain bundle, but a empty value should be left because in the invalid
    /// extrinsic root fraud proof the prover need to generate a proof-of-empty-value for the domain.
    #[pallet::storage]
    #[pallet::getter(fn domain_chain_allowlist_updates)]
    pub(super) type DomainChainAllowlistUpdate<T: Config> =
        StorageMap<_, Identity, DomainId, DomainAllowlistUpdates, OptionQuery>;

    /// `pallet-messenger` events
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when a channel between two chains is initiated.
        ChannelInitiated {
            /// Foreign chain id this channel connects to.
            chain_id: ChainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two chains is closed.
        ChannelClosed {
            /// Foreign chain id this channel connects to.
            chain_id: ChainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a channel between two chain is open.
        ChannelOpen {
            /// Foreign chain id this channel connects to.
            chain_id: ChainId,
            /// Channel ID of the said channel.
            channel_id: ChannelId,
        },

        /// Emits when a new message is added to the outbox.
        OutboxMessage {
            chain_id: ChainId,
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits when a message response is available for Outbox message.
        OutboxMessageResponse {
            /// Destination chain ID.
            chain_id: ChainId,
            /// Channel Is
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits outbox message result.
        OutboxMessageResult {
            chain_id: ChainId,
            channel_id: ChannelId,
            nonce: Nonce,
            result: OutboxMessageResult,
        },

        /// Emits when a new inbox message is validated and added to Inbox.
        InboxMessage {
            chain_id: ChainId,
            channel_id: ChannelId,
            nonce: Nonce,
        },

        /// Emits when a message response is available for Inbox message.
        InboxMessageResponse {
            /// Destination chain ID.
            chain_id: ChainId,
            /// Channel Is
            channel_id: ChannelId,
            nonce: Nonce,
        },
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::relay_message { msg: xdm } => {
                    let ValidatedRelayMessage {
                        msg,
                        next_nonce,
                        should_init_channel,
                    } = Self::validate_relay_message(xdm)?;
                    if msg.nonce != next_nonce {
                        log::error!(
                            "Unexpected message nonce, channel next nonce {:?}, msg nonce {:?}",
                            next_nonce,
                            msg.nonce,
                        );
                        return Err(if msg.nonce < next_nonce {
                            InvalidTransaction::Stale
                        } else {
                            InvalidTransaction::Future
                        }
                        .into());
                    }
                    Self::pre_dispatch_relay_message(msg, should_init_channel)
                }
                Call::relay_message_response { msg: xdm } => {
                    let (msg, next_nonce) = Self::validate_relay_message_response(xdm)?;
                    if msg.nonce != next_nonce {
                        log::error!(
                            "Unexpected message response nonce, channel next nonce {:?}, msg nonce {:?}",
                            next_nonce,
                            msg.nonce,
                        );
                        return Err(if msg.nonce < next_nonce {
                            InvalidTransaction::Stale
                        } else {
                            InvalidTransaction::Future
                        }
                        .into());
                    }
                    Self::pre_dispatch_relay_message_response(msg)
                }
                // always accept inherent extrinsic
                Call::update_domain_allowlist { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        /// Validate unsigned call to this module.
        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::relay_message { msg: xdm } => {
                    let ValidatedRelayMessage {
                        msg,
                        next_nonce,
                        should_init_channel: _,
                    } = Self::validate_relay_message(xdm)?;

                    let mut valid_tx_builder = ValidTransaction::with_tag_prefix("MessengerInbox");
                    // Only add the requires tag if the msg nonce is in future
                    if msg.nonce > next_nonce {
                        valid_tx_builder = valid_tx_builder.and_requires((
                            msg.dst_chain_id,
                            msg.channel_id,
                            msg.nonce - Nonce::one(),
                        ));
                    };
                    valid_tx_builder
                        // XDM have a bit higher priority than normal extrinsic but must less than
                        // fraud proof
                        .priority(1)
                        .longevity(TransactionLongevity::MAX)
                        .and_provides((msg.dst_chain_id, msg.channel_id, msg.nonce))
                        .propagate(true)
                        .build()
                }
                Call::relay_message_response { msg: xdm } => {
                    let (msg, next_nonce) = Self::validate_relay_message_response(xdm)?;

                    let mut valid_tx_builder =
                        ValidTransaction::with_tag_prefix("MessengerOutboxResponse");
                    // Only add the requires tag if the msg nonce is in future
                    if msg.nonce > next_nonce {
                        valid_tx_builder = valid_tx_builder.and_requires((
                            msg.dst_chain_id,
                            msg.channel_id,
                            msg.nonce - Nonce::one(),
                        ));
                    };
                    valid_tx_builder
                        // XDM have a bit higher priority than normal extrinsic but must less than
                        // fraud proof
                        .priority(1)
                        .longevity(TransactionLongevity::MAX)
                        .and_provides((msg.dst_chain_id, msg.channel_id, msg.nonce))
                        .propagate(true)
                        .build()
                }
                _ => InvalidTransaction::Call.into(),
            }
        }
    }

    /// `pallet-messenger` errors
    #[pallet::error]
    pub enum Error<T> {
        /// Emits when the chain is neither consensus not chain.
        InvalidChain,

        /// Emits when there is no channel for a given Channel ID.
        MissingChannel,

        /// Emits when the said channel is not in an open state.
        InvalidChannelState,

        /// Emits when there are no open channels for a chain
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

        /// Emits when there is mismatch between the message's weight tag and the message's
        /// actual processing path
        WeightTagNotMatch,

        /// Emits when the there is balance overflow.
        BalanceOverflow,

        /// Invalid allowed chain.
        InvalidAllowedChain,

        /// Operation not allowed.
        OperationNotAllowed,

        /// Account is not a Domain owner.
        NotDomainOwner,

        /// Chain not allowed to open channel
        ChainNotAllowed,

        /// Not enough balance to do the operation
        InsufficientBalance,

        /// Failed to hold balance
        BalanceHold,

        /// Not a channel owner
        ChannelOwner,

        /// Failed to unlock the balance
        BalanceUnlock,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            BlockMessages::<T>::kill();
            T::DbWeight::get().writes(1)
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A new Channel is initiated with a foreign chain.
        /// Next Channel ID is used to assign the new channel.
        /// Channel is set to initiated and do not accept or receive any messages.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::initiate_channel())]
        pub fn initiate_channel(
            origin: OriginFor<T>,
            dst_chain_id: ChainId,
            params: InitiateChannelParams<BalanceOf<T>>,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            // initiate the channel config
            let channel_id = Self::do_init_channel(dst_chain_id, params, Some(owner.clone()))?;

            // reserve channel open fees
            let hold_id = T::HoldIdentifier::messenger_channel(dst_chain_id, channel_id);
            let amount = T::ChannelReserveFee::get();

            // ensure there is enough free balance to lock
            ensure!(
                T::Currency::reducible_balance(&owner, Preservation::Preserve, Fortitude::Polite)
                    >= amount,
                Error::<T>::InsufficientBalance
            );
            T::Currency::hold(&hold_id, &owner, amount).map_err(|_| Error::<T>::BalanceHold)?;

            // send message to dst_chain
            Self::new_outbox_message(
                T::SelfChainId::get(),
                dst_chain_id,
                channel_id,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelOpen(params),
                ))),
            )?;

            Ok(())
        }

        /// An open channel is closed with a foreign chain.
        /// Channel is set to Closed and do not accept or receive any messages.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::close_channel())]
        pub fn close_channel(
            origin: OriginFor<T>,
            chain_id: ChainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            // either owner can close the channel
            // or sudo can close the channel
            let close_channel_by = match ensure_signed_or_root(origin)? {
                Some(owner) => CloseChannelBy::Owner(owner),
                None => CloseChannelBy::Sudo,
            };
            Self::do_close_channel(chain_id, channel_id, close_channel_by)?;
            Self::new_outbox_message(
                T::SelfChainId::get(),
                chain_id,
                channel_id,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelClose,
                ))),
            )?;

            Ok(())
        }

        /// Receives an Inbox message that needs to be validated and processed.
        #[pallet::call_index(2)]
        #[pallet::weight((T::WeightInfo::relay_message().saturating_add(Pallet::< T >::message_weight(& msg.weight_tag)), Pays::No))]
        pub fn relay_message(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            let inbox_msg = Inbox::<T>::take().ok_or(Error::<T>::MissingMessage)?;
            Self::process_inbox_messages(inbox_msg, msg.weight_tag)?;
            Ok(())
        }

        /// Receives a response from the dst_chain for a message in Outbox.
        #[pallet::call_index(3)]
        #[pallet::weight((T::WeightInfo::relay_message_response().saturating_add(Pallet::< T >::message_weight(& msg.weight_tag)), Pays::No))]
        pub fn relay_message_response(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            let outbox_resp_msg = OutboxResponses::<T>::take().ok_or(Error::<T>::MissingMessage)?;
            Self::process_outbox_message_responses(outbox_resp_msg, msg.weight_tag)?;
            Ok(())
        }

        /// A call to update consensus chain allow list.
        #[pallet::call_index(4)]
        #[pallet::weight(<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1))]
        pub fn update_consensus_chain_allowlist(
            origin: OriginFor<T>,
            update: ChainAllowlistUpdate,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                T::SelfChainId::get().is_consensus_chain(),
                Error::<T>::OperationNotAllowed
            );

            ensure!(
                update.chain_id() != T::SelfChainId::get(),
                Error::<T>::InvalidAllowedChain
            );

            ChainAllowlist::<T>::mutate(|list| match update {
                ChainAllowlistUpdate::Add(chain_id) => list.insert(chain_id),
                ChainAllowlistUpdate::Remove(chain_id) => list.remove(&chain_id),
            });
            Ok(())
        }

        /// A call to initiate chain allowlist update on domains
        #[pallet::call_index(5)]
        #[pallet::weight(<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1))]
        pub fn initiate_domain_update_chain_allowlist(
            origin: OriginFor<T>,
            domain_id: DomainId,
            update: ChainAllowlistUpdate,
        ) -> DispatchResult {
            let domain_owner = ensure_signed(origin)?;
            ensure!(
                T::DomainOwner::is_domain_owner(domain_id, domain_owner),
                Error::<T>::NotDomainOwner
            );

            ensure!(
                T::SelfChainId::get().is_consensus_chain(),
                Error::<T>::OperationNotAllowed
            );

            if let Some(dst_domain_id) = update.chain_id().maybe_domain_chain() {
                ensure!(dst_domain_id != domain_id, Error::<T>::InvalidAllowedChain);
            }

            DomainChainAllowlistUpdate::<T>::mutate(domain_id, |maybe_domain_updates| {
                let mut domain_updates = maybe_domain_updates.take().unwrap_or_default();
                match update {
                    ChainAllowlistUpdate::Add(chain_id) => {
                        domain_updates.remove_chains.remove(&chain_id);
                        domain_updates.allow_chains.insert(chain_id);
                    }
                    ChainAllowlistUpdate::Remove(chain_id) => {
                        domain_updates.allow_chains.remove(&chain_id);
                        domain_updates.remove_chains.insert(chain_id);
                    }
                }

                *maybe_domain_updates = Some(domain_updates)
            });
            Ok(())
        }

        /// An inherent call to update allowlist for domain.
        #[pallet::call_index(6)]
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Mandatory))]
        pub fn update_domain_allowlist(
            origin: OriginFor<T>,
            updates: DomainAllowlistUpdates,
        ) -> DispatchResult {
            ensure_none(origin)?;
            ensure!(
                !T::SelfChainId::get().is_consensus_chain(),
                Error::<T>::OperationNotAllowed
            );

            let DomainAllowlistUpdates {
                allow_chains,
                remove_chains,
            } = updates;

            ChainAllowlist::<T>::mutate(|list| {
                // remove chains from set
                // TODO: should we close the existing channels to the following chains?
                remove_chains.into_iter().for_each(|chain_id| {
                    list.remove(&chain_id);
                });

                // add new chains
                allow_chains.into_iter().for_each(|chain_id| {
                    list.insert(chain_id);
                });
            });

            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Messenger inherent data not correctly encoded")
                .expect("Messenger inherent data must be provided");

            inherent_data
                .maybe_updates
                .map(|updates| Call::update_domain_allowlist { updates })
        }

        fn is_inherent_required(data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Messenger inherent data not correctly encoded")
                .expect("Messenger inherent data must be provided");

            Ok(if inherent_data.maybe_updates.is_none() {
                None
            } else {
                Some(InherentError::MissingAllowlistUpdates)
            })
        }

        fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Messenger inherent data not correctly encoded")
                .expect("Messenger inherent data must be provided");

            if let Some(provided_updates) = inherent_data.maybe_updates {
                if let Call::update_domain_allowlist { updates } = call {
                    if updates != &provided_updates {
                        return Err(InherentError::IncorrectAllowlistUpdates);
                    }
                }
            } else {
                return Err(InherentError::MissingAllowlistUpdates);
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::update_domain_allowlist { .. })
        }
    }

    impl<T: Config> Sender<T::AccountId> for Pallet<T> {
        type MessageId = MessageId;

        fn send_message(
            sender: &T::AccountId,
            dst_chain_id: ChainId,
            req: EndpointRequest,
        ) -> Result<Self::MessageId, DispatchError> {
            let (channel_id, fee_model) =
                Self::get_open_channel_for_chain(dst_chain_id).ok_or(Error::<T>::NoOpenChannel)?;

            let src_endpoint = req.src_endpoint.clone();
            let nonce = Self::new_outbox_message(
                T::SelfChainId::get(),
                dst_chain_id,
                channel_id,
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(req))),
            )?;

            // ensure fees are paid by the sender
            Self::collect_fees_for_message(
                sender,
                (dst_chain_id, (channel_id, nonce)),
                &fee_model,
                &src_endpoint,
            )?;

            Ok((channel_id, nonce))
        }

        /// Only used in benchmark to prepare for a upcoming `send_message` call to
        /// ensure it will succeed.
        #[cfg(feature = "runtime-benchmarks")]
        fn unchecked_open_channel(dst_chain_id: ChainId) -> Result<(), DispatchError> {
            let fee_model = FeeModel {
                relay_fee: Default::default(),
            };
            let init_params = InitiateChannelParams {
                max_outgoing_messages: 100,
                fee_model,
            };
            let channel_id = Self::do_init_channel(dst_chain_id, init_params, None)?;
            Self::do_open_channel(dst_chain_id, channel_id)?;
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        // Get the weight according the given weight tag
        fn message_weight(weight_tag: &MessageWeightTag) -> Weight {
            match weight_tag {
                MessageWeightTag::ProtocolChannelOpen => T::WeightInfo::do_open_channel(),
                MessageWeightTag::ProtocolChannelClose => T::WeightInfo::do_close_channel(),
                MessageWeightTag::EndpointRequest(endpoint) => {
                    T::get_endpoint_handler(endpoint)
                        .map(|endpoint_handler| endpoint_handler.message_weight())
                        // If there is no endpoint handler the request won't be handled thus return zero weight
                        .unwrap_or(Weight::zero())
                }
                MessageWeightTag::EndpointResponse(endpoint) => {
                    T::get_endpoint_handler(endpoint)
                        .map(|endpoint_handler| endpoint_handler.message_response_weight())
                        // If there is no endpoint handler the request won't be handled thus return zero weight
                        .unwrap_or(Weight::zero())
                }
                MessageWeightTag::None => Weight::zero(),
            }
        }

        /// Returns the last open channel for a given chain.
        pub fn get_open_channel_for_chain(
            dst_chain_id: ChainId,
        ) -> Option<(ChannelId, FeeModel<BalanceOf<T>>)> {
            let mut next_channel_id = NextChannelId::<T>::get(dst_chain_id);

            // loop through channels in descending order until open channel is found.
            // we always prefer latest opened channel.
            while let Some(channel_id) = next_channel_id.checked_sub(ChannelId::one()) {
                if let Some(channel) = Channels::<T>::get(dst_chain_id, channel_id) {
                    if channel.state == ChannelState::Open {
                        return Some((channel_id, channel.fee));
                    }
                }

                next_channel_id = channel_id
            }

            None
        }

        /// Opens an initiated channel.
        pub(crate) fn do_open_channel(chain_id: ChainId, channel_id: ChannelId) -> DispatchResult {
            Channels::<T>::try_mutate(chain_id, channel_id, |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;

                ensure!(
                    channel.state == ChannelState::Initiated,
                    Error::<T>::InvalidChannelState
                );

                channel.state = ChannelState::Open;
                Ok(())
            })?;

            Self::deposit_event(Event::ChannelOpen {
                chain_id,
                channel_id,
            });

            Ok(())
        }

        pub(crate) fn do_close_channel(
            chain_id: ChainId,
            channel_id: ChannelId,
            close_channel_by: CloseChannelBy<T::AccountId>,
        ) -> DispatchResult {
            Channels::<T>::try_mutate(chain_id, channel_id, |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;

                ensure!(
                    channel.state == ChannelState::Open,
                    Error::<T>::InvalidChannelState
                );

                if let CloseChannelBy::Owner(owner) = close_channel_by {
                    ensure!(channel.maybe_owner == Some(owner), Error::<T>::ChannelOwner);
                }

                if let Some(owner) = &channel.maybe_owner {
                    let hold_id = T::HoldIdentifier::messenger_channel(chain_id, channel_id);
                    let locked_amount = T::Currency::balance_on_hold(&hold_id, owner);
                    T::Currency::release(&hold_id, owner, locked_amount, Precision::Exact)
                        .map_err(|_| Error::<T>::BalanceUnlock)?;
                }

                channel.state = ChannelState::Closed;
                Ok(())
            })?;

            Self::deposit_event(Event::ChannelClosed {
                chain_id,
                channel_id,
            });

            Ok(())
        }

        pub(crate) fn do_init_channel(
            dst_chain_id: ChainId,
            init_params: InitiateChannelParams<BalanceOf<T>>,
            maybe_owner: Option<T::AccountId>,
        ) -> Result<ChannelId, DispatchError> {
            ensure!(
                T::SelfChainId::get() != dst_chain_id,
                Error::<T>::InvalidChain,
            );

            let chain_allowlist = ChainAllowlist::<T>::get();
            ensure!(
                chain_allowlist.contains(&dst_chain_id),
                Error::<T>::ChainNotAllowed
            );

            let channel_id = NextChannelId::<T>::get(dst_chain_id);
            let next_channel_id = channel_id
                .checked_add(U256::one())
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;

            Channels::<T>::insert(
                dst_chain_id,
                channel_id,
                Channel {
                    channel_id,
                    state: ChannelState::Initiated,
                    next_inbox_nonce: Default::default(),
                    next_outbox_nonce: Default::default(),
                    latest_response_received_message_nonce: Default::default(),
                    max_outgoing_messages: init_params.max_outgoing_messages,
                    fee: init_params.fee_model,
                    maybe_owner,
                },
            );

            NextChannelId::<T>::insert(dst_chain_id, next_channel_id);
            Self::deposit_event(Event::ChannelInitiated {
                chain_id: dst_chain_id,
                channel_id,
            });
            Ok(channel_id)
        }

        pub fn validate_relay_message(
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> Result<ValidatedRelayMessage<BalanceOf<T>>, TransactionValidityError> {
            let mut should_init_channel = false;
            let next_nonce = match Channels::<T>::get(xdm.src_chain_id, xdm.channel_id) {
                None => {
                    // if there is no channel config, this must the Channel open request.
                    // so nonce is 0
                    should_init_channel = true;
                    log::debug!(
                        "Initiating new channel: {:?} to chain: {:?}",
                        xdm.channel_id,
                        xdm.src_chain_id
                    );
                    Nonce::zero()
                }
                Some(channel) => {
                    // Ensure channel is ready to receive messages
                    log::debug!(
                        "Message to channel: {:?} from chain: {:?}",
                        xdm.channel_id,
                        xdm.src_chain_id
                    );
                    ensure!(
                        channel.state == ChannelState::Open,
                        InvalidTransaction::Call
                    );
                    channel.next_inbox_nonce
                }
            };

            // derive the key as stored on the src_chain.
            let key = StorageKey(
                T::StorageKeys::outbox_storage_key(
                    xdm.src_chain_id,
                    (T::SelfChainId::get(), xdm.channel_id, xdm.nonce),
                )
                .ok_or(UnknownTransaction::CannotLookup)?,
            );

            // verify and decode message
            let msg = Self::do_verify_xdm(next_nonce, key, xdm)?;

            // if there is no channel config, this must be the Channel open request
            if should_init_channel {
                match msg.payload {
                    VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                        ProtocolMessageRequest::ChannelOpen(_),
                    ))) => {}
                    _ => {
                        log::error!("Unexpected call instead of channel open request: {:?}", msg,);
                        return Err(InvalidTransaction::Call.into());
                    }
                }
            }

            Ok(ValidatedRelayMessage {
                msg,
                next_nonce,
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
                    // channel is being opened without an owner since this is a relay message
                    // from other chain
                    Self::do_init_channel(msg.src_chain_id, params, None).map_err(|err| {
                        log::error!(
                            "Error initiating channel: {:?} with chain: {:?}: {:?}",
                            msg.channel_id,
                            msg.src_chain_id,
                            err
                        );
                        InvalidTransaction::Call
                    })?;
                } else {
                    log::error!("Unexpected call instead of channel open request: {:?}", msg,);
                    return Err(InvalidTransaction::Call.into());
                }
            }

            Self::deposit_event(Event::InboxMessage {
                chain_id: msg.src_chain_id,
                channel_id: msg.channel_id,
                nonce: msg.nonce,
            });
            Inbox::<T>::put(msg);
            Ok(())
        }

        pub fn validate_relay_message_response(
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> Result<(Message<BalanceOf<T>>, Nonce), TransactionValidityError> {
            // channel should be open and message should be present in outbox
            let next_nonce = match Channels::<T>::get(xdm.src_chain_id, xdm.channel_id) {
                // unknown channel. return
                None => {
                    log::error!("Unexpected inbox message response: {:?}", xdm,);
                    return Err(InvalidTransaction::Call.into());
                }
                Some(channel) => match channel.latest_response_received_message_nonce {
                    None => Some(Nonce::zero()),
                    Some(last_nonce) => last_nonce.checked_add(Nonce::one()),
                },
            }
            .ok_or(TransactionValidityError::Invalid(InvalidTransaction::Call))?;

            // derive the key as stored on the src_chain.
            let key = StorageKey(
                T::StorageKeys::inbox_responses_storage_key(
                    xdm.src_chain_id,
                    (T::SelfChainId::get(), xdm.channel_id, xdm.nonce),
                )
                .ok_or(UnknownTransaction::CannotLookup)?,
            );

            // verify, decode, and store the message
            let msg = Self::do_verify_xdm(next_nonce, key, xdm)?;

            Ok((msg, next_nonce))
        }

        pub(crate) fn pre_dispatch_relay_message_response(
            msg: Message<BalanceOf<T>>,
        ) -> Result<(), TransactionValidityError> {
            Self::deposit_event(Event::OutboxMessageResponse {
                chain_id: msg.src_chain_id,
                channel_id: msg.channel_id,
                nonce: msg.nonce,
            });

            OutboxResponses::<T>::put(msg);
            Ok(())
        }

        pub(crate) fn do_verify_xdm(
            next_nonce: Nonce,
            storage_key: StorageKey,
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> Result<Message<BalanceOf<T>>, TransactionValidityError> {
            // channel should be either already be created or match the next channelId for chain.
            let next_channel_id = NextChannelId::<T>::get(xdm.src_chain_id);
            ensure!(xdm.channel_id <= next_channel_id, InvalidTransaction::Call);

            // verify nonce
            // nonce should be either be next or in future.
            ensure!(xdm.nonce >= next_nonce, InvalidTransaction::Call);

            let state_root =
                T::MmrProofVerifier::verify_proof_and_extract_leaf(xdm.proof.consensus_mmr_proof())
                    .ok_or(InvalidTransaction::BadProof)?
                    .state_root();

            // if the message is from domain, verify domain confirmation proof
            let state_root = if let Some(domain_proof) = xdm.proof.domain_proof().clone()
                && let Some(domain_id) = xdm.src_chain_id.maybe_domain_chain()
            {
                let confirmed_domain_block_storage_key =
                    T::StorageKeys::confirmed_domain_block_storage_key(domain_id)
                        .ok_or(UnknownTransaction::CannotLookup)?;

                StorageProofVerifier::<T::Hashing>::get_decoded_value::<
                    sp_domains::ConfirmedDomainBlock<BlockNumberFor<T>, T::Hash>,
                >(
                    &state_root,
                    domain_proof,
                    StorageKey(confirmed_domain_block_storage_key),
                )
                .map_err(|err| {
                    log::error!(
                        target: "runtime::messenger",
                        "Failed to verify storage proof for confirmed Domain block: {:?}",
                        err
                    );
                    TransactionValidityError::Invalid(InvalidTransaction::BadProof)
                })?
                .state_root
            } else {
                state_root
            };

            // verify and decode the message
            let msg =
                StorageProofVerifier::<T::Hashing>::get_decoded_value::<Message<BalanceOf<T>>>(
                    &state_root,
                    xdm.proof.message_proof(),
                    storage_key,
                )
                .map_err(|err| {
                    log::error!(
                        target: "runtime::messenger",
                        "Failed to verify storage proof for message: {:?}",
                        err
                    );
                    TransactionValidityError::Invalid(InvalidTransaction::BadProof)
                })?;

            Ok(msg)
        }

        pub fn outbox_storage_key(message_key: MessageKey) -> Vec<u8> {
            Outbox::<T>::hashed_key_for(message_key)
        }

        pub fn inbox_response_storage_key(message_key: MessageKey) -> Vec<u8> {
            InboxResponses::<T>::hashed_key_for(message_key)
        }

        pub fn domain_chains_allowlist_update(
            domain_id: DomainId,
        ) -> Option<DomainAllowlistUpdates> {
            DomainChainAllowlistUpdate::<T>::get(domain_id).filter(|updates| !updates.is_empty())
        }

        pub fn domain_allow_list_update_storage_key(domain_id: DomainId) -> Vec<u8> {
            DomainChainAllowlistUpdate::<T>::hashed_key_for(domain_id)
        }
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    pub fn outbox_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
    ) -> Option<T::Extrinsic> {
        let call = Call::relay_message { msg };
        T::Extrinsic::new(call.into(), None)
    }

    pub fn inbox_response_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
    ) -> Option<T::Extrinsic> {
        let call = Call::relay_message_response { msg };
        T::Extrinsic::new(call.into(), None)
    }

    /// Returns true if the outbox message has not received the response yet.
    pub fn should_relay_outbox_message(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
        Outbox::<T>::contains_key((dst_chain_id, msg_id.0, msg_id.1))
    }

    /// Returns true if the inbox message response has not received acknowledgement yet.
    pub fn should_relay_inbox_message_response(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
        InboxResponses::<T>::contains_key((dst_chain_id, msg_id.0, msg_id.1))
    }
}

impl<T: Config> sp_domains::DomainBundleSubmitted for Pallet<T> {
    fn domain_bundle_submitted(domain_id: DomainId) {
        // NOTE: clear the updates leave an empty value but does not delete the value for the
        // domain completely because in the invalid extrinsic root fraud proof the prover need
        // to generate a proof-of-empty-value for the domain.
        DomainChainAllowlistUpdate::<T>::mutate(domain_id, |maybe_updates| {
            if let Some(ref mut updates) = maybe_updates {
                updates.clear();
            }
        });
    }
}

impl<T: Config> sp_domains::OnDomainInstantiated for Pallet<T> {
    fn on_domain_instantiated(domain_id: DomainId) {
        DomainChainAllowlistUpdate::<T>::insert(domain_id, DomainAllowlistUpdates::default());
    }
}
