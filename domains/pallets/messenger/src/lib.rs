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
#![warn(rust_2018_idioms)]
#![feature(variant_count, if_let_guard)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod extensions;
mod fees;
mod messages;
pub mod migrations;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

#[cfg(not(feature = "std"))]
extern crate alloc;

use frame_support::__private::RuntimeDebug;
use frame_support::pallet_prelude::{EnsureOrigin, MaxEncodedLen, StorageVersion};
use frame_support::traits::fungible::{Inspect, InspectHold};
use frame_system::pallet_prelude::BlockNumberFor;
pub use pallet::*;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::U256;
use sp_domains::{DomainAllowlistUpdates, DomainId};
use sp_messenger::MAX_FUTURE_ALLOWED_NONCES;
use sp_messenger::messages::{
    ChainId, Channel, ChannelId, ChannelState, CrossDomainMessage, Message, Nonce,
};
use sp_runtime::DispatchError;
use sp_runtime::traits::Hash;
use subspace_runtime_primitives::CreateUnsigned;
pub use weights::WeightInfo;

/// Transaction validity for a given validated XDM extrinsic.
/// If the extrinsic is not included in the bundle, extrinsic is removed from the TxPool.
const XDM_TRANSACTION_LONGEVITY: u64 = 10;

/// XDM verification errors.
pub(crate) mod verification_errors {
    // When updating these error codes, check for clashes between:
    // <https://github.com/autonomys/subspace/blob/main/domains/primitives/runtime/src/lib.rs#L85-L88>
    // <https://github.com/autonomys/subspace/blob/main/crates/sp-domains-fraud-proof/src/lib.rs#L49-L64>
    pub(crate) const INVALID_NONCE: u8 = 201;
    // Custom error code when a messenger nonce overflows.
    pub(crate) const XDM_NONCE_OVERFLOW: u8 = 202;
    // This error code was previously 200, but that clashed with ERR_BALANCE_OVERFLOW.
    pub(crate) const INVALID_CHANNEL: u8 = 203;
    pub(crate) const IN_FUTURE_NONCE: u8 = 204;
    // Failed to update next nonce during the pre_dispatch
    pub(crate) const NEXT_NONCE_UPDATE: u8 = 205;
}

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub enum OutboxMessageResult {
    /// Message response handler returned Ok.
    Ok,
    /// Message response handler failed with Err.
    Err(DispatchError),
}

/// Custom origin for validated unsigned extrinsics.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum RawOrigin {
    ValidatedUnsigned,
}

/// Ensure the messenger origin.
pub struct EnsureMessengerOrigin;
impl<O: Into<Result<RawOrigin, O>> + From<RawOrigin>> EnsureOrigin<O> for EnsureMessengerOrigin {
    type Success = ();

    fn try_origin(o: O) -> Result<Self::Success, O> {
        o.into().map(|o| match o {
            RawOrigin::ValidatedUnsigned => (),
        })
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn try_successful_origin() -> Result<O, ()> {
        Ok(O::from(RawOrigin::ValidatedUnsigned))
    }
}

pub(crate) type StateRootOf<T> = <<T as frame_system::Config>::Hashing as Hash>::Output;
pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;
pub(crate) type FungibleHoldId<T> =
    <<T as Config>::Currency as InspectHold<<T as frame_system::Config>::AccountId>>::Reason;

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

#[derive(Debug, Encode, Decode, TypeInfo)]
pub struct ValidatedRelayMessage<T: Config> {
    pub message: Message<BalanceOf<T>>,
    pub should_init_channel: bool,
    pub next_nonce: Nonce,
}

/// Channel can be closed either by Channel owner or Sudo
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub(crate) enum CloseChannelBy<AccountId> {
    Owner(AccountId),
    Sudo,
}

/// Hold identifier trait for messenger specific balance holds
pub trait HoldIdentifier<T: Config> {
    fn messenger_channel() -> FungibleHoldId<T>;
}

/// The current storage version.
const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

#[frame_support::pallet]
mod pallet {
    pub use crate::extensions::weights::WeightInfo as ExtensionWeightInfo;
    use crate::weights::WeightInfo;
    use crate::{
        BalanceOf, ChainAllowlistUpdate, Channel, ChannelId, ChannelState, CloseChannelBy,
        HoldIdentifier, Nonce, OutboxMessageResult, RawOrigin, STORAGE_VERSION, StateRootOf, U256,
        ValidatedRelayMessage,
    };
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use core::cmp::Ordering;
    use frame_support::ensure;
    use frame_support::pallet_prelude::*;
    use frame_support::storage::with_storage_layer;
    use frame_support::traits::fungible::{Balanced, Inspect, InspectHold, Mutate, MutateHold};
    use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
    use frame_support::weights::WeightToFee;
    use frame_system::pallet_prelude::*;
    use sp_core::storage::StorageKey;
    use sp_domains::proof_provider_and_verifier::{StorageProofVerifier, VerificationError};
    use sp_domains::{DomainAllowlistUpdates, DomainId, DomainOwner};
    use sp_messenger::endpoint::{
        Endpoint, EndpointHandler, EndpointRequest, EndpointRequestWithCollectedFee, Sender,
    };
    use sp_messenger::messages::{
        ChainId, ChannelOpenParamsV1, ChannelStateWithNonce, CrossDomainMessage, Message,
        MessageId, MessageKey, MessageWeightTag, PayloadV1, ProtocolMessageRequest,
        RequestResponse, VersionedPayload,
    };
    use sp_messenger::{
        ChannelNonce, DomainRegistration, INHERENT_IDENTIFIER, InherentError, InherentType,
        NoteChainTransfer, OnXDMRewards, StorageKeys,
    };
    use sp_runtime::traits::Zero;
    use sp_runtime::{ArithmeticError, Perbill, Saturating};
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
            + MutateHold<Self::AccountId>
            + Balanced<Self::AccountId>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
        /// Weight to fee conversion.
        type WeightToFee: WeightToFee<Balance = BalanceOf<Self>>;
        /// Adjusted Weight to fee conversion.
        /// This includes the TransactionPayment Multiper at the time of fee deduction.
        type AdjustedWeightToFee: WeightToFee<Balance = BalanceOf<Self>>;
        /// Fee Multiper for XDM
        /// Final fee calculated will fee_multiplier * adjusted_weight_to_fee.
        #[pallet::constant]
        type FeeMultiplier: Get<u32>;
        /// Handle XDM rewards.
        type OnXDMRewards: OnXDMRewards<BalanceOf<Self>>;
        /// Hash type of MMR
        type MmrHash: Parameter + Member + Default + Clone;
        /// MMR proof verifier
        type MmrProofVerifier: MmrProofVerifier<Self::MmrHash, BlockNumberFor<Self>, StateRootOf<Self>>;
        /// Storage key provider.
        type StorageKeys: StorageKeys;
        /// Domain owner provider.
        type DomainOwner: DomainOwner<Self::AccountId>;
        /// A variation of the Identifier used for holding the funds used for Messenger
        type HoldIdentifier: HoldIdentifier<Self>;
        /// Channel reserve fee to open a channel.
        #[pallet::constant]
        type ChannelReserveFee: Get<BalanceOf<Self>>;
        /// Portion of Channel reserve taken by the protocol
        /// if the channel is in init state and is requested to be closed.
        #[pallet::constant]
        type ChannelInitReservePortion: Get<Perbill>;
        /// Type to check if a given domain is registered on Consensus chain.
        type DomainRegistration: DomainRegistration;
        /// Maximum outgoing messages from a given channel
        #[pallet::constant]
        type MaxOutgoingMessages: Get<u32>;
        /// Origin for messenger call.
        type MessengerOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = ()>;
        /// Helper to note cross chain XDM fee transfer
        type NoteChainTransfer: NoteChainTransfer<BalanceOf<Self>>;
        /// Weight info for extensions
        type ExtensionWeightInfo: ExtensionWeightInfo;
    }

    /// Pallet messenger used to communicate between chains and other blockchains.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    #[pallet::storage_version(STORAGE_VERSION)]
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
    pub(super) type InboxResponses<T: Config> =
        StorageMap<_, Identity, (ChainId, ChannelId, Nonce), Message<BalanceOf<T>>, OptionQuery>;

    /// Stores the outgoing messages that are awaiting message responses from the dst_chain.
    /// Messages are processed in the outbox nonce order of chain's channel.
    #[pallet::storage]
    #[pallet::getter(fn outbox)]
    pub(super) type Outbox<T: Config> =
        StorageMap<_, Identity, (ChainId, ChannelId, Nonce), Message<BalanceOf<T>>, OptionQuery>;

    /// Stores the outgoing messages count that are awaiting message responses from the dst_chain.
    #[pallet::storage]
    #[pallet::getter(fn outbox_message_count)]
    pub(super) type OutboxMessageCount<T: Config> =
        StorageMap<_, Identity, (ChainId, ChannelId), u32, ValueQuery>;

    /// A temporary storage for storing decoded outbox response message between `pre_dispatch_relay_message_response`
    /// and `relay_message_response`.
    #[pallet::storage]
    #[pallet::getter(fn outbox_responses)]
    pub(super) type OutboxResponses<T: Config> =
        StorageValue<_, Message<BalanceOf<T>>, OptionQuery>;

    /// Storage to store the weight tags for all the outbox messages.
    #[pallet::storage]
    #[pallet::getter(fn outbox_message_weight_tags)]
    pub(super) type OutboxMessageWeightTags<T: Config> =
        StorageMap<_, Identity, (ChainId, MessageId), MessageWeightTag>;

    /// Storage to store the weight tags for all the inbox responses messages.
    #[pallet::storage]
    #[pallet::getter(fn inbox_response_message_weight_tags)]
    pub(super) type InboxResponseMessageWeightTags<T: Config> =
        StorageMap<_, Identity, (ChainId, MessageId), MessageWeightTag>;

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

    /// Temporary storage to store the updated channels between this chain and other chain.
    /// Storage is cleared on block initialization.
    #[pallet::storage]
    pub(super) type UpdatedChannels<T: Config> =
        StorageValue<_, BTreeSet<(ChainId, ChannelId)>, ValueQuery>;

    /// Storage to track the inbox fees that is hold on the chain before distributing.
    ///
    /// NOTE: The inbox fees is accounted to the chain's total issuance but not hold on any account
    /// because an account with balance below ED will be reaped, in this way, we can manage small
    /// inbox fee that less than ED easier. It also means whenever `InboxFeesOnHold` is increase/decrease
    /// we need to increase/decrease the total issuance manually.
    #[pallet::storage]
    pub(super) type InboxFeesOnHold<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Storage to track the outbox fees that is hold on the chain before distributing.
    ///
    /// NOTE: The outbox fees is accounted to the chain's total issuance but not hold on any account
    /// because an account with balance below ED will be reaped, in this way, we can manage small
    /// outbox fee that less than ED easier. It also means whenever `OutboxFeesOnHold` is increase/decrease
    /// we need to increase/decrease the total issuance manually.
    #[pallet::storage]
    pub(super) type OutboxFeesOnHold<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// `InboxFeesOnHoldStartAt` and `OutboxFeesOnHoldStartAt` are used to record when the inbox/outbox fee
    /// is started to be tracked in `InboxFeesOnHold` and `OutboxFeesOnHold`. This is needed as migration on
    /// Taurus.
    ///
    /// TODO: remove once the XDM V1 format is enabled on Taurus and all the untracked pending XDM is processed.
    #[pallet::storage]
    pub(super) type InboxFeesOnHoldStartAt<T: Config> =
        StorageMap<_, Identity, ChannelId, Nonce, OptionQuery>;
    #[pallet::storage]
    pub(super) type OutboxFeesOnHoldStartAt<T: Config> =
        StorageMap<_, Identity, ChannelId, Nonce, OptionQuery>;

    #[pallet::origin]
    pub type Origin = RawOrigin;

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

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            UpdatedChannels::<T>::take();
            T::DbWeight::get().reads_writes(0, 1)
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                // always accept inherent extrinsic
                Call::update_domain_allowlist { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        /// Validate unsigned call to this module.
        fn validate_unsigned(
            _source: TransactionSource,
            _call: &Self::Call,
        ) -> TransactionValidity {
            InvalidTransaction::Call.into()
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

        /// Emits when the there is balance underflow.
        BalanceUnderflow,

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

        /// Invalid channel reserve fee
        InvalidChannelReserveFee,

        /// Invalid max outgoing messages
        InvalidMaxOutgoingMessages,

        /// Message count overflow
        MessageCountOverflow,

        /// Message count underflow
        MessageCountUnderflow,

        /// Failed to note transfer in
        FailedToNoteTransferIn,

        /// Failed to note transfer out
        FailedToNoteTransferOut,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A new Channel is initiated with a foreign chain.
        /// Next Channel ID is used to assign the new channel.
        /// Channel is set to initiated and do not accept or receive any messages.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::initiate_channel())]
        pub fn initiate_channel(origin: OriginFor<T>, dst_chain_id: ChainId) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            // reserve channel open fees
            let hold_id = T::HoldIdentifier::messenger_channel();
            let amount = T::ChannelReserveFee::get();

            // ensure there is enough free balance to lock
            ensure!(
                T::Currency::reducible_balance(&owner, Preservation::Preserve, Fortitude::Polite)
                    >= amount,
                Error::<T>::InsufficientBalance
            );
            T::Currency::hold(&hold_id, &owner, amount).map_err(|_| Error::<T>::BalanceHold)?;

            // initiate the channel config
            let channel_open_params = ChannelOpenParamsV1 {
                max_outgoing_messages: T::MaxOutgoingMessages::get(),
            };
            let channel_id = Self::do_init_channel(
                dst_chain_id,
                channel_open_params,
                Some(owner.clone()),
                true,
                amount,
            )?;

            let payload = VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelOpen(ChannelOpenParamsV1 {
                    max_outgoing_messages: channel_open_params.max_outgoing_messages,
                }),
            )));

            // send message to dst_chain
            Self::new_outbox_message(T::SelfChainId::get(), dst_chain_id, channel_id, payload)?;

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

            let payload = VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelClose,
            )));

            Self::new_outbox_message(T::SelfChainId::get(), chain_id, channel_id, payload)?;

            Ok(())
        }

        /// Receives an Inbox message that needs to be validated and processed.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::relay_message().saturating_add(Pallet::< T >::message_weight(& msg.weight_tag)))]
        pub fn relay_message(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> DispatchResult {
            T::MessengerOrigin::ensure_origin(origin)?;
            let inbox_msg = Inbox::<T>::take().ok_or(Error::<T>::MissingMessage)?;
            Self::process_inbox_messages(inbox_msg, msg.weight_tag)?;
            Ok(())
        }

        /// Receives a response from the dst_chain for a message in Outbox.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::relay_message_response().saturating_add(Pallet::< T >::message_weight(& msg.weight_tag)))]
        pub fn relay_message_response(
            origin: OriginFor<T>,
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> DispatchResult {
            T::MessengerOrigin::ensure_origin(origin)?;
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

            if let ChainAllowlistUpdate::Add(ChainId::Domain(domain_id)) = update {
                ensure!(
                    T::DomainRegistration::is_domain_registered(domain_id),
                    Error::<T>::InvalidChain
                );
            }

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

            if let ChainAllowlistUpdate::Add(ChainId::Domain(domain_id)) = update {
                ensure!(
                    T::DomainRegistration::is_domain_registered(domain_id),
                    Error::<T>::InvalidChain
                );
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
                if let Call::update_domain_allowlist { updates } = call
                    && updates != &provided_updates
                {
                    return Err(InherentError::IncorrectAllowlistUpdates);
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
            let allowed_chains = ChainAllowlist::<T>::get();
            ensure!(
                allowed_chains.contains(&dst_chain_id),
                Error::<T>::ChainNotAllowed
            );

            let channel_id =
                Self::get_open_channel_for_chain(dst_chain_id).ok_or(Error::<T>::NoOpenChannel)?;

            let src_endpoint = req.src_endpoint.clone();

            let message_id = {
                // collect the fees from the sender
                let collected_fee = Self::collect_fees_for_message_v1(sender, &src_endpoint)?;
                let src_chain_fee = collected_fee.src_chain_fee;
                let dst_chain_fee = collected_fee.dst_chain_fee;
                let nonce = Self::new_outbox_message(
                    T::SelfChainId::get(),
                    dst_chain_id,
                    channel_id,
                    VersionedPayload::V1(PayloadV1::Endpoint(RequestResponse::Request(
                        EndpointRequestWithCollectedFee { req, collected_fee },
                    ))),
                )?;

                // store src_chain, this chain, fee to OutboxFee
                let message_id = (channel_id, nonce);
                Self::store_outbox_fee(dst_chain_id, message_id, src_chain_fee, dst_chain_fee)?;
                message_id
            };

            Ok(message_id)
        }

        /// Only used in benchmark to prepare for a upcoming `send_message` call to
        /// ensure it will succeed.
        #[cfg(feature = "runtime-benchmarks")]
        fn unchecked_open_channel(dst_chain_id: ChainId) -> Result<(), DispatchError> {
            let init_params = ChannelOpenParamsV1 {
                max_outgoing_messages: 100,
            };
            ChainAllowlist::<T>::mutate(|list| list.insert(dst_chain_id));
            let channel_id =
                Self::do_init_channel(dst_chain_id, init_params, None, true, Zero::zero())?;
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
        pub fn get_open_channel_for_chain(dst_chain_id: ChainId) -> Option<ChannelId> {
            let mut next_channel_id = NextChannelId::<T>::get(dst_chain_id);

            // loop through channels in descending order until open channel is found.
            // we always prefer latest opened channel.
            while let Some(channel_id) = next_channel_id.checked_sub(ChannelId::one()) {
                let message_count = OutboxMessageCount::<T>::get((dst_chain_id, channel_id));
                if let Some(channel) = Channels::<T>::get(dst_chain_id, channel_id)
                    && channel.state == ChannelState::Open
                    && message_count < channel.max_outgoing_messages
                {
                    return Some(channel_id);
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
                    channel.state != ChannelState::Closed,
                    Error::<T>::InvalidChannelState
                );

                if let CloseChannelBy::Owner(owner) = close_channel_by {
                    ensure!(channel.maybe_owner == Some(owner), Error::<T>::ChannelOwner);
                }

                if let Some(owner) = &channel.maybe_owner {
                    let hold_id = T::HoldIdentifier::messenger_channel();
                    let locked_amount = channel.channel_reserve_fee;
                    let (amount_to_release, maybe_amount_to_burn) = {
                        if channel.state == ChannelState::Open {
                            (locked_amount, None)
                        } else {
                            let protocol_fee = T::ChannelInitReservePortion::get() * locked_amount;
                            let release_amount = locked_amount.saturating_sub(protocol_fee);
                            (release_amount, Some(protocol_fee))
                        }
                    };

                    with_storage_layer(|| {
                        if let Some(protocol_fee) = maybe_amount_to_burn {
                            T::Currency::burn_held(
                                &hold_id,
                                owner,
                                protocol_fee,
                                Precision::Exact,
                                Fortitude::Force,
                            )?;
                            T::OnXDMRewards::on_chain_protocol_fees(chain_id, protocol_fee);
                        }

                        T::Currency::release(&hold_id, owner, amount_to_release, Precision::Exact)
                            .map_err(|_| Error::<T>::BalanceUnlock)?;

                        Ok::<(), DispatchError>(())
                    })?;
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
            init_params: ChannelOpenParamsV1,
            maybe_owner: Option<T::AccountId>,
            check_allowlist: bool,
            channel_reserve_fee: BalanceOf<T>,
        ) -> Result<ChannelId, DispatchError> {
            ensure!(
                T::SelfChainId::get() != dst_chain_id,
                Error::<T>::InvalidChain,
            );

            // ensure max outgoing messages is at least 1
            ensure!(
                init_params.max_outgoing_messages >= 1u32,
                Error::<T>::InvalidMaxOutgoingMessages
            );

            // If the channel owner is in this chain then the channel reserve fee
            // must not be empty
            ensure!(
                maybe_owner.is_none() || !channel_reserve_fee.is_zero(),
                Error::<T>::InvalidChannelReserveFee,
            );

            if check_allowlist {
                let chain_allowlist = ChainAllowlist::<T>::get();
                ensure!(
                    chain_allowlist.contains(&dst_chain_id),
                    Error::<T>::ChainNotAllowed
                );
            }

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
                    maybe_owner,
                    channel_reserve_fee,
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
            consensus_state_root: StateRootOf<T>,
        ) -> Result<ValidatedRelayMessage<T>, TransactionValidityError> {
            let (next_nonce, maybe_channel) =
                match Channels::<T>::get(xdm.src_chain_id, xdm.channel_id) {
                    None => {
                        // if there is no channel config, this must the Channel open request.
                        // so nonce is 0
                        log::debug!(
                            "Initiating new channel: {:?} to chain: {:?}",
                            xdm.channel_id,
                            xdm.src_chain_id
                        );
                        (Nonce::zero(), None)
                    }
                    Some(channel) => {
                        log::debug!(
                            "Message to channel: {:?} from chain: {:?}",
                            xdm.channel_id,
                            xdm.src_chain_id
                        );
                        (channel.next_inbox_nonce, Some(channel))
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
            let msg = Self::do_verify_xdm(next_nonce, key, consensus_state_root, xdm)?;

            let is_valid_call = match &msg.payload {
                VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(req))) => {
                    match req {
                        // channel open should ensure there is no Channel present already
                        ProtocolMessageRequest::ChannelOpen(_) => maybe_channel.is_none(),
                        // we allow channel close only if it is init or open state
                        ProtocolMessageRequest::ChannelClose => {
                            if let Some(ref channel) = maybe_channel {
                                !(channel.state == ChannelState::Closed)
                            } else {
                                false
                            }
                        }
                    }
                }
                // endpoint request messages are only allowed when
                // channel is open, or
                // channel is closed. Channel can be closed by dst_chain simultaneously
                // while src_chain already sent a message. We allow the message but return an
                // error in the response so that src_chain can revert any necessary actions
                VersionedPayload::V1(PayloadV1::Endpoint(RequestResponse::Request(_))) => {
                    if let Some(ref channel) = maybe_channel {
                        !(channel.state == ChannelState::Initiated)
                    } else {
                        false
                    }
                }
                // any other message variants are not allowed
                _ => false,
            };

            if !is_valid_call {
                log::error!("Unexpected XDM message: {:?}", msg,);
                return Err(InvalidTransaction::Call.into());
            }

            // Reject stale message
            if msg.nonce.cmp(&next_nonce) == Ordering::Less {
                return Err(InvalidTransaction::Stale.into());
            }

            let validated_relay_msg = ValidatedRelayMessage {
                message: msg,
                should_init_channel: maybe_channel.is_none(),
                next_nonce,
            };

            Ok(validated_relay_msg)
        }

        pub(crate) fn pre_dispatch_relay_message(
            msg: Message<BalanceOf<T>>,
            should_init_channel: bool,
        ) -> Result<(), TransactionValidityError> {
            if should_init_channel {
                if let VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(
                    ProtocolMessageRequest::ChannelOpen(params),
                ))) = msg.payload
                {
                    // channel is being opened without an owner since this is a relay message
                    // from other chain
                    // we do not check the allowlist to finish the end to end flow
                    Self::do_init_channel(msg.src_chain_id, params, None, false, Zero::zero())
                        .map_err(|err| {
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

            let (dst_chain_id, channel_id, nonce) = (msg.src_chain_id, msg.channel_id, msg.nonce);
            // future nonce check is already validated by the extension
            // it is safe to increment the next nonce here before processing.
            Channels::<T>::mutate(
                dst_chain_id,
                channel_id,
                |maybe_channel| -> sp_runtime::DispatchResult {
                    let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                    channel.next_inbox_nonce = nonce
                        .checked_add(Nonce::one())
                        .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
                    Ok(())
                },
            )
            .map_err(|err| {
                log::error!(
                    "Failed to increment the next relay message nonce for Chain[{:?}] with Channel[{:?}]: {:?}",
                    dst_chain_id,
                    channel_id,
                    err,
                );
                InvalidTransaction::Custom(crate::verification_errors::NEXT_NONCE_UPDATE)
            })?;

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
            consensus_state_root: StateRootOf<T>,
        ) -> Result<ValidatedRelayMessage<T>, TransactionValidityError> {
            // channel should be open and message should be present in outbox
            let next_nonce =
                match Channels::<T>::get(xdm.src_chain_id, xdm.channel_id) {
                    // unknown channel. return
                    None => {
                        log::error!("Unexpected inbox message response: {:?}", xdm,);
                        return Err(InvalidTransaction::Call.into());
                    }
                    Some(channel) => match channel.latest_response_received_message_nonce {
                        None => Nonce::zero(),
                        Some(last_nonce) => last_nonce.checked_add(Nonce::one()).ok_or(
                            InvalidTransaction::Custom(
                                crate::verification_errors::XDM_NONCE_OVERFLOW,
                            ),
                        )?,
                    },
                };

            // derive the key as stored on the src_chain.
            let key = StorageKey(
                T::StorageKeys::inbox_responses_storage_key(
                    xdm.src_chain_id,
                    (T::SelfChainId::get(), xdm.channel_id, xdm.nonce),
                )
                .ok_or(UnknownTransaction::CannotLookup)?,
            );

            // verify, decode, and store the message
            let msg = Self::do_verify_xdm(next_nonce, key, consensus_state_root, xdm)?;

            // Reject stale message
            if msg.nonce.cmp(&next_nonce) == Ordering::Less {
                return Err(InvalidTransaction::Stale.into());
            }

            let validated_relay_msg = ValidatedRelayMessage {
                message: msg,
                next_nonce,
                // not applicable in relay message response, default should be fine here
                should_init_channel: false,
            };

            Ok(validated_relay_msg)
        }

        pub(crate) fn pre_dispatch_relay_message_response(
            msg: Message<BalanceOf<T>>,
        ) -> Result<(), TransactionValidityError> {
            // future nonce check is already validated by the extension
            // it is safe to increment the next nonce here before processing.
            let (dst_chain_id, channel_id, nonce) = (msg.src_chain_id, msg.channel_id, msg.nonce);
            Channels::<T>::mutate(
                dst_chain_id,
                channel_id,
                |maybe_channel| -> sp_runtime::DispatchResult {
                    let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;
                    channel.latest_response_received_message_nonce = Some(nonce);
                    Ok(())
                },
            )
            .map_err(|err| {
                log::error!(
                    "Failed to increment the next relay message response nonce for Chain[{:?}] with Channel[{:?}]: {:?}",
                    dst_chain_id,
                    channel_id,
                    err,
                );
                InvalidTransaction::Custom(crate::verification_errors::NEXT_NONCE_UPDATE)
            })?;

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
            consensus_state_root: StateRootOf<T>,
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
        ) -> Result<Message<BalanceOf<T>>, TransactionValidityError> {
            // channel should be either already be created or match the next channelId for chain.
            let next_channel_id = NextChannelId::<T>::get(xdm.src_chain_id);
            ensure!(
                xdm.channel_id <= next_channel_id,
                InvalidTransaction::Custom(crate::verification_errors::INVALID_CHANNEL)
            );

            // verify nonce
            // nonce should be either be next or in future.
            ensure!(
                xdm.nonce >= next_nonce,
                InvalidTransaction::Custom(crate::verification_errors::INVALID_NONCE)
            );

            // if the message is from domain, verify domain confirmation proof
            let state_root = if let Some(domain_proof) = xdm.proof.domain_proof().clone()
                && let Some(domain_id) = xdm.src_chain_id.maybe_domain_chain()
            {
                let confirmed_domain_block_storage_key =
                    T::StorageKeys::confirmed_domain_block_storage_key(domain_id)
                        .ok_or(UnknownTransaction::CannotLookup)?;

                *StorageProofVerifier::<T::Hashing>::get_decoded_value::<
                    sp_domains::execution_receipt::ExecutionReceipt<
                        BlockNumberFor<T>,
                        T::Hash,
                        BlockNumberFor<T>,
                        T::Hash,
                        BalanceOf<T>,
                    >,
                >(
                    &consensus_state_root,
                    domain_proof,
                    StorageKey(confirmed_domain_block_storage_key),
                )
                .map_err(|err| {
                    log::error!(
                        "Failed to verify storage proof for confirmed Domain block: {:?}",
                        err
                    );
                    TransactionValidityError::Invalid(InvalidTransaction::BadProof)
                })?
                .final_state_root()
            } else {
                consensus_state_root
            };

            // verify and decode the message
            let msg =
                StorageProofVerifier::<T::Hashing>::get_decoded_value::<Message<BalanceOf<T>>>(
                    &state_root,
                    xdm.proof.message_proof(),
                    storage_key,
                )
                .map_err(|err| {
                    log::error!("Failed to verify storage proof for message: {:?}", err);
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

        pub fn channel_storage_key(chain_id: ChainId, channel_id: ChannelId) -> Vec<u8> {
            Channels::<T>::hashed_key_for(chain_id, channel_id)
        }

        pub fn domain_chains_allowlist_update(
            domain_id: DomainId,
        ) -> Option<DomainAllowlistUpdates> {
            DomainChainAllowlistUpdate::<T>::get(domain_id).filter(|updates| !updates.is_empty())
        }

        pub fn domain_allow_list_update_storage_key(domain_id: DomainId) -> Vec<u8> {
            DomainChainAllowlistUpdate::<T>::hashed_key_for(domain_id)
        }

        pub fn updated_channels() -> BTreeSet<(ChainId, ChannelId)> {
            UpdatedChannels::<T>::get()
        }

        pub fn open_channels() -> BTreeSet<(ChainId, ChannelId)> {
            Channels::<T>::iter_keys().collect()
        }

        pub fn channels_and_states() -> Vec<(ChainId, ChannelId, ChannelStateWithNonce)> {
            crate::migrations::get_channels_and_states::<T>()
        }

        pub fn channel_nonce(chain_id: ChainId, channel_id: ChannelId) -> Option<ChannelNonce> {
            crate::migrations::get_channel::<T>(chain_id, channel_id).map(|channel| {
                let last_inbox_nonce = channel.next_inbox_nonce.checked_sub(U256::one());
                ChannelNonce {
                    relay_msg_nonce: last_inbox_nonce,
                    relay_response_msg_nonce: channel.latest_response_received_message_nonce,
                }
            })
        }

        pub fn store_inbox_fee(
            src_chain_id: ChainId,
            message_id: MessageId,
            inbox_fees: BalanceOf<T>,
        ) -> DispatchResult {
            if !InboxFeesOnHoldStartAt::<T>::contains_key(message_id.0) {
                InboxFeesOnHoldStartAt::<T>::insert(message_id.0, message_id.1);
            }
            InboxFeesOnHold::<T>::mutate(|inbox_fees_on_hold| {
                *inbox_fees_on_hold = inbox_fees_on_hold
                    .checked_add(&inbox_fees)
                    .ok_or(Error::<T>::BalanceOverflow)?;

                // If the `imbalance` is dropped without consuming it will reduce the total issuance by
                // the same amount as we issued here, thus we need to manually `mem::forget` it.
                let imbalance = T::Currency::issue(inbox_fees);
                core::mem::forget(imbalance);

                Ok::<(), Error<T>>(())
            })?;

            InboxFee::<T>::insert((src_chain_id, message_id), inbox_fees);

            // Note `dst_chain_fee` as transfer in
            if !T::NoteChainTransfer::note_transfer_in(inbox_fees, src_chain_id) {
                return Err(Error::<T>::FailedToNoteTransferIn.into());
            }

            Ok(())
        }

        pub fn store_outbox_fee(
            dst_chain_id: ChainId,
            message_id: MessageId,
            outbox_fees: BalanceOf<T>,
            inbox_fees: BalanceOf<T>,
        ) -> DispatchResult {
            if !OutboxFeesOnHoldStartAt::<T>::contains_key(message_id.0) {
                OutboxFeesOnHoldStartAt::<T>::insert(message_id.0, message_id.1);
            }
            OutboxFeesOnHold::<T>::mutate(|outbox_fees_on_hold| {
                *outbox_fees_on_hold = outbox_fees_on_hold
                    .checked_add(&outbox_fees)
                    .ok_or(Error::<T>::BalanceOverflow)?;

                // If the `imbalance` is dropped without consuming it will reduce the total issuance by
                // the same amount as we issued here, thus we need to manually `mem::forget` it.
                let imbalance = T::Currency::issue(outbox_fees);
                core::mem::forget(imbalance);

                Ok::<(), Error<T>>(())
            })?;

            OutboxFee::<T>::insert((dst_chain_id, message_id), outbox_fees);

            // Note `dst_chain_fee` as transfer out
            if !T::NoteChainTransfer::note_transfer_out(inbox_fees, dst_chain_id) {
                return Err(Error::<T>::FailedToNoteTransferOut.into());
            }

            Ok(())
        }
    }
}

impl<T> Pallet<T>
where
    T: Config + CreateUnsigned<Call<T>>,
{
    pub fn outbox_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
    ) -> Option<T::Extrinsic> {
        let call = Call::relay_message { msg };
        Some(T::create_unsigned(call.into()))
    }

    pub fn inbox_response_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
    ) -> Option<T::Extrinsic> {
        let call = Call::relay_message_response { msg };
        Some(T::create_unsigned(call.into()))
    }

    /// Returns the first outbox message nonce that should be relayed to the dst_chain.
    pub fn first_outbox_message_nonce_to_relay(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        from_nonce: Nonce,
    ) -> Option<Nonce> {
        Self::first_relay_message(
            dst_chain_id,
            channel_id,
            from_nonce,
            Outbox::<T>::contains_key,
        )
    }

    /// Returns the first inbox response message nonce that should be relayed to the dst_chain.
    pub fn first_inbox_message_response_nonce_to_relay(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        from_nonce: Nonce,
    ) -> Option<Nonce> {
        Self::first_relay_message(
            dst_chain_id,
            channel_id,
            from_nonce,
            InboxResponses::<T>::contains_key,
        )
    }

    fn first_relay_message<Check>(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        from_nonce: Nonce,
        check: Check,
    ) -> Option<Nonce>
    where
        Check: Fn((ChainId, ChannelId, Nonce)) -> bool,
    {
        let mut nonce = from_nonce;
        let to_nonce = from_nonce.saturating_add(MAX_FUTURE_ALLOWED_NONCES.into());
        while nonce <= to_nonce {
            if check((dst_chain_id, channel_id, nonce)) {
                return Some(nonce);
            }

            nonce = nonce.saturating_add(Nonce::one())
        }

        None
    }
}

impl<T: Config> sp_domains::DomainBundleSubmitted for Pallet<T> {
    fn domain_bundle_submitted(domain_id: DomainId) {
        // NOTE: clear the updates leave an empty value but does not delete the value for the
        // domain completely because in the invalid extrinsic root fraud proof the prover need
        // to generate a proof-of-empty-value for the domain.
        DomainChainAllowlistUpdate::<T>::mutate(domain_id, |maybe_updates| {
            if let Some(updates) = maybe_updates {
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
