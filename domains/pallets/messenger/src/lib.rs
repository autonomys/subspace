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

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

mod fees;
mod messages;

use codec::{Decode, Encode};
use frame_support::traits::fungible::Inspect;
use frame_system::pallet_prelude::*;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::U256;
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
pub struct Channel<Balance> {
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

pub(crate) struct ValidatedRelayMessage<Balance> {
    msg: Message<Balance>,
    next_nonce: Nonce,
    should_init_channel: bool,
}

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use crate::{
        BalanceOf, Channel, ChannelId, ChannelState, FeeModel, Nonce, OutboxMessageResult,
        StateRootOf, ValidatedRelayMessage, U256,
    };
    use frame_support::pallet_prelude::*;
    use frame_support::traits::fungible::Mutate;
    use frame_support::weights::WeightToFee;
    use frame_system::pallet_prelude::*;
    use sp_core::storage::StorageKey;
    use sp_domains::verification::{StorageProofVerifier, VerificationError};
    use sp_domains::DomainId;
    use sp_messenger::endpoint::{DomainInfo, Endpoint, EndpointHandler, EndpointRequest, Sender};
    use sp_messenger::messages::{
        BlockInfo, ChainId, CrossDomainMessage, InitiateChannelParams, Message, MessageId,
        MessageWeightTag, Payload, ProtocolMessageRequest, RequestResponse, VersionedPayload,
    };
    use sp_messenger::OnXDMRewards;
    use sp_runtime::traits::CheckedSub;
    use sp_runtime::ArithmeticError;
    use sp_std::boxed::Box;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Gets the chain_id that is treated as src_chain_id for outgoing messages.
        type SelfChainId: Get<ChainId>;
        /// function to fetch endpoint response handler by Endpoint.
        fn get_endpoint_handler(endpoint: &Endpoint)
            -> Option<Box<dyn EndpointHandler<MessageId>>>;
        /// Currency type pallet uses for fees and deposits.
        type Currency: Mutate<Self::AccountId>;
        /// Chain info to verify chain state roots at a confirmation depth.
        type DomainInfo: DomainInfo<BlockNumberFor<Self>, Self::Hash, StateRootOf<Self>>;
        /// Confirmation depth for XDM coming from chains.
        type ConfirmationDepth: Get<BlockNumberFor<Self>>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
        /// Weight to fee conversion.
        type WeightToFee: WeightToFee<Balance = BalanceOf<Self>>;
        /// Handle XDM rewards.
        type OnXDMRewards: OnXDMRewards<BalanceOf<Self>>;
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
        Channel<BalanceOf<T>>,
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
                    } = Self::do_validate_relay_message(xdm)?;
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
                    let (msg, next_nonce) = Self::do_validate_relay_message_response(xdm)?;
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
                    } = Self::do_validate_relay_message(xdm)?;

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
                        .priority(TransactionPriority::MAX)
                        .longevity(TransactionLongevity::MAX)
                        .and_provides((msg.dst_chain_id, msg.channel_id, msg.nonce))
                        .propagate(true)
                        .build()
                }
                Call::relay_message_response { msg: xdm } => {
                    let (msg, next_nonce) = Self::do_validate_relay_message_response(xdm)?;

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
                        .priority(TransactionPriority::MAX)
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

        /// Emite when the there is balance overflow
        BalanceOverflow,
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
        /// Only a root user can create the channel.
        #[pallet::call_index(0)]
        #[pallet::weight((T::WeightInfo::initiate_channel(), Pays::No))]
        pub fn initiate_channel(
            origin: OriginFor<T>,
            dst_chain_id: ChainId,
            params: InitiateChannelParams<BalanceOf<T>>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            // TODO(ved): fee for channel open

            // initiate the channel config
            let channel_id = Self::do_init_channel(dst_chain_id, params)?;

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
        /// Only a root user can close an open channel.
        #[pallet::call_index(1)]
        #[pallet::weight((T::WeightInfo::close_channel(), Pays::No))]
        pub fn close_channel(
            origin: OriginFor<T>,
            chain_id: ChainId,
            channel_id: ChannelId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::do_close_channel(chain_id, channel_id)?;
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
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
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
            msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            let outbox_resp_msg = OutboxResponses::<T>::take().ok_or(Error::<T>::MissingMessage)?;
            Self::process_outbox_message_responses(outbox_resp_msg, msg.weight_tag)?;
            Ok(())
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
            let channel_id = Self::do_init_channel(dst_chain_id, init_params)?;
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
                        // If there is no endpoint handler the request won't be handled thus reture zero weight
                        .unwrap_or(Weight::zero())
                }
                MessageWeightTag::EndpointResponse(endpoint) => {
                    T::get_endpoint_handler(endpoint)
                        .map(|endpoint_handler| endpoint_handler.message_response_weight())
                        // If there is no endpoint handler the request won't be handled thus reture zero weight
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

        pub(crate) fn do_close_channel(chain_id: ChainId, channel_id: ChannelId) -> DispatchResult {
            Channels::<T>::try_mutate(chain_id, channel_id, |maybe_channel| -> DispatchResult {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::MissingChannel)?;

                ensure!(
                    channel.state == ChannelState::Open,
                    Error::<T>::InvalidChannelState
                );

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
        ) -> Result<ChannelId, DispatchError> {
            ensure!(
                T::SelfChainId::get() != dst_chain_id,
                Error::<T>::InvalidChain,
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
                },
            );

            NextChannelId::<T>::insert(dst_chain_id, next_channel_id);
            Self::deposit_event(Event::ChannelInitiated {
                chain_id: dst_chain_id,
                channel_id,
            });
            Ok(channel_id)
        }

        pub(crate) fn do_validate_relay_message(
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
        ) -> Result<ValidatedRelayMessage<BalanceOf<T>>, TransactionValidityError> {
            let mut should_init_channel = false;
            let next_nonce = match Channels::<T>::get(xdm.src_chain_id, xdm.channel_id) {
                None => {
                    // if there is no channel config, this must the Channel open request.
                    // so nonce is 0
                    should_init_channel = true;
                    // TODO(ved): collect fees to open channel
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
            let key = StorageKey(Outbox::<T>::hashed_key_for((
                T::SelfChainId::get(),
                xdm.channel_id,
                xdm.nonce,
            )));

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
                    Self::do_init_channel(msg.src_chain_id, params).map_err(|err| {
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

        pub(crate) fn do_validate_relay_message_response(
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
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
            let key = StorageKey(InboxResponses::<T>::hashed_key_for((
                T::SelfChainId::get(),
                xdm.channel_id,
                xdm.nonce,
            )));

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
            xdm: &CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
        ) -> Result<Message<BalanceOf<T>>, TransactionValidityError> {
            // channel should be either already be created or match the next channelId for chain.
            let next_channel_id = NextChannelId::<T>::get(xdm.src_chain_id);
            ensure!(xdm.channel_id <= next_channel_id, InvalidTransaction::Call);

            // verify nonce
            // nonce should be either be next or in future.
            ensure!(xdm.nonce >= next_nonce, InvalidTransaction::Call);

            let extracted_state_roots = xdm.extract_state_roots_from_proof::<T::Hashing>().ok_or(
                TransactionValidityError::Invalid(InvalidTransaction::BadProof),
            )?;

            // on consensus, ensure the domain info is at K-depth and state root matches
            if T::SelfChainId::get().is_consensus_chain() {
                if let Some((domain_id, block_info, state_root)) =
                    extracted_state_roots.domain_info.clone()
                {
                    ensure!(
                        Self::is_domain_info_confirmed(domain_id, block_info, state_root),
                        InvalidTransaction::BadProof
                    )
                }
            }

            let state_root = extracted_state_roots
                .domain_info
                .map(|(_chain_id, _info, state_root)| state_root)
                .unwrap_or(extracted_state_roots.consensus_chain_state_root);

            // verify and decode the message
            let msg =
                StorageProofVerifier::<T::Hashing>::get_decoded_value::<Message<BalanceOf<T>>>(
                    &state_root,
                    xdm.proof.message_proof.clone(),
                    storage_key,
                )
                .map_err(|err| {
                    log::error!(
                        target: "runtime::messenger",
                        "Failed to verify storage proof: {:?}",
                        err
                    );
                    TransactionValidityError::Invalid(InvalidTransaction::BadProof)
                })?;

            Ok(msg)
        }

        pub fn is_domain_info_confirmed(
            domain_id: DomainId,
            domain_block_info: BlockInfo<BlockNumberFor<T>, T::Hash>,
            domain_state_root: T::Hash,
        ) -> bool {
            // ensure the block is at-least k-deep
            let confirmed = T::DomainInfo::domain_best_number(domain_id)
                .and_then(|best_number| {
                    best_number
                        .checked_sub(&T::ConfirmationDepth::get())
                        .map(|confirmed_number| confirmed_number >= domain_block_info.block_number)
                })
                .unwrap_or(false);

            // verify state root of the block
            let valid_state_root = T::DomainInfo::domain_state_root(
                domain_id,
                domain_block_info.block_number,
                domain_block_info.block_hash,
            )
            .map(|got_state_root| got_state_root == domain_state_root)
            .unwrap_or(false);

            confirmed && valid_state_root
        }
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    pub fn outbox_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
    ) -> Option<T::Extrinsic> {
        let call = Call::relay_message { msg };
        T::Extrinsic::new(call.into(), None)
    }

    pub fn inbox_response_message_unsigned(
        msg: CrossDomainMessage<BlockNumberFor<T>, T::Hash, StateRootOf<T>>,
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
