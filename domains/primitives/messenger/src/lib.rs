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

//! Primitives for Messenger.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod endpoint;
pub mod messages;

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::messages::{ChannelStateWithNonce, MessageKey, Nonce};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use frame_support::inherent::InherentData;
use frame_support::inherent::{InherentIdentifier, IsFatalError};
#[cfg(feature = "runtime-benchmarks")]
use frame_support::storage::storage_prefix;
#[cfg(feature = "runtime-benchmarks")]
use frame_support::{Identity, StorageHasher};
use messages::{
    BlockMessagesQuery, BlockMessagesWithStorageKey, ChannelId, CrossDomainMessage, MessageId,
};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::{ChainId, DomainAllowlistUpdates, DomainId};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Messenger inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"messengr";

/// Maximum number of XDMs per domain/channel with future nonces that are allowed to be validated.
/// Any XDM comes with a nonce above Maximum future nonce will be rejected.
// TODO: We need to benchmark how many XDMs can fit in to a
//  - Single consensus block
//  - Single domain block(includes all bundles filled with XDMs)
//  Once we have that info, we can make a better judgement on how many XDMs
//  we want to include per block while allowing other extrinsics to be included as well.
//  Note: Currently XDM takes priority over other extrinsics unless they come with priority fee
pub const MAX_FUTURE_ALLOWED_NONCES: u32 = 256;

/// Trait to handle XDM rewards.
pub trait OnXDMRewards<Balance> {
    fn on_xdm_rewards(rewards: Balance);
    fn on_chain_protocol_fees(chain_id: ChainId, fees: Balance);
}

/// Trait to note cross chain transfer
pub trait NoteChainTransfer<Balance> {
    fn note_transfer_in(amount: Balance, from_chain_id: ChainId) -> bool;
    fn note_transfer_out(amount: Balance, to_chain_id: ChainId) -> bool;
}

impl<Balance> NoteChainTransfer<Balance> for () {
    fn note_transfer_in(_amount: Balance, _from_chain_id: ChainId) -> bool {
        true
    }
    fn note_transfer_out(_amount: Balance, _to_chain_id: ChainId) -> bool {
        true
    }
}

impl<Balance> OnXDMRewards<Balance> for () {
    fn on_xdm_rewards(_: Balance) {}

    fn on_chain_protocol_fees(_chain_id: ChainId, _fees: Balance) {}
}

/// Trait to check if the domain is registered.
pub trait DomainRegistration {
    fn is_domain_registered(domain_id: DomainId) -> bool;
}

impl DomainRegistration for () {
    fn is_domain_registered(_domain_id: DomainId) -> bool {
        false
    }
}

/// Trait that return various storage keys for storages on Consensus chain and domains
pub trait StorageKeys {
    /// Returns the storage key for confirmed domain block on conensus chain
    fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Option<Vec<u8>>;

    /// Returns the outbox storage key for given chain.
    fn outbox_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>>;

    /// Returns the inbox responses storage key for given chain.
    fn inbox_responses_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>>;
}

impl StorageKeys for () {
    fn confirmed_domain_block_storage_key(_domain_id: DomainId) -> Option<Vec<u8>> {
        None
    }

    fn outbox_storage_key(_chain_id: ChainId, _message_key: MessageKey) -> Option<Vec<u8>> {
        None
    }

    fn inbox_responses_storage_key(
        _chain_id: ChainId,
        _message_key: MessageKey,
    ) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(feature = "runtime-benchmarks")]
pub struct BenchmarkStorageKeys;

#[cfg(feature = "runtime-benchmarks")]
impl StorageKeys for BenchmarkStorageKeys {
    fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Option<Vec<u8>> {
        let storage_prefix = storage_prefix(
            "Domains".as_bytes(),
            "LatestConfirmedDomainExecutionReceipt".as_bytes(),
        );
        let key_hashed = domain_id.using_encoded(Identity::hash);

        let mut final_key = Vec::with_capacity(storage_prefix.len() + key_hashed.len());

        final_key.extend_from_slice(&storage_prefix);
        final_key.extend_from_slice(key_hashed.as_ref());

        Some(final_key)
    }

    fn outbox_storage_key(_chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        let storage_prefix = storage_prefix("Messenger".as_bytes(), "Outbox".as_bytes());
        let key_hashed = message_key.using_encoded(Identity::hash);

        let mut final_key = Vec::with_capacity(storage_prefix.len() + key_hashed.len());

        final_key.extend_from_slice(&storage_prefix);
        final_key.extend_from_slice(key_hashed.as_ref());

        Some(final_key)
    }

    fn inbox_responses_storage_key(_chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        let storage_prefix = storage_prefix("Messenger".as_bytes(), "InboxResponses".as_bytes());
        let key_hashed = message_key.using_encoded(Identity::hash);

        let mut final_key = Vec::with_capacity(storage_prefix.len() + key_hashed.len());

        final_key.extend_from_slice(&storage_prefix);
        final_key.extend_from_slice(key_hashed.as_ref());

        Some(final_key)
    }
}

/// The type of the messenger inherent data.
#[derive(Debug, Encode, Decode)]
pub struct InherentType {
    pub maybe_updates: Option<DomainAllowlistUpdates>,
}

/// Inherent specific errors
#[derive(Debug, Encode)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
    MissingAllowlistUpdates,
    IncorrectAllowlistUpdates,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        true
    }
}

/// Provides the set code inherent data.
#[cfg(feature = "std")]
pub struct InherentDataProvider {
    data: InherentType,
}

#[cfg(feature = "std")]
impl InherentDataProvider {
    /// Create new inherent data provider from the given `data`.
    pub fn new(data: InherentType) -> Self {
        Self { data }
    }

    /// Returns the `data` of this inherent data provider.
    pub fn data(&self) -> &InherentType {
        &self.data
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
    async fn provide_inherent_data(
        &self,
        inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        inherent_data.put_data(INHERENT_IDENTIFIER, &self.data)
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        if *identifier != INHERENT_IDENTIFIER {
            return None;
        }

        let error = InherentError::decode(&mut &*error).ok()?;

        Some(Err(sp_inherents::Error::Application(Box::from(format!(
            "{error:?}"
        )))))
    }
}

/// Represent a union of XDM types with their message ID
#[derive(Debug, Encode, Decode, TypeInfo, Copy, Clone)]
pub enum XdmId {
    RelayMessage(MessageKey),
    RelayResponseMessage(MessageKey),
}

impl XdmId {
    pub fn get_chain_id_and_channel_id(&self) -> (ChainId, ChannelId) {
        match self {
            XdmId::RelayMessage(key) => (key.0, key.1),
            XdmId::RelayResponseMessage(key) => (key.0, key.1),
        }
    }
}

#[derive(Debug, Encode, Decode, TypeInfo, Copy, Clone)]
pub struct ChannelNonce {
    /// Last processed relay message nonce.
    /// Could be None if there is no relay message yet.
    pub relay_msg_nonce: Option<Nonce>,
    /// Last processed relay response message nonce.
    /// Could be None if there is no first response yet
    pub relay_response_msg_nonce: Option<Nonce>,
}

sp_api::decl_runtime_apis! {
    /// Api useful for relayers to fetch messages and submit transactions.
    #[api_version(3)]
    pub trait RelayerApi<BlockNumber, CNumber, CHash>
    where
        BlockNumber: Encode + Decode,
        CNumber: Encode + Decode,
        CHash: Encode + Decode,
    {
        /// Returns all the outbox and inbox responses to deliver.
        /// Storage key is used to generate the storage proof for the message.
        fn block_messages() -> BlockMessagesWithStorageKey;

        /// Constructs an outbox message to the dst_chain as an unsigned extrinsic.
        fn outbox_message_unsigned(
            msg: CrossDomainMessage<CNumber, CHash, sp_core::H256>,
        ) -> Option<Block::Extrinsic>;

        /// Constructs an inbox response message to the dst_chain as an unsigned extrinsic.
        fn inbox_response_message_unsigned(
            msg: CrossDomainMessage<CNumber, CHash, sp_core::H256>,
        ) -> Option<Block::Extrinsic>;

        /// Returns true if the outbox message is ready to be relayed to dst_chain.
        fn should_relay_outbox_message(dst_chain_id: ChainId, msg_id: MessageId) -> bool;

        /// Returns true if the inbox message response is ready to be relayed to dst_chain.
        fn should_relay_inbox_message_response(dst_chain_id: ChainId, msg_id: MessageId) -> bool;

        /// Returns the list of channels updated in the given block.
        fn updated_channels() -> BTreeSet<(ChainId, ChannelId)>;

        /// Returns storage key for channels for given chain and channel id.
        fn channel_storage_key(chain_id: ChainId, channel_id: ChannelId) -> Vec<u8>;

        /// Returns all the open channels to other chains.
        fn open_channels() -> BTreeSet<(ChainId, ChannelId)>;

        /// Returns outbox and inbox responses from given nonce to maximum allowed nonce per block
        /// Storage key is used to generate the storage proof for the message.
        fn block_messages_with_query(query: BlockMessagesQuery) -> BlockMessagesWithStorageKey;

        /// Returns all the channels to other chains and their local Channel state.
        fn channels_and_state() -> Vec<(ChainId, ChannelId, ChannelStateWithNonce)>;

        /// Returns the first outbox message nonce that should be relayed to the dst_chain.
        fn should_relay_outbox_messages(dst_chain_id: ChainId, channel_id: ChannelId, from_nonce: Nonce) -> Option<Nonce>;

        /// Returns the first inbox response message nonce that should be relayed to the dst_chain.
        fn should_relay_inbox_message_responses(dst_chain_id: ChainId,channel_id: ChannelId, from_nonce: Nonce) -> Option<Nonce>;
    }

    /// Api to provide XDM extraction from Runtime Calls.
    #[api_version(3)]
    pub trait MessengerApi<CNumber, CHash>
    where
        CNumber: Encode + Decode,
        CHash: Encode + Decode,
    {
        /// Returns `Some(true)` if valid XDM or `Some(false)` if not
        /// Returns None if this is not an XDM
        fn is_xdm_mmr_proof_valid(
            ext: &Block::Extrinsic
        ) -> Option<bool>;

        // Extract the MMR proof from the XDM
        fn extract_xdm_mmr_proof(ext: &Block::Extrinsic) -> Option<ConsensusChainMmrLeafProof<CNumber, CHash, sp_core::H256>>;

        // Extract the MMR proofs a the given batch of XDM
        // `allow(clippy::ptr_arg` is needed because Clippy complains to replace `&Vec<T>` with `&[T]`
        // but the latter fails to compile.
        #[allow(clippy::ptr_arg)]
        fn batch_extract_xdm_mmr_proof(ext: &Vec<Block::Extrinsic>) -> BTreeMap<u32, ConsensusChainMmrLeafProof<CNumber, CHash, sp_core::H256>>;

        /// Returns the confirmed domain block storage for given domain.
        fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Vec<u8>;

        /// Returns storage key for outbox for a given message_id.
        fn outbox_storage_key(message_key: MessageKey) -> Vec<u8>;

        /// Returns storage key for inbox response for a given message_id.
        fn inbox_response_storage_key(message_key: MessageKey) -> Vec<u8>;

        /// Returns any domain's chains allowlist updates on consensus chain.
        fn domain_chains_allowlist_update(domain_id: DomainId) -> Option<DomainAllowlistUpdates>;

        /// Returns XDM message ID
        fn xdm_id(ext: &Block::Extrinsic) -> Option<XdmId>;

        /// Get Channel nonce for given chain and channel id.
        fn channel_nonce(chain_id: ChainId, channel_id: ChannelId) -> Option<ChannelNonce>;
    }
}
