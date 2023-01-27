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

use codec::{Decode, Encode};
use messages::{CrossDomainMessage, MessageId, RelayerMessagesWithStorageKey};
use sp_domains::DomainId;
use sp_runtime::app_crypto::sp_core::storage::StorageKey;

/// Implemented by domain registry on system domain or system domain tracker on core domains.
/// This trait supports utilities to verify the message coming from src_domain to system domain.
/// If the message is sent to another core domain, then dst_domain can use this trait and verify the message
/// using System domain as trusted third party.
pub trait DomainTracker<BlockNumber, StateRoot> {
    /// Returns the storage key that maps to the state root of the core domain for a specific block.
    fn storage_key_for_core_domain_state_root(
        domain_id: DomainId,
        block_number: BlockNumber,
    ) -> StorageKey;
}

sp_api::decl_runtime_apis! {
    /// Api useful for relayers to fetch messages and submit transactions.
    pub trait RelayerApi<RelayerId, BlockNumber>
    where
        RelayerId: Encode + Decode,
        BlockNumber: Encode + Decode
    {
        /// Returns the the domain_id of the Runtime.
        fn domain_id() -> DomainId;

        /// Returns the confirmation depth to relay message
        fn relay_confirmation_depth() -> BlockNumber;

        /// Returns all the outbox and inbox responses this relayer is assigned to deliver.
        /// Storage key is used to generate the storage proof for the message.
        fn relayer_assigned_messages(relayer_id: RelayerId) -> RelayerMessagesWithStorageKey;

        /// Constructs an outbox message to the dst_domain as an unsigned extrinsic.
        fn outbox_message_unsigned(
            msg: CrossDomainMessage<Block::Hash, BlockNumber>,
        ) -> Option<Block::Extrinsic>;

        /// Constructs an inbox response message to the dst_domain as an unsigned extrinsic.
        fn inbox_response_message_unsigned(
            msg: CrossDomainMessage<Block::Hash, BlockNumber>,
        ) -> Option<Block::Extrinsic>;

        /// Returns true if the outbox message is ready to be relayed to dst_domain.
        fn should_relay_outbox_message(dst_domain_id: DomainId, msg_id: MessageId) -> bool;

        /// Returns true if the inbox message response is ready to be relayed to dst_domain.
        fn should_relay_inbox_message_response(dst_domain_id: DomainId, msg_id: MessageId) -> bool;
    }
}
