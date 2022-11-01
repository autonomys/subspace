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
use messages::{CrossDomainMessage, RelayerMessagesWithStorageKey};

/// A trait used by domains to track and fetch info about system domain.
pub trait SystemDomainTracker<StateRoot> {
    /// Get the latest state roots of the K-deep System domain blocks.
    fn latest_state_roots() -> Vec<StateRoot>;
}

sp_api::decl_runtime_apis! {
    /// Api useful for relayers to fetch messages and submit transactions.
    pub trait RelayerApi<RelayerId, DomainId>
    where
        RelayerId: Encode + Decode,
        DomainId: Encode + Decode
    {
        /// Returns the the domain_id of the Runtime.
        fn domain_id() -> DomainId;

        /// Returns all the outbox and inbox responses this relayer is assigned to deliver.
        /// Storage key is used to generate the storage proof for the message.
        fn relayer_assigned_messages(relayer_id: RelayerId) -> RelayerMessagesWithStorageKey<DomainId>;

        /// Submits outbox message to the dst_domain as an unsigned extrinsic.
        fn submit_outbox_message_unsigned(
            msg: CrossDomainMessage<DomainId, Block::Hash>,
        );

        /// Submits inbox response message to the dst_domain as an unsigned extrinsic.
        fn submit_inbox_response_message_unsigned(
            msg: CrossDomainMessage<DomainId, Block::Hash>,
        );
    }
}
