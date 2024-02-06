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

//! Host functions for Messenger.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::{ChainId, DomainId};
use sp_messenger::messages::MessageId;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;

#[cfg(feature = "std")]
mod host_functions;
mod runtime_interface;

#[cfg(feature = "std")]
pub use host_functions::{MessengerExtension, MessengerHostFunctionsImpl};
pub use runtime_interface::messenger_runtime_interface::get_storage_key;
#[cfg(feature = "std")]
pub use runtime_interface::messenger_runtime_interface::HostFunctions;

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum StorageKeyRequest {
    /// Request to get confirmed domain block storage key for given domain.
    ConfirmedDomainBlockStorageKey(DomainId),
    /// Request to get Outbox storage key for given chain and message.
    OutboxStorageKey {
        chain_id: ChainId,
        message_id: MessageId,
    },
    /// Request to get Inbox response storage key for given chain and message.
    InboxResponseStorageKey {
        chain_id: ChainId,
        message_id: MessageId,
    },
}

impl PassBy for StorageKeyRequest {
    type PassBy = pass_by::Codec<Self>;
}
