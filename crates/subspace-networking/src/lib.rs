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

//! Networking functionality of Subspace Network, primarily used for DSN (Distributed Storage
//! Network).

#![feature(exact_size_is_empty, impl_trait_in_assoc_type, ip, try_blocks)]
#![warn(missing_docs)]

mod behavior;
mod constructor;
mod node;
mod node_runner;
pub mod protocols;

mod shared;
pub mod utils;

pub use crate::behavior::persistent_parameters::{
    KnownPeersManager, KnownPeersManagerConfig, KnownPeersManagerPersistenceError,
    KnownPeersRegistry, PeerAddressRemovedEvent,
};
pub use crate::node::{
    GetClosestPeersError, Node, SendRequestError, SubscribeError, TopicSubscription, WeakNode,
};
pub use crate::node_runner::NodeRunner;
pub use constructor::{
    construct, peer_id, Config, CreationError, KademliaMode, LocalRecordProvider,
};
pub use libp2p;
pub use shared::PeerDiscovered;
pub use utils::key_with_distance::KeyWithDistance;
pub use utils::multihash::Multihash;
pub use utils::PeerAddress;
