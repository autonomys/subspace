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
#![feature(const_option, impl_trait_in_assoc_type, ip, try_blocks)]
#![warn(missing_docs)]

mod behavior;
mod composer;
mod node;
mod node_runner;
mod protocols;

mod shared;
pub mod utils;

pub use crate::behavior::persistent_parameters::{
    NetworkParametersPersistenceError, NetworkingParametersManager,
};
pub use crate::node::{
    GetClosestPeersError, Node, SendRequestError, SubscribeError, TopicSubscription,
};
pub use crate::node_runner::NodeRunner;
pub use crate::protocols::peer_info::{
    Config as PeerInfoConfig, CuckooFilterDTO, CuckooFilterProvider, Notification,
    NotificationHandler, PeerInfo, PeerInfoProvider,
};
pub use composer::{compose, peer_id, Config, CreationError, LocalRecordProvider};
pub use libp2p;
pub use protocols::requests::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
pub use protocols::requests::handlers::piece_by_index::{
    PieceByIndexRequest, PieceByIndexRequestHandler, PieceByIndexResponse,
};
pub use protocols::requests::handlers::segment_header::{
    SegmentHeaderBySegmentIndexesRequestHandler, SegmentHeaderRequest, SegmentHeaderResponse,
};
pub use shared::NewPeerInfo;
pub use utils::multihash::Multihash;
pub use utils::prometheus::start_prometheus_metrics_server;
pub use utils::unique_record_binary_heap::{KeyWrapper, UniqueRecordBinaryHeap};
