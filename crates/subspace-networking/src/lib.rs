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
mod create;
mod node;
mod node_runner;
mod peer_info;
mod request_handlers;
mod request_responses;
mod reserved_peers;
mod shared;
pub mod utils;

pub use crate::behavior::persistent_parameters::{
    BootstrappedNetworkingParameters, NetworkParametersPersistenceError,
    NetworkingParametersManager, ParityDbError,
};
pub use crate::node::{
    GetClosestPeersError, Node, SendRequestError, SubscribeError, TopicSubscription,
};
pub use crate::node_runner::{NodeRunner, KADEMLIA_PROVIDER_TTL_IN_SECS};
pub use crate::peer_info::{
    Config as PeerInfoConfig, CuckooFilterDTO, CuckooFilterProvider, Notification,
    NotificationHandler, PeerInfo, PeerInfoProvider,
};
pub use behavior::provider_storage::{
    MemoryProviderStorage, ParityDbProviderStorage, ProviderStorage, VoidProviderStorage,
};
pub use create::{create, peer_id, Config, CreationError,};
pub use libp2p;
pub use request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
pub use request_handlers::object_mappings::{
    ObjectMappingsRequest, ObjectMappingsRequestHandler, ObjectMappingsResponse,
};
pub use request_handlers::piece_announcement::{
    PieceAnnouncementRequest, PieceAnnouncementRequestHandler, PieceAnnouncementResponse,
};
pub use request_handlers::piece_by_key::{
    PieceByHashRequest, PieceByHashRequestHandler, PieceByHashResponse,
};
pub use request_handlers::pieces_by_range::{
    PiecesByRangeRequest, PiecesByRangeRequestHandler, PiecesByRangeResponse, PiecesToPlot,
};
pub use request_handlers::segment_header::{
    SegmentHeaderBySegmentIndexesRequestHandler, SegmentHeaderRequest, SegmentHeaderResponse,
};
pub use utils::prometheus::start_prometheus_metrics_server;
pub use utils::unique_record_binary_heap::UniqueRecordBinaryHeap;
