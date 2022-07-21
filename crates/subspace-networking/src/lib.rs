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
#![feature(ip)]

mod behavior;
mod create;
pub mod multimess;
mod node;
mod node_runner;
mod pieces_by_range_handler;
mod request_responses;
mod shared;
mod utils;

pub use crate::behavior::persistent_parameters::NetworkingParametersManager;
pub use crate::node::{
    CircuitRelayClientError, GetPiecesByRangeError, Node, SubscribeError, TopicSubscription,
};
pub use crate::node_runner::NodeRunner;
pub use create::{create, Config, CreationError};
pub use libp2p;
use libp2p::gossipsub::Sha256Topic;
use once_cell::sync::Lazy;
pub use pieces_by_range_handler::{PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};

// TODO: Move this out of the networking crate into separate crate.
pub static PUB_SUB_ARCHIVING_TOPIC: Lazy<Sha256Topic> =
    Lazy::new(|| Sha256Topic::new("PUB_SUB_ARCHIVING_TOPIC"));
