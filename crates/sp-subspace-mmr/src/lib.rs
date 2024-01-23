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

//! Primitives for Subspace MMR.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod host_functions;
pub mod runtime_interface;
#[cfg(feature = "std")]
pub use runtime_interface::subspace_mmr_runtime_interface::HostFunctions;

use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// MMR leaf structure
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum MmrLeaf<BlockNumber, Hash> {
    /// V0 version of leaf data
    V0(LeafDataV0<BlockNumber, Hash>),
}

/// MMR v0 leaf data
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct LeafDataV0<BlockNumber, Hash> {
    pub block_number: BlockNumber,
    pub block_hash: Hash,
    /// Can be used to prove specific storage after block was imported
    pub state_root: Hash,
    /// Can be used to prove block body
    pub extrinsics_root: Hash,
}
