// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Node primitives for Subspace Network.

use futures::Future;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_application_crypto::KeyTypeId;
use sp_consensus_slots::Slot;
use sp_core::bytes;
use sp_executor::{OpaqueBundle, OpaqueExecutionReceipt};
use sp_runtime::traits::Hash as HashT;
use std::{borrow::Cow, pin::Pin};
use subspace_core_primitives::{Randomness, Tag};
use subspace_runtime_primitives::Hash;

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub struct ExecutorSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global slot challenge
    pub global_challenge: Tag,
}

/// Parachain head data included in the chain.
#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    Clone,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TypeInfo,
)]
pub struct HeadData(#[serde(with = "bytes")] pub Vec<u8>);

impl HeadData {
    /// Returns the hash of this head data.
    pub fn hash(&self) -> Hash {
        sp_runtime::traits::BlakeTwo256::hash(&self.0)
    }
}

/// Result of the [`BundlerFn`] invocation.
pub struct BundleResult {
    /// The opaque bundle that was built.
    pub opaque_bundle: OpaqueBundle,
}

impl BundleResult {
    pub fn to_opaque_bundle(self) -> OpaqueBundle {
        self.opaque_bundle
    }
}

/// Result of the [`ProcessorFn`] invocation.
pub struct ProcessorResult {
    /// The opaque execution receipt that was built.
    pub opaque_execution_receipt: OpaqueExecutionReceipt,
}

impl ProcessorResult {
    pub fn to_opaque_execution_receipt(self) -> OpaqueExecutionReceipt {
        self.opaque_execution_receipt
    }
}

// TODO: proper signal?
pub type CollationSecondedSignal = Vec<u8>;

// TODO: SubspaceBlockWeight
/// The cumulative weight of a block in a fork-choice rule.
pub type BlockWeight = u32;

/// Bundle function.
///
/// Will be called with each slot of the primary chain.
///
/// Returns an optional [`BundleResult`].
pub type BundlerFn = Box<
    dyn Fn(Hash, ExecutorSlotInfo) -> Pin<Box<dyn Future<Output = Option<BundleResult>> + Send>>
        + Send
        + Sync,
>;

/// Process function.
///
/// Will be called with the hash of the primary chain block.
///
/// Returns an optional [`ProcessorResult`].
pub type ProcessorFn = Box<
    dyn Fn(
            Hash,
            Vec<OpaqueBundle>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Option<ProcessorResult>> + Send>>
        + Send
        + Sync,
>;

/// The key type ID for a collator key.
const COLLATOR_KEY_TYPE_ID: KeyTypeId = KeyTypeId(*b"coll");

mod collator_app {
    use super::COLLATOR_KEY_TYPE_ID;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, COLLATOR_KEY_TYPE_ID);
}

/// Identity that collators use.
pub type CollatorId = collator_app::Public;

/// A Parachain collator keypair.
pub type CollatorPair = collator_app::Pair;

/// Signature on candidate's block data by a collator.
pub type CollatorSignature = collator_app::Signature;

/// Configuration for the collation generator
pub struct CollationGenerationConfig {
    /// Transaction bundle function. See [`BundlerFn`] for more details.
    pub bundler: BundlerFn,
    /// State processor function. See [`ProcessorFn`] for more details.
    pub processor: ProcessorFn,
}

impl std::fmt::Debug for CollationGenerationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CollationGenerationConfig {{ ... }}")
    }
}
