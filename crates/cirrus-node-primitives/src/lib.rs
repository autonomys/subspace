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
use sc_consensus_subspace::NewSlotInfo;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_application_crypto::KeyTypeId;
use sp_core::bytes;
use sp_executor::{Bundle, ExecutionReceipt};
use sp_runtime::traits::Hash as HashT;
use std::pin::Pin;
use subspace_runtime_primitives::{BlockNumber, Hash};

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

pub struct Collation {
    pub number: BlockNumber,
    pub head_data: HeadData,
}

/// Result of the [`CollatorFn`] invocation.
pub struct CollationResult {
    /// The collation that was build.
    pub collation: Collation,
    // TODO: can be useful in the future?
    /// An optional result sender that should be informed about a successfully seconded collation.
    ///
    /// There is no guarantee that this sender is informed ever about any result, it is completely okay to just drop it.
    /// However, if it is called, it should be called with the signed statement of a parachain validator seconding the
    /// collation.
    pub result_sender: Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>,
}

///
pub struct BundleResult {
    ///
    pub bundle: Bundle,
}

impl BundleResult {
    pub fn to_bundle(self) -> Bundle {
        self.bundle
    }
}

///
pub struct ProcessorResult {
    ///
    pub execution_receipt: ExecutionReceipt<Hash>,
}

impl ProcessorResult {
    pub fn to_execution_receipt(self) -> ExecutionReceipt<Hash> {
        self.execution_receipt
    }
}

// TODO: proper signal?
pub type CollationSecondedSignal = Vec<u8>;

// TODO: SubspaceBlockWeight
/// The cumulative weight of a block in a fork-choice rule.
pub type BlockWeight = u32;

#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub struct PersistedValidationData<H = Hash, N = BlockNumber> {
    // TODO: use a proper wrapper type?
    /// The encoded optional parent head hash.
    pub parent_head: Vec<u8>,
    /// The relay-chain block number this is in the context of.
    pub relay_parent_number: N,
    /// The relay-chain block storage root this is in the context of.
    pub relay_parent_storage_root: H,
}

impl CollationResult {
    /// Convert into the inner values.
    pub fn into_inner(
        self,
    ) -> (
        Collation,
        Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>,
    ) {
        (self.collation, self.result_sender)
    }
}

/// Collation function.
///
/// Will be called with the hash of the relay chain block the parachain block should be build on and the
/// [`ValidationData`] that provides information about the state of the parachain on the relay chain.
///
/// Returns an optional [`CollationResult`].
pub type CollatorFn = Box<
    dyn Fn(
            Hash,
            &PersistedValidationData,
        ) -> Pin<Box<dyn Future<Output = Option<CollationResult>> + Send>>
        + Send
        + Sync,
>;

/// Collation function.
///
/// Will be called with the hash of the relay chain block the parachain block should be build on and the
/// [`ValidationData`] that provides information about the state of the parachain on the relay chain.
///
/// Returns an optional [`CollationResult`].
pub type BundlerFn = Box<
    dyn Fn(NewSlotInfo) -> Pin<Box<dyn Future<Output = Option<BundleResult>> + Send>> + Send + Sync,
>;

/// Collation function.
///
/// Will be called with the hash of the relay chain block the parachain block should be build on and the
/// [`ValidationData`] that provides information about the state of the parachain on the relay chain.
///
/// Returns an optional [`CollationResult`].
pub type ProcessorFn = Box<
    dyn Fn(Hash, Vec<Bundle>) -> Pin<Box<dyn Future<Output = Option<ProcessorResult>> + Send>>
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
    /// Collator's authentication key, so it can sign things.
    pub key: CollatorPair,
    /// Collation function. See [`CollatorFn`] for more details.
    pub collator: CollatorFn,
    /// Transaction bundle function.
    pub bundler: BundlerFn,
    /// State processor function.
    pub processor: ProcessorFn,
}

impl std::fmt::Debug for CollationGenerationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CollationGenerationConfig {{ ... }}")
    }
}
