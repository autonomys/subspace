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
use std::pin::Pin;
use subspace_runtime_primitives::{
    BlockNumber, CollatorPair, Hash, HeadData, PersistedValidationData,
};

pub struct Collation {
    pub number: BlockNumber,
    pub head_data: HeadData,
}

/// Result of the [`CollatorFn`] invocation.
pub struct CollationResult {
    /// The collation that was build.
    pub collation: Collation,
    /// An optional result sender that should be informed about a successfully seconded collation.
    ///
    /// There is no guarantee that this sender is informed ever about any result, it is completely okay to just drop it.
    /// However, if it is called, it should be called with the signed statement of a parachain validator seconding the
    /// collation.
    pub result_sender: Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>,
}

pub type CollationSecondedSignal = Vec<u8>;

/// The cumulative weight of a block in a fork-choice rule.
pub type BlockWeight = u32;

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

/// Configuration for the collation generator
pub struct CollationGenerationConfig {
    /// Collator's authentication key, so it can sign things.
    pub key: CollatorPair,
    /// Collation function. See [`CollatorFn`] for more details.
    pub collator: CollatorFn,
}

impl std::fmt::Debug for CollationGenerationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CollationGenerationConfig {{ ... }}")
    }
}
