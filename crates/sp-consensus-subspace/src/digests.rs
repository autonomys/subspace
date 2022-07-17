// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
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

//! Private implementation details of Subspace consensus digests.

use crate::{ConsensusLog, FarmerPublicKey, FarmerSignature, SUBSPACE_ENGINE_ID};
use codec::{Decode, Encode};
use log::trace;
use sp_api::HeaderT;
use sp_consensus_slots::Slot;
use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::Zero;
use sp_runtime::DigestItem;
use subspace_core_primitives::{Randomness, Salt, Solution};

/// A Subspace pre-runtime digest. This contains all data required to validate a block and for the
/// Subspace runtime module.
#[derive(Debug, Clone, Encode, Decode)]
pub struct PreDigest<PublicKey, RewardAddress> {
    /// Slot
    pub slot: Slot,
    /// Solution (includes PoR)
    pub solution: Solution<PublicKey, RewardAddress>,
}

/// A digest item which is usable with Subspace consensus.
pub trait CompatibleDigestItem: Sized {
    /// Construct a digest item which contains a Subspace pre-digest.
    fn subspace_pre_digest<AccountId: Encode>(
        pre_digest: &PreDigest<FarmerPublicKey, AccountId>,
    ) -> Self;

    /// If this item is an Subspace pre-digest, return it.
    fn as_subspace_pre_digest<AccountId: Decode>(
        &self,
    ) -> Option<PreDigest<FarmerPublicKey, AccountId>>;

    /// Construct a digest item which contains a Subspace seal.
    fn subspace_seal(signature: FarmerSignature) -> Self;

    /// If this item is a Subspace signature, return the signature.
    fn as_subspace_seal(&self) -> Option<FarmerSignature>;

    /// Construct a digest item which contains a global randomness.
    fn global_randomness(global_randomness: Randomness) -> Self;

    /// If this item is a Subspace global randomness, return it.
    fn as_global_randomness(&self) -> Option<Randomness>;

    /// Construct a digest item which contains a solution range.
    fn solution_range(solution_range: u64) -> Self;

    /// If this item is a Subspace solution range, return it.
    fn as_solution_range(&self) -> Option<u64>;

    /// Construct a digest item which contains a salt.
    fn salt(salt: Salt) -> Self;

    /// If this item is a Subspace salt, return it.
    fn as_salt(&self) -> Option<Salt>;
}

impl CompatibleDigestItem for DigestItem {
    fn subspace_pre_digest<RewardAddress: Encode>(
        pre_digest: &PreDigest<FarmerPublicKey, RewardAddress>,
    ) -> Self {
        Self::PreRuntime(SUBSPACE_ENGINE_ID, pre_digest.encode())
    }

    fn as_subspace_pre_digest<RewardAddress: Decode>(
        &self,
    ) -> Option<PreDigest<FarmerPublicKey, RewardAddress>> {
        self.pre_runtime_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn subspace_seal(signature: FarmerSignature) -> Self {
        Self::Seal(SUBSPACE_ENGINE_ID, signature.encode())
    }

    fn as_subspace_seal(&self) -> Option<FarmerSignature> {
        self.seal_try_to(&SUBSPACE_ENGINE_ID)
    }

    /// Construct a digest item which contains a global randomness.
    fn global_randomness(global_randomness: Randomness) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::GlobalRandomness(global_randomness).encode(),
        )
    }

    /// If this item is a Subspace global randomness, return it.
    fn as_global_randomness(&self) -> Option<Randomness> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::GlobalRandomness(global_randomness) = c {
                Some(global_randomness)
            } else {
                None
            }
        })
    }

    fn solution_range(solution_range: u64) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::SolutionRange(solution_range).encode(),
        )
    }

    fn as_solution_range(&self) -> Option<u64> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::SolutionRange(solution_range) = c {
                Some(solution_range)
            } else {
                None
            }
        })
    }

    fn salt(salt: Salt) -> Self {
        Self::Consensus(SUBSPACE_ENGINE_ID, ConsensusLog::Salt(salt).encode())
    }

    fn as_salt(&self) -> Option<Salt> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::Salt(salt) = c {
                Some(salt)
            } else {
                None
            }
        })
    }
}

/// Digest error
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
    /// Multiple Subspace global randomness digests
    #[cfg_attr(
        feature = "thiserror",
        error("Multiple Subspace global randomness digests, rejecting!")
    )]
    MultipleGlobalRandomnessDigests,
    /// Multiple Subspace solution range digests
    #[cfg_attr(
        feature = "thiserror",
        error("Multiple Subspace solution range digests, rejecting!")
    )]
    MultipleSolutionRangeDigests,
    /// Multiple Subspace salt digests
    #[cfg_attr(
        feature = "thiserror",
        error("Multiple Subspace salt digests, rejecting!")
    )]
    MultipleSaltDigests,
    /// Multiple Subspace pre-runtime digests
    #[cfg_attr(
        feature = "thiserror",
        error("Multiple Subspace pre-runtime digests, rejecting!")
    )]
    MultiplePreRuntimeDigests,
    /// No Subspace pre-runtime digest found
    #[cfg_attr(feature = "thiserror", error("No Subspace pre-runtime digest found"))]
    NoPreRuntimeDigest,
}

#[cfg(feature = "std")]
impl From<Error> for String {
    fn from(error: Error) -> String {
        error.to_string()
    }
}

/// Extract the Subspace global randomness from the given header.
pub fn extract_global_randomness<Header>(header: &Header) -> Result<Option<Randomness>, Error>
where
    Header: HeaderT,
{
    let mut maybe_global_randomness = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for global randomness digest.", log);
        match (
            log.as_global_randomness(),
            maybe_global_randomness.is_some(),
        ) {
            (Some(_), true) => return Err(Error::MultipleGlobalRandomnessDigests),
            (Some(global_randomness), false) => maybe_global_randomness = Some(global_randomness),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(maybe_global_randomness)
}

/// Extract the Subspace solution range from the given header.
pub fn extract_solution_range<Header>(header: &Header) -> Result<Option<u64>, Error>
where
    Header: HeaderT,
{
    let mut maybe_solution_range = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for solution range digest.", log);
        match (log.as_solution_range(), maybe_solution_range.is_some()) {
            (Some(_), true) => return Err(Error::MultipleSolutionRangeDigests),
            (Some(solution_range), false) => maybe_solution_range = Some(solution_range),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(maybe_solution_range)
}

/// Extract the Subspace salt from the given header.
pub fn extract_salt<Header>(header: &Header) -> Result<Option<Salt>, Error>
where
    Header: HeaderT,
{
    let mut maybe_salt = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for salt digest.", log);
        match (log.as_salt(), maybe_salt.is_some()) {
            (Some(_), true) => return Err(Error::MultipleSaltDigests),
            (Some(salt), false) => maybe_salt = Some(salt),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(maybe_salt)
}

/// Extract the Subspace pre digest from the given header. Pre-runtime digests are mandatory, the
/// function will return `Err` if none is found.
pub fn extract_pre_digest<Header>(
    header: &Header,
) -> Result<PreDigest<FarmerPublicKey, FarmerPublicKey>, Error>
where
    Header: HeaderT,
{
    // genesis block doesn't contain a pre digest so let's generate a
    // dummy one to not break any invariants in the rest of the code
    if header.number().is_zero() {
        return Ok(PreDigest {
            slot: Slot::from(0),
            solution: Solution::genesis_solution(
                FarmerPublicKey::unchecked_from([0u8; 32]),
                FarmerPublicKey::unchecked_from([0u8; 32]),
            ),
        });
    }

    let mut pre_digest = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for pre runtime digest", log);
        match (log.as_subspace_pre_digest(), pre_digest.is_some()) {
            (Some(_), true) => return Err(Error::MultiplePreRuntimeDigests),
            (None, _) => trace!(target: "subspace", "Ignoring digest not meant for us"),
            (s, false) => pre_digest = s,
        }
    }
    pre_digest.ok_or(Error::NoPreRuntimeDigest)
}
