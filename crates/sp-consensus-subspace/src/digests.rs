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

use crate::{ConsensusLog, FarmerSignature, SubspaceBlockWeight, SUBSPACE_ENGINE_ID};
use codec::{Decode, Encode};
use sp_consensus_slots::Slot;
use sp_core::crypto::UncheckedFrom;
use sp_runtime::generic::DigestItemRef;
use sp_runtime::{DigestItem, RuntimeDebug};
use subspace_core_primitives::{LocalChallenge, Piece, Randomness, Salt, Signature, Tag};

/// Farmer solution for slot challenge.
#[derive(Clone, RuntimeDebug, Encode, Decode)]
pub struct Solution<AccountId> {
    /// Public key of the farmer that created the solution
    pub public_key: AccountId,
    /// Index of encoded piece
    pub piece_index: u64,
    /// Encoding
    pub encoding: Piece,
    /// Signature of the tag
    pub signature: Signature,
    /// Local challenge derived from global challenge using farmer's identity.
    pub local_challenge: LocalChallenge,
    /// Tag (hmac of encoding and salt)
    pub tag: Tag,
}

impl<AccountId> Solution<AccountId>
where
    AccountId: UncheckedFrom<[u8; 32]>,
{
    /// Dummy solution for the genesis block
    pub fn genesis_solution() -> Self {
        Self {
            public_key: AccountId::unchecked_from([0u8; 32]),
            piece_index: 0u64,
            encoding: Piece::default(),
            signature: Signature::default(),
            local_challenge: LocalChallenge::default(),
            tag: Tag::default(),
        }
    }
}

/// A Subspace pre-runtime digest. This contains all data required to validate a block and for the
/// Subspace runtime module.
#[derive(Clone, RuntimeDebug, Encode, Decode)]
pub struct PreDigest<AccountId> {
    /// Slot
    pub slot: Slot,
    /// Solution (includes PoR)
    pub solution: Solution<AccountId>,
}

impl<AccountId> PreDigest<AccountId> {
    /// Returns the weight _added_ by this digest, not the cumulative weight
    /// of the chain.
    pub fn added_weight(&self) -> SubspaceBlockWeight {
        let target = u64::from_be_bytes(self.solution.local_challenge.derive_target());
        let tag = u64::from_be_bytes(self.solution.tag);
        let diff = target.wrapping_sub(tag);
        let diff2 = tag.wrapping_sub(target);
        // Find smaller diff between 2 directions.
        let bidirectional_diff = diff.min(diff2);
        u128::from(u64::MAX - bidirectional_diff)
    }
}

/// Information about the global randomness for the block.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct GlobalRandomnessDescriptor {
    /// Global randomness used for deriving global slot challenges.
    pub global_randomness: Randomness,
}

/// Information about the solution range for the block.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct SolutionRangeDescriptor {
    /// Solution range used for challenges.
    pub solution_range: u64,
}

/// Salt for the block.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct SaltDescriptor {
    /// Salt used with challenges.
    pub salt: Salt,
}

/// A digest item which is usable with Subspace consensus.
pub trait CompatibleDigestItem: Sized {
    /// Construct a digest item which contains a Subspace pre-digest.
    fn subspace_pre_digest<AccountId: Encode>(pre_digest: &PreDigest<AccountId>) -> Self;

    /// If this item is an Subspace pre-digest, return it.
    fn as_subspace_pre_digest<AccountId: Decode>(&self) -> Option<PreDigest<AccountId>>;

    /// Construct a digest item which contains a Subspace seal.
    fn subspace_seal(signature: FarmerSignature) -> Self;

    /// If this item is a Subspace signature, return the signature.
    fn as_subspace_seal(&self) -> Option<FarmerSignature>;

    /// Construct a digest item which contains a global randomness descriptor.
    fn global_randomness_descriptor(global_randomness: GlobalRandomnessDescriptor) -> Self;

    /// If this item is a Subspace global randomness descriptor, return it.
    fn as_global_randomness_descriptor(&self) -> Option<GlobalRandomnessDescriptor>;

    /// Construct a digest item which contains a solution range descriptor.
    fn solution_range_descriptor(solution_range: SolutionRangeDescriptor) -> Self;

    /// If this item is a Subspace solution range descriptor, return it.
    fn as_solution_range_descriptor(&self) -> Option<SolutionRangeDescriptor>;

    /// Construct a digest item which contains a salt descriptor.
    fn salt_descriptor(salt: SaltDescriptor) -> Self;

    /// If this item is a Subspace salt descriptor, return it.
    fn as_salt_descriptor(&self) -> Option<SaltDescriptor>;
}

impl CompatibleDigestItem for DigestItem {
    fn subspace_pre_digest<AccountId: Encode>(pre_digest: &PreDigest<AccountId>) -> Self {
        Self::PreRuntime(SUBSPACE_ENGINE_ID, pre_digest.encode())
    }

    fn as_subspace_pre_digest<AccountId: Decode>(&self) -> Option<PreDigest<AccountId>> {
        self.pre_runtime_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn subspace_seal(signature: FarmerSignature) -> Self {
        Self::Seal(SUBSPACE_ENGINE_ID, signature.encode())
    }

    fn as_subspace_seal(&self) -> Option<FarmerSignature> {
        self.seal_try_to(&SUBSPACE_ENGINE_ID)
    }

    /// Construct a digest item which contains a global randomness descriptor.
    fn global_randomness_descriptor(global_randomness: GlobalRandomnessDescriptor) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::GlobalRandomness(global_randomness).encode(),
        )
    }

    /// If this item is a Subspace global randomness descriptor, return it.
    fn as_global_randomness_descriptor(&self) -> Option<GlobalRandomnessDescriptor> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::GlobalRandomness(global_randomness) = c {
                Some(global_randomness)
            } else {
                None
            }
        })
    }

    fn solution_range_descriptor(solution_range: SolutionRangeDescriptor) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::SolutionRange(solution_range).encode(),
        )
    }

    fn as_solution_range_descriptor(&self) -> Option<SolutionRangeDescriptor> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::SolutionRange(solution_range) = c {
                Some(solution_range)
            } else {
                None
            }
        })
    }

    fn salt_descriptor(salt: SaltDescriptor) -> Self {
        Self::Consensus(SUBSPACE_ENGINE_ID, ConsensusLog::Salt(salt).encode())
    }

    fn as_salt_descriptor(&self) -> Option<SaltDescriptor> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::Salt(salt) = c {
                Some(salt)
            } else {
                None
            }
        })
    }
}

/// A digest item which is usable with Subspace consensus.
pub trait CompatibleDigestItemRef: Sized {
    /// If this item is an Subspace pre-digest, return it.
    fn as_subspace_pre_digest<AccountId: Decode>(&self) -> Option<PreDigest<AccountId>>;

    /// Construct a digest item which contains a Subspace seal.
    fn as_subspace_seal(&self) -> Option<FarmerSignature>;
}

impl CompatibleDigestItemRef for DigestItemRef<'_> {
    fn as_subspace_pre_digest<AccountId: Decode>(&self) -> Option<PreDigest<AccountId>> {
        self.pre_runtime_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn as_subspace_seal(&self) -> Option<FarmerSignature> {
        self.seal_try_to(&SUBSPACE_ENGINE_ID)
    }
}
