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

//! Primitives for Subspace consensus.

#![forbid(unsafe_code, missing_docs, unused_variables, unused_imports)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod digests;
pub mod inherents;
pub mod offence;

use crate::digests::{
    CompatibleDigestItem, GlobalRandomnessDescriptor, PreDigest, SaltDescriptor,
    SolutionRangeDescriptor, UpdatedSaltDescriptor,
};
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_api::{BlockT, HeaderT};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{ConsensusEngineId, RuntimeAppPublic, RuntimeDebug};
use sp_std::vec::Vec;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{Randomness, RootBlock, Salt, Sha256Hash};

/// Key type for Subspace pallet.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"sub_");

mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

/// A Subspace farmer signature.
pub type FarmerSignature = app::Signature;

/// A Subspace farmer identifier. Necessarily equivalent to the schnorrkel public key used in
/// the main Subspace module. If that ever changes, then this must, too.
pub type FarmerPublicKey = app::Public;

/// The `ConsensusEngineId` of Subspace.
const SUBSPACE_ENGINE_ID: ConsensusEngineId = *b"SUB_";

/// An equivocation proof for multiple block authorships on the same slot (i.e. double vote).
pub type EquivocationProof<H> = sp_consensus_slots::EquivocationProof<H, FarmerPublicKey>;

/// The cumulative weight of a Subspace block, i.e. sum of block weights starting
/// at this block until the genesis block.
///
/// The closer solution's tag is to the target, the heavier it is.
pub type SubspaceBlockWeight = u128;

/// An consensus log item for Subspace.
#[derive(Decode, Encode, Clone, PartialEq, Eq, RuntimeDebug)]
enum ConsensusLog {
    /// Global randomness for this block/interval.
    #[codec(index = 1)]
    GlobalRandomness(GlobalRandomnessDescriptor),
    /// Solution range for this block/era.
    #[codec(index = 3)]
    SolutionRange(SolutionRangeDescriptor),
    /// Salt for this block/eon.
    #[codec(index = 4)]
    Salt(SaltDescriptor),
    /// The eon has changed and the salt has changed because of that.
    #[codec(index = 6)]
    UpdatedSalt(UpdatedSaltDescriptor),
}

// TODO: Can we kill this too?
/// Configuration data used by the Subspace consensus engine.
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct SubspaceGenesisConfiguration {
    /// The slot duration in milliseconds for Subspace. Currently, only
    /// the value provided by this type at genesis will be used.
    ///
    /// Dynamic slot duration may be supported in the future.
    pub slot_duration: u64,

    /// A constant value that is used in the threshold calculation formula.
    /// Expressed as a rational where the first member of the tuple is the
    /// numerator and the second is the denominator. The rational should
    /// represent a value between 0 and 1.
    /// In the threshold formula calculation, `1 - c` represents the probability
    /// of a slot being empty.
    pub c: (u64, u64),
}

#[cfg(feature = "std")]
impl sp_consensus::SlotData for SubspaceGenesisConfiguration {
    fn slot_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.slot_duration)
    }

    const SLOT_KEY: &'static [u8] = b"subspace_configuration";
}

/// Verifies the equivocation proof by making sure that: both headers have
/// different hashes, are targeting the same slot, and have valid signatures by
/// the same authority.
pub fn check_equivocation_proof<H>(proof: EquivocationProof<H>) -> bool
where
    H: HeaderT,
{
    let find_pre_digest = |header: &H| -> Option<PreDigest<FarmerPublicKey>> {
        header
            .digest()
            .logs()
            .iter()
            .find_map(|log| log.as_subspace_pre_digest())
    };

    let verify_seal_signature = |mut header: H, offender: &FarmerPublicKey| {
        let seal = CompatibleDigestItem::as_subspace_seal(&header.digest_mut().pop()?)?;
        let pre_hash = header.hash();

        if !offender.verify(&pre_hash.as_ref(), &seal) {
            return None;
        }

        Some(())
    };

    let verify_proof = || {
        // we must have different headers for the equivocation to be valid
        if proof.first_header.hash() == proof.second_header.hash() {
            return None;
        }

        let first_pre_digest = find_pre_digest(&proof.first_header)?;
        let second_pre_digest = find_pre_digest(&proof.second_header)?;

        // both headers must be targeting the same slot and it must
        // be the same as the one in the proof.
        if proof.slot != first_pre_digest.slot || first_pre_digest.slot != second_pre_digest.slot {
            return None;
        }

        // both headers must have been authored by the same farmer
        if first_pre_digest.solution.public_key != second_pre_digest.solution.public_key {
            return None;
        }

        // we finally verify that the expected farmer has signed both headers and
        // that the signature is valid.
        verify_seal_signature(proof.first_header, &proof.offender)?;
        verify_seal_signature(proof.second_header, &proof.offender)?;

        Some(())
    };

    // NOTE: we isolate the verification code into an helper function that
    // returns `Option<()>` so that we can use `?` to deal with any intermediate
    // errors and discard the proof as invalid.
    verify_proof().is_some()
}

/// Subspace global randomnesses used for deriving global challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Debug, TypeInfo)]
pub struct GlobalRandomnesses {
    /// Global randomness used for deriving global challenge in current block/interval.
    pub current: Randomness,
    /// Global randomness that will be used for deriving global challenge in the next
    /// block/interval.
    pub next: Option<Randomness>,
}

/// Subspace solution ranges used for challenges.
#[derive(Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Debug, TypeInfo)]
pub struct SolutionRanges {
    /// Solution range in current block/era.
    pub current: u64,
    /// Solution range that will be used in the next block/era.
    pub next: Option<u64>,
}

impl Default for SolutionRanges {
    fn default() -> Self {
        Self {
            current: u64::MAX,
            next: None,
        }
    }
}

/// Subspace salts used for challenges.
#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub struct Salts {
    /// Salt used for challenges in current block/eon.
    pub salt: Salt,
    /// Salt used for challenges after `salt` in the next block/eon.
    pub next_salt: Option<Salt>,
}

sp_api::decl_runtime_apis! {
    /// API necessary for block authorship with Subspace.
    pub trait SubspaceApi {
        /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
        /// to the client-dependent transaction confirmation depth `k`).
        fn confirmation_depth_k() -> <<Block as BlockT>::Header as HeaderT>::Number;

        /// The size of data in one piece (in bytes).
        fn record_size() -> u32;

        /// Recorded history is encoded and plotted in segments of this size (in bytes).
        fn recorded_history_segment_size() -> u32;

        /// Return the genesis configuration for Subspace. The configuration is only read on genesis.
        fn configuration() -> SubspaceGenesisConfiguration;

        /// Global randomnesses used for deriving global challenges.
        fn global_randomnesses() -> GlobalRandomnesses;

        /// Solution ranges.
        fn solution_ranges() -> SolutionRanges;

        /// Subspace salts used for challenges.
        fn salts() -> Salts;

        /// Submits an unsigned extrinsic to report an equivocation. The caller must provide the
        /// equivocation proof. The extrinsic will be unsigned and should only be accepted for local
        /// authorship (not to be broadcast to the network). This method returns `None` when
        /// creation of the extrinsic fails, e.g. if equivocation reporting is disabled for the
        /// given runtime (i.e. this method is hardcoded to return `None`). Only useful in an
        /// offchain context.
        fn submit_report_equivocation_extrinsic(
            equivocation_proof: EquivocationProof<Block::Header>,
        ) -> Option<()>;

        /// Check if `farmer_public_key` is in block list (due to equivocation)
        fn is_in_block_list(farmer_public_key: &FarmerPublicKey) -> bool;

        /// Get the merkle tree root of records for specified segment index
        fn records_root(segment_index: u64) -> Option<Sha256Hash>;

        /// Returns `Vec<RootBlock>` if a given extrinsic has them.
        fn extract_root_blocks(ext: &Block::Extrinsic) -> Option<Vec<RootBlock>>;

        /// Extract block object mapping for a given block
        fn extract_block_object_mapping(block: Block) -> BlockObjectMapping;
    }
}
