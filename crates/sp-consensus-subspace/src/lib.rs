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

#![forbid(unsafe_code, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate core;

pub mod digests;
pub mod inherents;
pub mod offence;
#[cfg(test)]
mod tests;

use crate::digests::{CompatibleDigestItem, PreDigest};
use codec::{Decode, Encode, MaxEncodedLen};
use core::time::Duration;
use scale_info::TypeInfo;
use schnorrkel::context::SigningContext;
use sp_api::{BlockT, HeaderT};
use sp_consensus_slots::Slot;
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
use sp_io::hashing;
use sp_runtime::{ConsensusEngineId, DigestItem};
use sp_std::vec::Vec;
use subspace_core_primitives::{
    BlockNumber, PublicKey, Randomness, RecordsRoot, RewardSignature, RootBlock, SegmentIndex,
    Solution, SolutionRange, PUBLIC_KEY_LENGTH, REWARD_SIGNATURE_LENGTH,
};
use subspace_solving::REWARD_SIGNING_CONTEXT;
use subspace_verification::{check_reward_signature, verify_solution, Error, VerifySolutionParams};

/// Key type for Subspace pallet.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"sub_");

// TODO: Remove this and replace with simple encodable wrappers of Schnorrkel's types
mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

/// A Subspace farmer signature.
pub type FarmerSignature = app::Signature;

impl From<&FarmerSignature> for RewardSignature {
    fn from(signature: &FarmerSignature) -> Self {
        RewardSignature::from(
            TryInto::<[u8; REWARD_SIGNATURE_LENGTH]>::try_into(AsRef::<[u8]>::as_ref(signature))
                .expect("Always correct length; qed"),
        )
    }
}

/// A Subspace farmer identifier. Necessarily equivalent to the schnorrkel public key used in
/// the main Subspace module. If that ever changes, then this must, too.
pub type FarmerPublicKey = app::Public;

impl From<&FarmerPublicKey> for PublicKey {
    fn from(pub_key: &FarmerPublicKey) -> Self {
        PublicKey::from(
            TryInto::<[u8; PUBLIC_KEY_LENGTH]>::try_into(AsRef::<[u8]>::as_ref(pub_key))
                .expect("Always correct length; qed"),
        )
    }
}

/// The `ConsensusEngineId` of Subspace.
const SUBSPACE_ENGINE_ID: ConsensusEngineId = *b"SUB_";

/// An equivocation proof for multiple block authorships on the same slot (i.e. double vote).
pub type EquivocationProof<Header> = sp_consensus_slots::EquivocationProof<Header, FarmerPublicKey>;

/// An consensus log item for Subspace.
#[derive(Debug, Decode, Encode, Clone, PartialEq, Eq)]
enum ConsensusLog {
    /// Global randomness for this block/interval.
    #[codec(index = 0)]
    GlobalRandomness(Randomness),
    /// Solution range for this block/era.
    #[codec(index = 1)]
    SolutionRange(SolutionRange),
    /// Global randomness for next block/interval.
    #[codec(index = 2)]
    NextGlobalRandomness(Randomness),
    /// Solution range for next block/era.
    #[codec(index = 3)]
    NextSolutionRange(SolutionRange),
    /// Records roots.
    #[codec(index = 4)]
    RecordsRoot((SegmentIndex, RecordsRoot)),
    /// Enable Solution range adjustment and Override Solution Range.
    #[codec(index = 5)]
    EnableSolutionRangeAdjustmentAndOverride(Option<SolutionRange>),
    /// Root plot public key was updated.
    #[codec(index = 6)]
    RootPlotPublicKeyUpdate(Option<FarmerPublicKey>),
}

/// Farmer vote.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub enum Vote<Number, Hash, RewardAddress> {
    /// V0 of the farmer vote.
    V0 {
        /// Height at which vote was created.
        ///
        /// Equivalent to block number, but this is not a block.
        height: Number,
        /// Hash of the block on top of which vote was created.
        parent_hash: Hash,
        /// Slot at which vote was created.
        slot: Slot,
        /// Solution (includes PoR).
        solution: Solution<FarmerPublicKey, RewardAddress>,
    },
}

impl<Number, Hash, RewardAddress> Vote<Number, Hash, RewardAddress>
where
    Number: Encode,
    Hash: Encode,
    RewardAddress: Encode,
{
    /// Solution contained within.
    pub fn solution(&self) -> &Solution<FarmerPublicKey, RewardAddress> {
        let Self::V0 { solution, .. } = self;
        solution
    }

    /// Hash of the vote, used for signing and verifying signature.
    pub fn hash(&self) -> H256 {
        hashing::blake2_256(&self.encode()).into()
    }
}

/// Signed farmer vote.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub struct SignedVote<Number, Hash, RewardAddress> {
    /// Farmer vote.
    pub vote: Vote<Number, Hash, RewardAddress>,
    /// Signature.
    pub signature: FarmerSignature,
}

fn find_pre_digest<Header, RewardAddress>(
    header: &Header,
) -> Option<PreDigest<FarmerPublicKey, RewardAddress>>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    header
        .digest()
        .logs()
        .iter()
        .find_map(|log| log.as_subspace_pre_digest())
}

fn is_seal_signature_valid<Header>(mut header: Header, offender: &FarmerPublicKey) -> bool
where
    Header: HeaderT,
{
    let seal = match header.digest_mut().pop() {
        Some(seal) => seal,
        None => {
            return false;
        }
    };
    let seal = match seal.as_subspace_seal() {
        Some(seal) => seal,
        None => {
            return false;
        }
    };
    let pre_hash = header.hash();

    check_reward_signature(
        pre_hash.as_ref(),
        &RewardSignature::from(&seal),
        &PublicKey::from(offender),
        &schnorrkel::signing_context(REWARD_SIGNING_CONTEXT),
    )
    .is_ok()
}

/// Verifies the equivocation proof by making sure that: both headers have
/// different hashes, are targeting the same slot, and have valid signatures by
/// the same authority.
pub fn is_equivocation_proof_valid<Header, RewardAddress>(proof: EquivocationProof<Header>) -> bool
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    // we must have different headers for the equivocation to be valid
    if proof.first_header.hash() == proof.second_header.hash() {
        return false;
    }

    let first_pre_digest = match find_pre_digest::<_, RewardAddress>(&proof.first_header) {
        Some(pre_digest) => pre_digest,
        None => {
            return false;
        }
    };
    let second_pre_digest = match find_pre_digest::<_, RewardAddress>(&proof.second_header) {
        Some(pre_digest) => pre_digest,
        None => {
            return false;
        }
    };

    // both headers must be targeting the same slot and it must
    // be the same as the one in the proof.
    if !(proof.slot == first_pre_digest.slot && proof.slot == second_pre_digest.slot) {
        return false;
    }

    // both headers must have the same sector index
    if first_pre_digest.solution.sector_index != second_pre_digest.solution.sector_index {
        return false;
    }

    // both headers must have been authored by the same farmer
    if first_pre_digest.solution.public_key != second_pre_digest.solution.public_key {
        return false;
    }

    // we finally verify that the expected farmer has signed both headers and
    // that the signature is valid.
    is_seal_signature_valid(proof.first_header, &proof.offender)
        && is_seal_signature_valid(proof.second_header, &proof.offender)
}

/// Subspace global randomnesses used for deriving global challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct GlobalRandomnesses {
    /// Global randomness used for deriving global challenge in current block/interval.
    pub current: Randomness,
    /// Global randomness that will be used for deriving global challenge in the next
    /// block/interval.
    pub next: Option<Randomness>,
}

/// Subspace solution ranges used for challenges.
#[derive(Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct SolutionRanges {
    /// Solution range in current block/era.
    pub current: u64,
    /// Solution range that will be used in the next block/era.
    pub next: Option<u64>,
    /// Voting solution range in current block/era.
    pub voting_current: u64,
    /// Voting solution range that will be used in the next block/era.
    pub voting_next: Option<u64>,
}

impl Default for SolutionRanges {
    fn default() -> Self {
        Self {
            current: u64::MAX,
            next: None,
            voting_current: u64::MAX,
            voting_next: None,
        }
    }
}

// TODO: Likely add more stuff here
/// Subspace blockchain constants.
#[derive(Debug, Encode, Decode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, TypeInfo)]
pub enum ChainConstants {
    /// V0 of the chain constants.
    V0 {
        /// Depth `K` after which a block enters the recorded history.
        confirmation_depth_k: BlockNumber,
        /// Number of blocks between global randomness updates.
        global_randomness_interval: BlockNumber,
        /// Era duration in blocks.
        era_duration: BlockNumber,
        /// Slot probability.
        slot_probability: (u64, u64),
    },
}

impl ChainConstants {
    /// Depth `K` after which a block enters the recorded history.
    pub fn confirmation_depth_k(&self) -> BlockNumber {
        let Self::V0 {
            confirmation_depth_k,
            ..
        } = self;
        *confirmation_depth_k
    }

    /// Number of blocks between global randomness updates.
    pub fn global_randomness_interval(&self) -> BlockNumber {
        let Self::V0 {
            global_randomness_interval,
            ..
        } = self;
        *global_randomness_interval
    }

    /// Era duration in blocks.
    pub fn era_duration(&self) -> BlockNumber {
        let Self::V0 { era_duration, .. } = self;
        *era_duration
    }

    /// Slot probability.
    pub fn slot_probability(&self) -> (u64, u64) {
        let Self::V0 {
            slot_probability, ..
        } = self;
        *slot_probability
    }
}

sp_api::decl_runtime_apis! {
    /// API necessary for block authorship with Subspace.
    pub trait SubspaceApi<RewardAddress: Encode + Decode> {
        /// The slot duration in milliseconds for Subspace.
        fn slot_duration() -> Duration;

        /// Global randomnesses used for deriving global challenges.
        fn global_randomnesses() -> GlobalRandomnesses;

        /// Solution ranges.
        fn solution_ranges() -> SolutionRanges;

        /// Submits an unsigned extrinsic to report an equivocation. The caller must provide the
        /// equivocation proof. The extrinsic will be unsigned and should only be accepted for local
        /// authorship (not to be broadcast to the network). This method returns `None` when
        /// creation of the extrinsic fails, e.g. if equivocation reporting is disabled for the
        /// given runtime (i.e. this method is hardcoded to return `None`). Only useful in an
        /// offchain context.
        fn submit_report_equivocation_extrinsic(
            equivocation_proof: EquivocationProof<Block::Header>,
        ) -> Option<()>;

        /// Submit farmer vote vote that is essentially a header with bigger solution range than
        /// acceptable for block authoring. Only useful in an offchain context.
        fn submit_vote_extrinsic(
            signed_vote: SignedVote<
                <<Block as BlockT>::Header as HeaderT>::Number,
                Block::Hash,
                RewardAddress,
            >,
        );

        /// Check if `farmer_public_key` is in block list (due to equivocation)
        fn is_in_block_list(farmer_public_key: &FarmerPublicKey) -> bool;

        /// Total number of pieces in a blockchain
        fn total_pieces() -> u64;

        /// Get the merkle tree root of records for specified segment index
        fn records_root(segment_index: SegmentIndex) -> Option<RecordsRoot>;

        /// Returns `Vec<RootBlock>` if a given extrinsic has them.
        fn extract_root_blocks(ext: &Block::Extrinsic) -> Option<Vec<RootBlock>>;

        /// Returns root plot public key in case block authoring is restricted.
        fn root_plot_public_key() -> Option<FarmerPublicKey>;

        /// Whether solution range adjustment is enabled.
        fn should_adjust_solution_range() -> bool;

        /// Get Subspace blockchain constants
        fn chain_constants() -> ChainConstants;
    }
}

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError<Header: HeaderT> {
    /// No Subspace pre-runtime digest found
    #[cfg_attr(feature = "thiserror", error("No Subspace pre-runtime digest found"))]
    NoPreRuntimeDigest,
    /// Header has a bad seal
    #[cfg_attr(feature = "thiserror", error("Header {0:?} has a bad seal"))]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[cfg_attr(feature = "thiserror", error("Header {0:?} is unsealed"))]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[cfg_attr(feature = "thiserror", error("Bad reward signature on {0:?}"))]
    BadRewardSignature(Header::Hash),
    /// Verification error
    #[cfg_attr(
        feature = "thiserror",
        error("Verification error on slot {0:?}: {1:?}")
    )]
    VerificationError(Slot, Error),
}

/// A header which has been checked
pub enum CheckedHeader<H, S> {
    /// A header which has slot in the future. this is the full header (not stripped)
    /// and the slot in which it should be processed.
    Deferred(H, Slot),
    /// A header which is fully checked, including signature. This is the pre-header
    /// accompanied by the seal components.
    ///
    /// Includes the digest item that encoded the seal.
    Checked(H, S),
}

/// Subspace verification parameters
pub struct VerificationParams<'a, Header>
where
    Header: HeaderT + 'a,
{
    /// The header being verified.
    pub header: Header,
    /// The slot number of the current time.
    pub slot_now: Slot,
    /// Parameters for solution verification
    pub verify_solution_params: VerifySolutionParams<'a>,
    /// Signing context for reward signature
    pub reward_signing_context: &'a SigningContext,
}

/// Information from verified header
pub struct VerifiedHeaderInfo<RewardAddress> {
    /// Pre-digest
    pub pre_digest: PreDigest<FarmerPublicKey, RewardAddress>,
    /// Seal (signature)
    pub seal: DigestItem,
}

/// Check a header has been signed correctly and whether solution is correct. If the slot is too far
/// in the future, an error will be returned. If successful, returns the pre-header and the digest
/// item containing the seal.
///
/// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This is
/// required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
///
/// `pre_digest` argument is optional in case it is available to avoid doing the work of extracting
/// it from the header twice.
pub fn check_header<Header, RewardAddress>(
    params: VerificationParams<Header>,
    pre_digest: Option<PreDigest<FarmerPublicKey, RewardAddress>>,
) -> Result<CheckedHeader<Header, VerifiedHeaderInfo<RewardAddress>>, VerificationError<Header>>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    let VerificationParams {
        mut header,
        slot_now,
        verify_solution_params,
        reward_signing_context,
    } = params;

    let pre_digest = match pre_digest {
        Some(pre_digest) => pre_digest,
        None => find_pre_digest::<Header, RewardAddress>(&header)
            .ok_or(VerificationError::NoPreRuntimeDigest)?,
    };
    let slot = pre_digest.slot;

    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| VerificationError::HeaderUnsealed(header.hash()))?;

    let signature = seal
        .as_subspace_seal()
        .ok_or_else(|| VerificationError::HeaderBadSeal(header.hash()))?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    // Verify that block is signed properly
    if check_reward_signature(
        pre_hash.as_ref(),
        &RewardSignature::from(&signature),
        &PublicKey::from(&pre_digest.solution.public_key),
        reward_signing_context,
    )
    .is_err()
    {
        return Err(VerificationError::BadRewardSignature(pre_hash));
    }

    // Verify that solution is valid
    verify_solution(&pre_digest.solution, slot.into(), verify_solution_params)
        .map_err(|error| VerificationError::VerificationError(slot, error))?;

    Ok(CheckedHeader::Checked(
        header,
        VerifiedHeaderInfo { pre_digest, seal },
    ))
}
