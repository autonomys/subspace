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
#![feature(let_chains)]

extern crate alloc;

pub mod digests;
pub mod inherents;
pub mod offence;
#[cfg(test)]
mod tests;

use crate::digests::{CompatibleDigestItem, PreDigest};
use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_consensus_slots::{Slot, SlotDuration};
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
use sp_io::hashing;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::{ConsensusEngineId, Justification};
use sp_runtime_interface::pass_by::PassBy;
use sp_runtime_interface::{pass_by, runtime_interface};
use sp_std::num::NonZeroU32;
#[cfg(feature = "std")]
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Blake3Hash, BlockHash, BlockNumber, HistorySize, PotCheckpoints, PotOutput, PotSeed, PublicKey,
    RewardSignature, SegmentCommitment, SegmentHeader, SegmentIndex, SlotNumber, Solution,
    SolutionRange, REWARD_SIGNATURE_LENGTH, REWARD_SIGNING_CONTEXT,
};
#[cfg(feature = "std")]
use subspace_proof_of_space::chia::ChiaTable;
#[cfg(feature = "std")]
use subspace_proof_of_space::shim::ShimTable;
#[cfg(feature = "std")]
use subspace_proof_of_space::PosTableType;
#[cfg(feature = "std")]
use subspace_proof_of_space::Table;
use subspace_verification::{check_reward_signature, VerifySolutionParams};

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
    #[inline]
    fn from(signature: &FarmerSignature) -> Self {
        RewardSignature::from(
            TryInto::<[u8; REWARD_SIGNATURE_LENGTH]>::try_into(AsRef::<[u8]>::as_ref(signature))
                .expect("Always correct length; qed"),
        )
    }
}

/// The `ConsensusEngineId` of Subspace.
const SUBSPACE_ENGINE_ID: ConsensusEngineId = *b"SUB_";

/// Subspace justification
#[derive(Debug, Clone, Encode, Decode, TypeInfo)]
pub enum SubspaceJustification {
    /// Proof of time checkpoints that were not seen before
    #[codec(index = 0)]
    PotCheckpoints {
        /// Proof of time seed, the input for computing checkpoints
        seed: PotSeed,
        /// Proof of time checkpoints from after future proof of parent block to current block's
        /// future proof (inclusive)
        checkpoints: Vec<PotCheckpoints>,
    },
}

impl From<SubspaceJustification> for Justification {
    #[inline]
    fn from(justification: SubspaceJustification) -> Self {
        (SUBSPACE_ENGINE_ID, justification.encode())
    }
}

impl SubspaceJustification {
    /// Try to decode Subspace justification from generic justification.
    ///
    /// `None` means this is not a Subspace justification.
    pub fn try_from_justification(
        (consensus_engine_id, encoded_justification): &Justification,
    ) -> Option<Result<Self, codec::Error>> {
        (*consensus_engine_id == SUBSPACE_ENGINE_ID)
            .then(|| Self::decode(&mut encoded_justification.as_slice()))
    }

    /// Returns `true` if justification must be archived, implies that it is canonical
    pub fn must_be_archived(&self) -> bool {
        match self {
            SubspaceJustification::PotCheckpoints { .. } => true,
        }
    }
}

/// An equivocation proof for multiple block authorships on the same slot (i.e. double vote).
pub type EquivocationProof<Header> = sp_consensus_slots::EquivocationProof<Header, PublicKey>;

/// Next slot input for proof of time evaluation
#[derive(Debug, Copy, Clone, PartialEq, Eq, Decode, Encode, TypeInfo, MaxEncodedLen)]
pub struct PotNextSlotInput {
    /// Slot
    pub slot: Slot,
    /// Slot iterations for this slot
    pub slot_iterations: NonZeroU32,
    /// Seed for this slot
    pub seed: PotSeed,
}

impl PotNextSlotInput {
    /// Derive next slot input while taking parameters change into account.
    ///
    /// NOTE: `base_slot_iterations` doesn't have to be parent block, just something that is after
    /// prior parameters change (if any) took effect, in most cases this value corresponds to parent
    /// block's slot.
    pub fn derive(
        base_slot_iterations: NonZeroU32,
        parent_slot: Slot,
        parent_output: PotOutput,
        pot_parameters_change: &Option<PotParametersChange>,
    ) -> Self {
        let next_slot = parent_slot + Slot::from(1);
        let slot_iterations;
        let seed;

        // The change to number of iterations might have happened before `next_slot`
        if let Some(parameters_change) = pot_parameters_change
            && parameters_change.slot <= next_slot
        {
            slot_iterations = parameters_change.slot_iterations;
            // Only if entropy injection happens exactly on next slot we need to mix it in
            if parameters_change.slot == next_slot {
                seed = parent_output.seed_with_entropy(&parameters_change.entropy);
            } else {
                seed = parent_output.seed();
            }
        } else {
            slot_iterations = base_slot_iterations;
            seed = parent_output.seed();
        }

        PotNextSlotInput {
            slot: next_slot,
            slot_iterations,
            seed,
        }
    }
}

/// Change of parameters to apply to PoT chain
#[derive(Debug, Copy, Clone, PartialEq, Eq, Decode, Encode, TypeInfo, MaxEncodedLen)]
pub struct PotParametersChange {
    /// At which slot change of parameters takes effect
    pub slot: Slot,
    /// New number of slot iterations
    pub slot_iterations: NonZeroU32,
    /// Entropy that should be injected at this time
    // TODO: Reconsider if the type is correct here
    pub entropy: Blake3Hash,
}

/// An consensus log item for Subspace.
#[derive(Debug, Decode, Encode, Clone, PartialEq, Eq)]
enum ConsensusLog {
    /// Number of iterations for proof of time per slot, corresponds to slot that directly follows
    /// parent block's slot and can change before slot for which block is produced.
    #[codec(index = 0)]
    PotSlotIterations(NonZeroU32),
    /// Solution range for this block/era.
    #[codec(index = 1)]
    SolutionRange(SolutionRange),
    /// Change of parameters to apply to PoT chain.
    #[codec(index = 2)]
    PotParametersChange(PotParametersChange),
    /// Solution range for next block/era.
    #[codec(index = 3)]
    NextSolutionRange(SolutionRange),
    /// Segment commitments.
    #[codec(index = 4)]
    SegmentCommitment((SegmentIndex, SegmentCommitment)),
    /// Enable Solution range adjustment and Override Solution Range.
    #[codec(index = 5)]
    EnableSolutionRangeAdjustmentAndOverride(Option<SolutionRange>),
    /// Root plot public key was updated.
    #[codec(index = 6)]
    RootPlotPublicKeyUpdate(Option<PublicKey>),
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
        solution: Solution<RewardAddress>,
        /// Proof of time for this slot
        proof_of_time: PotOutput,
        /// Future proof of time
        future_proof_of_time: PotOutput,
    },
}

impl<Number, Hash, RewardAddress> Vote<Number, Hash, RewardAddress>
where
    Number: Encode,
    Hash: Encode,
    RewardAddress: Encode,
{
    /// Solution contained within.
    pub fn solution(&self) -> &Solution<RewardAddress> {
        let Self::V0 { solution, .. } = self;
        solution
    }

    /// Slot at which vote was created.
    pub fn slot(&self) -> &Slot {
        let Self::V0 { slot, .. } = self;
        slot
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

fn find_pre_digest<Header, RewardAddress>(header: &Header) -> Option<PreDigest<RewardAddress>>
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

fn is_seal_signature_valid<Header>(mut header: Header, offender: &PublicKey) -> bool
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
        offender,
        &schnorrkel::signing_context(REWARD_SIGNING_CONTEXT),
    )
    .is_ok()
}

/// Verifies the equivocation proof by making sure that: both headers have
/// different hashes, are targeting the same slot, and have valid signatures by
/// the same authority.
pub fn is_equivocation_proof_valid<Header, RewardAddress>(proof: &EquivocationProof<Header>) -> bool
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
    if !(proof.slot == first_pre_digest.slot() && proof.slot == second_pre_digest.slot()) {
        return false;
    }

    // both headers must have the same sector index
    if first_pre_digest.solution().sector_index != second_pre_digest.solution().sector_index {
        return false;
    }

    // both headers must have been authored by the same farmer
    if first_pre_digest.solution().public_key != second_pre_digest.solution().public_key {
        return false;
    }

    // we finally verify that the expected farmer has signed both headers and
    // that the signature is valid.
    is_seal_signature_valid(proof.first_header.clone(), &proof.offender)
        && is_seal_signature_valid(proof.second_header.clone(), &proof.offender)
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
    #[inline]
    fn default() -> Self {
        Self {
            current: u64::MAX,
            next: None,
            voting_current: u64::MAX,
            voting_next: None,
        }
    }
}

/// Subspace blockchain constants.
#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone, Copy, TypeInfo)]
pub enum ChainConstants {
    /// V0 of the chain constants.
    #[codec(index = 0)]
    V0 {
        /// Depth `K` after which a block enters the recorded history.
        confirmation_depth_k: BlockNumber,
        /// Number of slots between slot arrival and when corresponding block can be produced.
        block_authoring_delay: Slot,
        /// Era duration in blocks.
        era_duration: BlockNumber,
        /// Slot probability.
        slot_probability: (u64, u64),
        /// The slot duration in milliseconds.
        slot_duration: SlotDuration,
        /// Number of latest archived segments that are considered "recent history".
        recent_segments: HistorySize,
        /// Fraction of pieces from the "recent history" (`recent_segments`) in each sector.
        recent_history_fraction: (HistorySize, HistorySize),
        /// Minimum lifetime of a plotted sector, measured in archived segment.
        min_sector_lifetime: HistorySize,
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

    /// Era duration in blocks.
    pub fn era_duration(&self) -> BlockNumber {
        let Self::V0 { era_duration, .. } = self;
        *era_duration
    }

    /// Number of slots between slot arrival and when corresponding block can be produced.
    pub fn block_authoring_delay(&self) -> Slot {
        let Self::V0 {
            block_authoring_delay,
            ..
        } = self;
        *block_authoring_delay
    }

    /// Slot probability.
    pub fn slot_probability(&self) -> (u64, u64) {
        let Self::V0 {
            slot_probability, ..
        } = self;
        *slot_probability
    }

    /// The slot duration in milliseconds.
    pub fn slot_duration(&self) -> SlotDuration {
        let Self::V0 { slot_duration, .. } = self;
        *slot_duration
    }

    /// Number of latest archived segments that are considered "recent history".
    pub fn recent_segments(&self) -> HistorySize {
        let Self::V0 {
            recent_segments, ..
        } = self;
        *recent_segments
    }

    /// Fraction of pieces from the "recent history" (`recent_segments`) in each sector.
    pub fn recent_history_fraction(&self) -> (HistorySize, HistorySize) {
        let Self::V0 {
            recent_history_fraction,
            ..
        } = self;
        *recent_history_fraction
    }

    /// Minimum lifetime of a plotted sector, measured in archived segment.
    pub fn min_sector_lifetime(&self) -> HistorySize {
        let Self::V0 {
            min_sector_lifetime,
            ..
        } = self;
        *min_sector_lifetime
    }
}

/// Wrapped solution for the purposes of runtime interface.
#[derive(Debug, Encode, Decode)]
pub struct WrappedSolution(Solution<()>);

impl<RewardAddress> From<&Solution<RewardAddress>> for WrappedSolution {
    #[inline]
    fn from(solution: &Solution<RewardAddress>) -> Self {
        Self(Solution {
            public_key: solution.public_key,
            reward_address: (),
            sector_index: solution.sector_index,
            history_size: solution.history_size,
            piece_offset: solution.piece_offset,
            record_commitment: solution.record_commitment,
            record_witness: solution.record_witness,
            chunk: solution.chunk,
            chunk_witness: solution.chunk_witness,
            proof_of_space: solution.proof_of_space,
        })
    }
}

impl PassBy for WrappedSolution {
    type PassBy = pass_by::Codec<Self>;
}

/// Wrapped solution verification parameters for the purposes of runtime interface.
#[derive(Debug, Encode, Decode)]
pub struct WrappedVerifySolutionParams<'a>(Cow<'a, VerifySolutionParams>);

impl<'a> From<&'a VerifySolutionParams> for WrappedVerifySolutionParams<'a> {
    #[inline]
    fn from(value: &'a VerifySolutionParams) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl<'a> PassBy for WrappedVerifySolutionParams<'a> {
    type PassBy = pass_by::Codec<Self>;
}

/// Wrapped proof of time output for the purposes of runtime interface.
#[derive(Debug, Encode, Decode)]
pub struct WrappedPotOutput(PotOutput);

impl From<PotOutput> for WrappedPotOutput {
    #[inline]
    fn from(value: PotOutput) -> Self {
        Self(value)
    }
}

impl PassBy for WrappedPotOutput {
    type PassBy = pass_by::Codec<Self>;
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
    /// A KZG extension.
    pub struct KzgExtension(Kzg);
}

#[cfg(feature = "std")]
impl KzgExtension {
    /// Create new instance.
    pub fn new(kzg: Kzg) -> Self {
        Self(kzg)
    }
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
    /// A Poof of space extension.
    pub struct PosExtension(PosTableType);
}

#[cfg(feature = "std")]
impl PosExtension {
    /// Create new instance.
    pub fn new<PosTable>() -> Self
    where
        PosTable: Table,
    {
        Self(PosTable::TABLE_TYPE)
    }
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
    /// A Poof of time extension.
    pub struct PotExtension(Box<dyn (Fn(BlockHash, SlotNumber, PotOutput, bool) -> bool) + Send + Sync>);
}

#[cfg(feature = "std")]
impl PotExtension {
    /// Create new instance.
    pub fn new(
        verifier: Box<dyn (Fn(BlockHash, SlotNumber, PotOutput, bool) -> bool) + Send + Sync>,
    ) -> Self {
        Self(verifier)
    }
}

/// Consensus-related runtime interface
#[runtime_interface]
pub trait Consensus {
    /// Verify whether solution is valid, returns solution distance that is `<= solution_range/2` on
    /// success.
    fn verify_solution(
        &mut self,
        solution: WrappedSolution,
        slot: SlotNumber,
        params: WrappedVerifySolutionParams<'_>,
    ) -> Result<SolutionRange, String> {
        use sp_externalities::ExternalitiesExt;
        use subspace_proof_of_space::PosTableType;

        let pos_table_type = self
            .extension::<PosExtension>()
            .expect("No `PosExtension` associated for the current context!")
            .0;

        let kzg = &self
            .extension::<KzgExtension>()
            .expect("No `KzgExtension` associated for the current context!")
            .0;

        match pos_table_type {
            PosTableType::Chia => subspace_verification::verify_solution::<ChiaTable, _>(
                &solution.0,
                slot,
                &params.0,
                kzg,
            )
            .map_err(|error| error.to_string()),
            PosTableType::Shim => subspace_verification::verify_solution::<ShimTable, _>(
                &solution.0,
                slot,
                &params.0,
                kzg,
            )
            .map_err(|error| error.to_string()),
        }
    }

    /// Verify whether `proof_of_time` is valid at specified `slot` if built on top of `parent_hash`
    /// fork of the chain.
    fn is_proof_of_time_valid(
        &mut self,
        parent_hash: BlockHash,
        slot: SlotNumber,
        proof_of_time: WrappedPotOutput,
        quick_verification: bool,
    ) -> bool {
        use sp_externalities::ExternalitiesExt;

        let verifier = &self
            .extension::<PotExtension>()
            .expect("No `PotExtension` associated for the current context!")
            .0;

        verifier(parent_hash, slot, proof_of_time.0, quick_verification)
    }
}

/// Proof of time parameters
#[derive(Debug, Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum PotParameters {
    /// Initial version of the parameters
    V0 {
        /// Number of iterations for proof of time per slot, corresponds to slot that directly
        /// follows parent block's slot and can change before slot for which block is produced
        slot_iterations: NonZeroU32,
        /// Optional next scheduled change of parameters
        next_change: Option<PotParametersChange>,
    },
}

impl PotParameters {
    /// Number of iterations for proof of time per slot, corresponds to slot that directly follows
    /// parent block's slot and can change before slot for which block is produced
    pub fn slot_iterations(&self) -> NonZeroU32 {
        let Self::V0 {
            slot_iterations, ..
        } = self;

        *slot_iterations
    }

    /// Get next proof of time parameters change if any
    pub fn next_parameters_change(&self) -> Option<PotParametersChange> {
        let Self::V0 { next_change, .. } = self;

        *next_change
    }
}

sp_api::decl_runtime_apis! {
    /// API necessary for block authorship with Subspace.
    pub trait SubspaceApi<RewardAddress: Encode + Decode> {
        /// Proof of time parameters
        fn pot_parameters() -> PotParameters;

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
        fn is_in_block_list(farmer_public_key: &PublicKey) -> bool;

        /// Size of the blockchain history
        fn history_size() -> HistorySize;

        /// How many pieces one sector is supposed to contain (max)
        fn max_pieces_in_sector() -> u16;

        /// Get the segment commitment of records for specified segment index
        fn segment_commitment(segment_index: SegmentIndex) -> Option<SegmentCommitment>;

        /// Returns `Vec<SegmentHeader>` if a given extrinsic has them.
        fn extract_segment_headers(ext: &Block::Extrinsic) -> Option<Vec<SegmentHeader >>;

        /// Checks if the extrinsic is an inherent.
        fn is_inherent(ext: &Block::Extrinsic) -> bool;

        /// Returns root plot public key in case block authoring is restricted.
        fn root_plot_public_key() -> Option<PublicKey>;

        /// Whether solution range adjustment is enabled.
        fn should_adjust_solution_range() -> bool;

        /// Get Subspace blockchain constants
        fn chain_constants() -> ChainConstants;
    }
}
