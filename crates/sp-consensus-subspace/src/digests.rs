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
use sp_runtime::traits::{One, Zero};
use sp_runtime::DigestItem;
use sp_std::collections::btree_map::{BTreeMap, Entry};
use sp_std::fmt;
use subspace_core_primitives::{
    NonEmptyVec, PotProof, Randomness, SegmentCommitment, SegmentIndex, SlotNumber, Solution,
    SolutionRange,
};
use subspace_verification::derive_randomness;

/// A Subspace pre-runtime digest. This contains all data required to validate a block and for the
/// Subspace runtime module.
#[derive(Debug, Clone, Encode, Decode)]
pub struct PreDigest<PublicKey, RewardAddress> {
    /// Slot
    pub slot: Slot,
    /// Solution (includes PoR)
    pub solution: Solution<PublicKey, RewardAddress>,
    /// Proof of time included in the block
    /// TODO: It is Option<> for now for testing, to be removed
    /// when PoT feature is permanently enabled.
    pub proof_of_time: Option<PotPreDigest>,
}

/// The proof of time included in the pre digest.
/// TODO: versioning needs to match PotProof version,
/// versioning added on the proof side
#[derive(Clone, Encode, Decode)]
pub enum PotPreDigest {
    /// The block was produced in the bootstrapping phase, where
    /// the genesis slot has not yet been determined and the proof
    /// production has not started.
    Bootstrapping,

    /// Genesis slot determined by the bootstrap node.
    FirstBlock(SlotNumber),

    /// V0 proof.
    V0(NonEmptyVec<PotProof>),
}

impl PotPreDigest {
    /// Constructs the PoT for the pre digest.
    pub fn new(proofs: NonEmptyVec<PotProof>) -> Self {
        Self::V0(proofs)
    }

    /// Returns a reference to the proofs.
    pub fn proofs(&self) -> Option<&NonEmptyVec<PotProof>> {
        match self {
            Self::Bootstrapping | Self::FirstBlock(_) => None,
            Self::V0(proofs) => Some(proofs),
        }
    }

    /// Returns the starting slot number for the proofs in the next
    /// block.
    pub fn next_block_initial_slot(&self) -> Option<SlotNumber> {
        match self {
            Self::Bootstrapping => None,
            Self::FirstBlock(slot_number) => Some(slot_number + 1),
            Self::V0(proofs) => Some(proofs.last().slot_number + 1),
        }
    }
}

impl Default for PotPreDigest {
    fn default() -> Self {
        Self::Bootstrapping
    }
}

impl fmt::Debug for PotPreDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootstrapping => {
                write!(f, "PotPreDigest::Bootstrapping")
            }
            Self::FirstBlock(slot_number) => {
                write!(
                    f,
                    "PotPreDigest::FirstBlock => genesis_slot = {slot_number}"
                )
            }
            Self::V0(proofs) => {
                write!(
                    f,
                    "PotPreDigest::V0 => num_proofs: {}, proofs: [{} - {}]",
                    proofs.len(),
                    proofs.first(),
                    proofs.last(),
                )
            }
        }
    }
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
    fn solution_range(solution_range: SolutionRange) -> Self;

    /// If this item is a Subspace solution range, return it.
    fn as_solution_range(&self) -> Option<SolutionRange>;

    /// Construct a digest item which contains next global randomness.
    fn next_global_randomness(global_randomness: Randomness) -> Self;

    /// If this item is a Subspace next global randomness, return it.
    fn as_next_global_randomness(&self) -> Option<Randomness>;

    /// Construct a digest item which contains next solution range.
    fn next_solution_range(solution_range: SolutionRange) -> Self;

    /// If this item is a Subspace next solution range, return it.
    fn as_next_solution_range(&self) -> Option<SolutionRange>;

    /// Construct a digest item which contains segment commitment.
    fn segment_commitment(
        segment_index: SegmentIndex,
        segment_commitment: SegmentCommitment,
    ) -> Self;

    /// If this item is a Subspace segment commitment, return it.
    fn as_segment_commitment(&self) -> Option<(SegmentIndex, SegmentCommitment)>;

    /// Construct digest item than indicates enabling of solution range adjustment and override next
    /// solution range.
    fn enable_solution_range_adjustment_and_override(
        override_solution_range: Option<SolutionRange>,
    ) -> Self;

    /// If this item is a Subspace Enable solution range adjustment and override next solution
    /// range, return it.
    fn as_enable_solution_range_adjustment_and_override(&self) -> Option<Option<SolutionRange>>;

    /// Construct digest item than indicates update of root plot public key.
    fn root_plot_public_key_update(root_plot_public_key: Option<FarmerPublicKey>) -> Self;

    /// If this item is a Subspace update of root plot public key, return it.
    fn as_root_plot_public_key_update(&self) -> Option<Option<FarmerPublicKey>>;
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

    fn global_randomness(global_randomness: Randomness) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::GlobalRandomness(global_randomness).encode(),
        )
    }

    fn as_global_randomness(&self) -> Option<Randomness> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::GlobalRandomness(global_randomness) = c {
                Some(global_randomness)
            } else {
                None
            }
        })
    }

    fn solution_range(solution_range: SolutionRange) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::SolutionRange(solution_range).encode(),
        )
    }

    fn as_solution_range(&self) -> Option<SolutionRange> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::SolutionRange(solution_range) = c {
                Some(solution_range)
            } else {
                None
            }
        })
    }

    fn next_global_randomness(global_randomness: Randomness) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::NextGlobalRandomness(global_randomness).encode(),
        )
    }

    fn as_next_global_randomness(&self) -> Option<Randomness> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::NextGlobalRandomness(global_randomness) = c {
                Some(global_randomness)
            } else {
                None
            }
        })
    }

    fn next_solution_range(solution_range: SolutionRange) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::NextSolutionRange(solution_range).encode(),
        )
    }

    fn as_next_solution_range(&self) -> Option<SolutionRange> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::NextSolutionRange(solution_range) = c {
                Some(solution_range)
            } else {
                None
            }
        })
    }

    fn segment_commitment(
        segment_index: SegmentIndex,
        segment_commitment: SegmentCommitment,
    ) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::SegmentCommitment((segment_index, segment_commitment)).encode(),
        )
    }

    fn as_segment_commitment(&self) -> Option<(SegmentIndex, SegmentCommitment)> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::SegmentCommitment(segment_commitment) = c {
                Some(segment_commitment)
            } else {
                None
            }
        })
    }

    fn enable_solution_range_adjustment_and_override(
        maybe_override_solution_range: Option<SolutionRange>,
    ) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::EnableSolutionRangeAdjustmentAndOverride(maybe_override_solution_range)
                .encode(),
        )
    }

    fn as_enable_solution_range_adjustment_and_override(&self) -> Option<Option<SolutionRange>> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::EnableSolutionRangeAdjustmentAndOverride(
                maybe_override_solution_range,
            ) = c
            {
                Some(maybe_override_solution_range)
            } else {
                None
            }
        })
    }

    fn root_plot_public_key_update(root_plot_public_key: Option<FarmerPublicKey>) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::RootPlotPublicKeyUpdate(root_plot_public_key).encode(),
        )
    }

    fn as_root_plot_public_key_update(&self) -> Option<Option<FarmerPublicKey>> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::RootPlotPublicKeyUpdate(root_plot_public_key) = c {
                Some(root_plot_public_key)
            } else {
                None
            }
        })
    }
}

/// Various kinds of digest types used in errors
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorDigestType {
    /// Pre-digest
    PreDigest,
    /// Seal (signature)
    Seal,
    /// Global randomness
    GlobalRandomness,
    /// Solution range
    SolutionRange,
    /// Next global randomness
    NextGlobalRandomness,
    /// Next solution range
    NextSolutionRange,
    /// Segment commitment
    SegmentCommitment,
    /// Generic consensus
    Consensus,
    /// Enable solution range adjustment and override solution range
    EnableSolutionRangeAdjustmentAndOverride,
    /// Root plot public key was updated
    RootPlotPublicKeyUpdate,
}

impl fmt::Display for ErrorDigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorDigestType::PreDigest => {
                write!(f, "PreDigest")
            }
            ErrorDigestType::Seal => {
                write!(f, "Seal")
            }
            ErrorDigestType::GlobalRandomness => {
                write!(f, "GlobalRandomness")
            }
            ErrorDigestType::SolutionRange => {
                write!(f, "SolutionRange")
            }
            ErrorDigestType::NextGlobalRandomness => {
                write!(f, "NextGlobalRandomness")
            }
            ErrorDigestType::NextSolutionRange => {
                write!(f, "NextSolutionRange")
            }
            ErrorDigestType::SegmentCommitment => {
                write!(f, "SegmentCommitment")
            }
            ErrorDigestType::Consensus => {
                write!(f, "Consensus")
            }
            ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride => {
                write!(f, "EnableSolutionRangeAdjustmentAndOverride")
            }
            ErrorDigestType::RootPlotPublicKeyUpdate => {
                write!(f, "RootPlotPublicKeyUpdate")
            }
        }
    }
}

/// Digest error
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
    /// Subspace digest missing
    #[cfg_attr(feature = "thiserror", error("Subspace {0} digest not found"))]
    Missing(ErrorDigestType),
    /// Failed to decode Subspace digest
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to decode Subspace {0} digest: {1}")
    )]
    FailedToDecode(ErrorDigestType, codec::Error),
    /// Duplicate Subspace digests
    #[cfg_attr(
        feature = "thiserror",
        error("Duplicate Subspace {0} digests, rejecting!")
    )]
    Duplicate(ErrorDigestType),

    /// Error when deriving next digests
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to derive next {0} digest, rejecting!")
    )]
    NextDigestDerivationError(ErrorDigestType),

    /// Error when verifying next digests
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to verify next {0} digest, rejecting!")
    )]
    NextDigestVerificationError(ErrorDigestType),
}

#[cfg(feature = "std")]
impl From<Error> for String {
    #[inline]
    fn from(error: Error) -> String {
        error.to_string()
    }
}

/// Digest items extracted from a header into convenient form
#[derive(Debug)]
pub struct SubspaceDigestItems<PublicKey, RewardAddress, Signature> {
    /// Pre-runtime digest
    pub pre_digest: PreDigest<PublicKey, RewardAddress>,
    /// Signature (seal) if present
    pub signature: Option<Signature>,
    /// Global randomness
    pub global_randomness: Randomness,
    /// Solution range
    pub solution_range: SolutionRange,
    /// Next global randomness
    pub next_global_randomness: Option<Randomness>,
    /// Next solution range
    pub next_solution_range: Option<SolutionRange>,
    /// Segment commitments
    pub segment_commitments: BTreeMap<SegmentIndex, SegmentCommitment>,
    /// Enable solution range adjustment and Override solution range
    pub enable_solution_range_adjustment_and_override: Option<Option<SolutionRange>>,
    /// Root plot public key was updated
    pub root_plot_public_key_update: Option<Option<FarmerPublicKey>>,
}

/// Extract the Subspace global randomness from the given header.
pub fn extract_subspace_digest_items<Header, PublicKey, RewardAddress, Signature>(
    header: &Header,
) -> Result<SubspaceDigestItems<PublicKey, RewardAddress, Signature>, Error>
where
    Header: HeaderT,
    PublicKey: Decode,
    RewardAddress: Decode,
    Signature: Decode,
{
    let mut maybe_pre_digest = None;
    let mut maybe_seal = None;
    let mut maybe_global_randomness = None;
    let mut maybe_solution_range = None;
    let mut maybe_next_global_randomness = None;
    let mut maybe_next_solution_range = None;
    let mut segment_commitments = BTreeMap::new();
    let mut maybe_enable_and_override_solution_range = None;
    let mut maybe_root_plot_public_key_update = None;

    for log in header.digest().logs() {
        match log {
            DigestItem::PreRuntime(id, data) => {
                if id != &SUBSPACE_ENGINE_ID {
                    continue;
                }

                let pre_digest = PreDigest::<PublicKey, RewardAddress>::decode(
                    &mut data.as_slice(),
                )
                .map_err(|error| Error::FailedToDecode(ErrorDigestType::PreDigest, error))?;

                match maybe_pre_digest {
                    Some(_) => {
                        return Err(Error::Duplicate(ErrorDigestType::PreDigest));
                    }
                    None => {
                        maybe_pre_digest.replace(pre_digest);
                    }
                }
            }
            DigestItem::Consensus(id, data) => {
                if id != &SUBSPACE_ENGINE_ID {
                    continue;
                }

                let consensus = ConsensusLog::decode(&mut data.as_slice())
                    .map_err(|error| Error::FailedToDecode(ErrorDigestType::Consensus, error))?;

                match consensus {
                    ConsensusLog::GlobalRandomness(global_randomness) => {
                        match maybe_global_randomness {
                            Some(_) => {
                                return Err(Error::Duplicate(ErrorDigestType::GlobalRandomness));
                            }
                            None => {
                                maybe_global_randomness.replace(global_randomness);
                            }
                        }
                    }
                    ConsensusLog::SolutionRange(solution_range) => match maybe_solution_range {
                        Some(_) => {
                            return Err(Error::Duplicate(ErrorDigestType::SolutionRange));
                        }
                        None => {
                            maybe_solution_range.replace(solution_range);
                        }
                    },
                    ConsensusLog::NextGlobalRandomness(global_randomness) => {
                        match maybe_next_global_randomness {
                            Some(_) => {
                                return Err(Error::Duplicate(
                                    ErrorDigestType::NextGlobalRandomness,
                                ));
                            }
                            None => {
                                maybe_next_global_randomness.replace(global_randomness);
                            }
                        }
                    }
                    ConsensusLog::NextSolutionRange(solution_range) => {
                        match maybe_next_solution_range {
                            Some(_) => {
                                return Err(Error::Duplicate(ErrorDigestType::NextSolutionRange));
                            }
                            None => {
                                maybe_next_solution_range.replace(solution_range);
                            }
                        }
                    }
                    ConsensusLog::SegmentCommitment((segment_index, segment_commitment)) => {
                        if let Entry::Vacant(entry) = segment_commitments.entry(segment_index) {
                            entry.insert(segment_commitment);
                        } else {
                            return Err(Error::Duplicate(ErrorDigestType::SegmentCommitment));
                        }
                    }
                    ConsensusLog::EnableSolutionRangeAdjustmentAndOverride(
                        override_solution_range,
                    ) => match maybe_enable_and_override_solution_range {
                        None => {
                            maybe_enable_and_override_solution_range
                                .replace(override_solution_range);
                        }
                        Some(_) => {
                            return Err(Error::Duplicate(
                                ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride,
                            ));
                        }
                    },
                    ConsensusLog::RootPlotPublicKeyUpdate(root_plot_public_key_update) => {
                        match maybe_enable_and_override_solution_range {
                            None => {
                                maybe_root_plot_public_key_update
                                    .replace(root_plot_public_key_update);
                            }
                            Some(_) => {
                                return Err(Error::Duplicate(
                                    ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride,
                                ));
                            }
                        }
                    }
                }
            }
            DigestItem::Seal(id, data) => {
                if id != &SUBSPACE_ENGINE_ID {
                    continue;
                }

                let seal = Signature::decode(&mut data.as_slice())
                    .map_err(|error| Error::FailedToDecode(ErrorDigestType::Seal, error))?;

                match maybe_seal {
                    Some(_) => {
                        return Err(Error::Duplicate(ErrorDigestType::Seal));
                    }
                    None => {
                        maybe_seal.replace(seal);
                    }
                }
            }
            DigestItem::Other(_data) => {
                // Ignore
            }
            DigestItem::RuntimeEnvironmentUpdated => {
                // Ignore
            }
        }
    }

    Ok(SubspaceDigestItems {
        pre_digest: maybe_pre_digest.ok_or(Error::Missing(ErrorDigestType::PreDigest))?,
        signature: maybe_seal,
        global_randomness: maybe_global_randomness
            .ok_or(Error::Missing(ErrorDigestType::GlobalRandomness))?,
        solution_range: maybe_solution_range
            .ok_or(Error::Missing(ErrorDigestType::SolutionRange))?,
        next_global_randomness: maybe_next_global_randomness,
        next_solution_range: maybe_next_solution_range,
        segment_commitments,
        enable_solution_range_adjustment_and_override: maybe_enable_and_override_solution_range,
        root_plot_public_key_update: maybe_root_plot_public_key_update,
    })
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
            proof_of_time: Default::default(),
        });
    }

    let mut pre_digest = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for pre runtime digest", log);
        match (log.as_subspace_pre_digest(), pre_digest.is_some()) {
            (Some(_), true) => return Err(Error::Duplicate(ErrorDigestType::PreDigest)),
            (None, _) => trace!(target: "subspace", "Ignoring digest not meant for us"),
            (s, false) => pre_digest = s,
        }
    }
    pre_digest.ok_or(Error::Missing(ErrorDigestType::PreDigest))
}

type NumberOf<T> = <T as HeaderT>::Number;

/// Returns the next global randomness if interval is met.
pub fn derive_next_global_randomness<Header: HeaderT>(
    number: NumberOf<Header>,
    global_randomness_interval: NumberOf<Header>,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> Option<Randomness> {
    if number % global_randomness_interval != Zero::zero() {
        return None;
    }

    Some(derive_randomness(
        &pre_digest.solution,
        pre_digest.slot.into(),
    ))
}

/// Params used to derive the next solution range.
pub struct DeriveNextSolutionRangeParams<Header: HeaderT> {
    /// Current number of the block.
    pub number: NumberOf<Header>,
    /// Era duration of the chain.
    pub era_duration: NumberOf<Header>,
    /// Slot probability at which a block is produced.
    pub slot_probability: (u64, u64),
    /// Current slot of the block.
    pub current_slot: Slot,
    /// Current solution range of the block.
    pub current_solution_range: SolutionRange,
    /// Slot at which era has begun.
    pub era_start_slot: Slot,
    /// Flag to check if the next solution range should be adjusted.
    pub should_adjust_solution_range: bool,
    /// Solution range override that should be used instead of deriving from current.
    pub maybe_next_solution_range_override: Option<SolutionRange>,
}

/// Derives next solution range if era duration interval has met.
pub fn derive_next_solution_range<Header: HeaderT>(
    params: DeriveNextSolutionRangeParams<Header>,
) -> Result<Option<SolutionRange>, Error> {
    let DeriveNextSolutionRangeParams {
        number,
        era_duration,
        slot_probability,
        current_slot,
        current_solution_range,
        era_start_slot,
        should_adjust_solution_range,
        maybe_next_solution_range_override,
    } = params;

    if number.is_zero() || number % era_duration != Zero::zero() {
        return Ok(None);
    }

    // if the solution range should not be adjusted, return the current solution range
    let next_solution_range = if !should_adjust_solution_range {
        current_solution_range
    } else if let Some(solution_range_override) = maybe_next_solution_range_override {
        // era has change so take this override and reset it
        solution_range_override
    } else {
        subspace_verification::derive_next_solution_range(
            u64::from(era_start_slot),
            u64::from(current_slot),
            slot_probability,
            current_solution_range,
            era_duration
                .try_into()
                .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
        )
    };

    Ok(Some(next_solution_range))
}

/// Type that holds the parameters to derive and verify next digest items.
pub struct NextDigestsVerificationParams<'a, Header: HeaderT> {
    /// Header number for which we are verifying the digests.
    pub number: NumberOf<Header>,
    /// Digests present in the header that corresponds to number above.
    pub header_digests: &'a SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
    /// Randomness interval at which next randomness is derived.
    pub global_randomness_interval: NumberOf<Header>,
    /// Era duration at which solution range is updated.
    pub era_duration: NumberOf<Header>,
    /// Slot probability.
    pub slot_probability: (u64, u64),
    /// Current Era start slot.
    pub era_start_slot: Slot,
    /// Should the solution range be adjusted on era change.
    /// If the digest logs indicate that solution range adjustment has been enabled, value is updated.
    pub should_adjust_solution_range: &'a mut bool,
    /// Next Solution range override.
    /// If the digest logs indicate that solution range override is provided, value is updated.
    pub maybe_next_solution_range_override: &'a mut Option<SolutionRange>,
    /// Root plot public key.
    /// Value is updated when digest items contain an update.
    pub maybe_root_plot_public_key: &'a mut Option<FarmerPublicKey>,
}

/// Derives and verifies next digest items based on their respective intervals.
pub fn verify_next_digests<Header: HeaderT>(
    params: NextDigestsVerificationParams<Header>,
) -> Result<(), Error> {
    let NextDigestsVerificationParams {
        number,
        header_digests,
        global_randomness_interval,
        era_duration,
        slot_probability,
        era_start_slot,
        should_adjust_solution_range,
        maybe_next_solution_range_override,
        maybe_root_plot_public_key: root_plot_public_key,
    } = params;

    // verify if the randomness is supposed to derived at this block header
    let expected_next_randomness = derive_next_global_randomness::<Header>(
        number,
        global_randomness_interval,
        &header_digests.pre_digest,
    );
    if expected_next_randomness != header_digests.next_global_randomness {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::NextGlobalRandomness,
        ));
    }

    // verify solution range adjustment and override
    // if the adjustment is already enabled, then error out
    if *should_adjust_solution_range
        && header_digests
            .enable_solution_range_adjustment_and_override
            .is_some()
    {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride,
        ));
    }

    if let Some(solution_range_override) =
        header_digests.enable_solution_range_adjustment_and_override
    {
        *should_adjust_solution_range = true;
        *maybe_next_solution_range_override = solution_range_override;
    }

    // verify if the solution range should be derived at this block header
    let expected_next_solution_range =
        derive_next_solution_range::<Header>(DeriveNextSolutionRangeParams {
            number,
            era_duration,
            slot_probability,
            current_slot: header_digests.pre_digest.slot,
            current_solution_range: header_digests.solution_range,
            era_start_slot,
            should_adjust_solution_range: *should_adjust_solution_range,
            maybe_next_solution_range_override: *maybe_next_solution_range_override,
        })?;

    if expected_next_solution_range.is_some() {
        // Whatever override we had, it is no longer necessary
        maybe_next_solution_range_override.take();
    }
    if expected_next_solution_range != header_digests.next_solution_range {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::NextSolutionRange,
        ));
    }

    if let Some(updated_root_plot_public_key) = &header_digests.root_plot_public_key_update {
        match updated_root_plot_public_key {
            Some(updated_root_plot_public_key) => {
                if number.is_one()
                    && root_plot_public_key.is_none()
                    && &header_digests.pre_digest.solution.public_key
                        == updated_root_plot_public_key
                {
                    root_plot_public_key.replace(updated_root_plot_public_key.clone());
                } else {
                    return Err(Error::NextDigestVerificationError(
                        ErrorDigestType::RootPlotPublicKeyUpdate,
                    ));
                }
            }
            None => {
                root_plot_public_key.take();
            }
        }
    }

    Ok(())
}
