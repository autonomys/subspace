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

use crate::{ConsensusLog, PotParametersChange, SUBSPACE_ENGINE_ID};
use codec::{Decode, Encode};
use log::trace;
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Header as HeaderT, One, Zero};
use sp_runtime::DigestItem;
use sp_std::collections::btree_map::{BTreeMap, Entry};
use sp_std::fmt;
use sp_std::num::NonZeroU32;
use subspace_core_primitives::segments::{SegmentCommitment, SegmentIndex};
use subspace_core_primitives::{PotOutput, PublicKey, RewardSignature, Solution, SolutionRange};

/// A Subspace pre-runtime digest. This contains all data required to validate a block and for the
/// Subspace runtime module.
#[derive(Debug, Clone, Encode, Decode)]
pub enum PreDigest<RewardAddress> {
    /// Initial version of the pre-digest
    #[codec(index = 0)]
    V0 {
        /// Slot
        slot: Slot,
        /// Solution (includes PoR)
        solution: Solution<RewardAddress>,
        /// Proof of time information
        pot_info: PreDigestPotInfo,
    },
}

impl<RewardAddress> PreDigest<RewardAddress> {
    /// Slot
    #[inline]
    pub fn slot(&self) -> Slot {
        let Self::V0 { slot, .. } = self;
        *slot
    }

    /// Solution (includes PoR)
    #[inline]
    pub fn solution(&self) -> &Solution<RewardAddress> {
        let Self::V0 { solution, .. } = self;
        solution
    }

    /// Proof of time information
    #[inline]
    pub fn pot_info(&self) -> &PreDigestPotInfo {
        let Self::V0 { pot_info, .. } = self;
        pot_info
    }
}

/// Proof of time information in pre-digest
#[derive(Debug, Clone, Encode, Decode)]
pub enum PreDigestPotInfo {
    /// Initial version of proof of time information
    #[codec(index = 0)]
    V0 {
        /// Proof of time for this slot
        proof_of_time: PotOutput,
        /// Future proof of time
        future_proof_of_time: PotOutput,
    },
}

impl PreDigestPotInfo {
    /// Proof of time for this slot
    #[inline]
    pub fn proof_of_time(&self) -> PotOutput {
        let Self::V0 { proof_of_time, .. } = self;
        *proof_of_time
    }

    /// Future proof of time
    #[inline]
    pub fn future_proof_of_time(&self) -> PotOutput {
        let Self::V0 {
            future_proof_of_time,
            ..
        } = self;
        *future_proof_of_time
    }
}

/// A digest item which is usable with Subspace consensus.
pub trait CompatibleDigestItem: Sized {
    /// Construct a digest item which contains a Subspace pre-digest.
    fn subspace_pre_digest<AccountId: Encode>(pre_digest: &PreDigest<AccountId>) -> Self;

    /// If this item is an Subspace pre-digest, return it.
    fn as_subspace_pre_digest<AccountId: Decode>(&self) -> Option<PreDigest<AccountId>>;

    /// Construct a digest item which contains a Subspace seal.
    fn subspace_seal(signature: RewardSignature) -> Self;

    /// If this item is a Subspace signature, return the signature.
    fn as_subspace_seal(&self) -> Option<RewardSignature>;

    /// Number of iterations for proof of time per slot, corresponds to slot that directly follows
    /// parent block's slot and can change before slot for which block is produced
    fn pot_slot_iterations(pot_slot_iterations: NonZeroU32) -> Self;

    /// If this item is a Subspace proof of time slot iterations, return it.
    fn as_pot_slot_iterations(&self) -> Option<NonZeroU32>;

    /// Construct a digest item which contains a solution range.
    fn solution_range(solution_range: SolutionRange) -> Self;

    /// If this item is a Subspace solution range, return it.
    fn as_solution_range(&self) -> Option<SolutionRange>;

    /// Change of parameters to apply to PoT chain
    fn pot_parameters_change(pot_parameters_change: PotParametersChange) -> Self;

    /// If this item is a Subspace proof of time change of parameters, return it.
    fn as_pot_parameters_change(&self) -> Option<PotParametersChange>;

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

    /// Construct digest item that indicates update of root plot public key.
    fn root_plot_public_key_update(root_plot_public_key: Option<PublicKey>) -> Self;

    /// If this item is a Subspace update of root plot public key, return it.
    fn as_root_plot_public_key_update(&self) -> Option<Option<PublicKey>>;
}

impl CompatibleDigestItem for DigestItem {
    fn subspace_pre_digest<RewardAddress: Encode>(pre_digest: &PreDigest<RewardAddress>) -> Self {
        Self::PreRuntime(SUBSPACE_ENGINE_ID, pre_digest.encode())
    }

    fn as_subspace_pre_digest<RewardAddress: Decode>(&self) -> Option<PreDigest<RewardAddress>> {
        self.pre_runtime_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn subspace_seal(signature: RewardSignature) -> Self {
        Self::Seal(SUBSPACE_ENGINE_ID, signature.encode())
    }

    fn as_subspace_seal(&self) -> Option<RewardSignature> {
        self.seal_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn pot_slot_iterations(pot_slot_iterations: NonZeroU32) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::PotSlotIterations(pot_slot_iterations).encode(),
        )
    }

    fn as_pot_slot_iterations(&self) -> Option<NonZeroU32> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::PotSlotIterations(pot_slot_iterations) = c {
                Some(pot_slot_iterations)
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

    fn pot_parameters_change(pot_parameters_change: PotParametersChange) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::PotParametersChange(pot_parameters_change).encode(),
        )
    }

    fn as_pot_parameters_change(&self) -> Option<PotParametersChange> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::PotParametersChange(pot_parameters_change) = c {
                Some(pot_parameters_change)
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

    fn root_plot_public_key_update(root_plot_public_key: Option<PublicKey>) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::RootPlotPublicKeyUpdate(root_plot_public_key).encode(),
        )
    }

    fn as_root_plot_public_key_update(&self) -> Option<Option<PublicKey>> {
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
    /// Number of iterations for proof of time per slot
    PotSlotIterations,
    /// Solution range
    SolutionRange,
    /// Change of parameters to apply to PoT chain
    PotParametersChange,
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
            ErrorDigestType::PotSlotIterations => {
                write!(f, "PotSlotIterations")
            }
            ErrorDigestType::SolutionRange => {
                write!(f, "SolutionRange")
            }
            ErrorDigestType::PotParametersChange => {
                write!(f, "PotParametersChange")
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
pub struct SubspaceDigestItems<RewardAddress> {
    /// Pre-runtime digest
    pub pre_digest: PreDigest<RewardAddress>,
    /// Signature (seal) if present
    pub signature: Option<RewardSignature>,
    /// Number of iterations for proof of time per slot, corresponds to slot that directly follows
    /// parent block's slot and can change before slot for which block is produced
    pub pot_slot_iterations: NonZeroU32,
    /// Solution range
    pub solution_range: SolutionRange,
    /// Change of parameters to apply to PoT chain
    pub pot_parameters_change: Option<PotParametersChange>,
    /// Next solution range
    pub next_solution_range: Option<SolutionRange>,
    /// Segment commitments
    pub segment_commitments: BTreeMap<SegmentIndex, SegmentCommitment>,
    /// Enable solution range adjustment and Override solution range
    pub enable_solution_range_adjustment_and_override: Option<Option<SolutionRange>>,
    /// Root plot public key was updated
    pub root_plot_public_key_update: Option<Option<PublicKey>>,
}

/// Extract the Subspace global randomness from the given header.
pub fn extract_subspace_digest_items<Header, RewardAddress>(
    header: &Header,
) -> Result<SubspaceDigestItems<RewardAddress>, Error>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    let mut maybe_pre_digest = None;
    let mut maybe_seal = None;
    let mut maybe_pot_slot_iterations = None;
    let mut maybe_solution_range = None;
    let mut maybe_pot_parameters_change = None;
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

                let pre_digest = PreDigest::<RewardAddress>::decode(&mut data.as_slice())
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
                    ConsensusLog::PotSlotIterations(pot_slot_iterations) => {
                        match maybe_pot_slot_iterations {
                            Some(_) => {
                                return Err(Error::Duplicate(ErrorDigestType::PotSlotIterations));
                            }
                            None => {
                                maybe_pot_slot_iterations.replace(pot_slot_iterations);
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
                    ConsensusLog::PotParametersChange(pot_parameters_change) => {
                        match maybe_pot_parameters_change {
                            Some(_) => {
                                return Err(Error::Duplicate(ErrorDigestType::PotParametersChange));
                            }
                            None => {
                                maybe_pot_parameters_change.replace(pot_parameters_change);
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
                        Some(_) => {
                            return Err(Error::Duplicate(
                                ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride,
                            ));
                        }
                        None => {
                            maybe_enable_and_override_solution_range
                                .replace(override_solution_range);
                        }
                    },
                    ConsensusLog::RootPlotPublicKeyUpdate(root_plot_public_key_update) => {
                        match maybe_root_plot_public_key_update {
                            Some(_) => {
                                return Err(Error::Duplicate(
                                    ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride,
                                ));
                            }
                            None => {
                                maybe_root_plot_public_key_update
                                    .replace(root_plot_public_key_update);
                            }
                        }
                    }
                }
            }
            DigestItem::Seal(id, data) => {
                if id != &SUBSPACE_ENGINE_ID {
                    continue;
                }

                let seal = RewardSignature::decode(&mut data.as_slice())
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
        pot_slot_iterations: maybe_pot_slot_iterations
            .ok_or(Error::Missing(ErrorDigestType::PotSlotIterations))?,
        solution_range: maybe_solution_range
            .ok_or(Error::Missing(ErrorDigestType::SolutionRange))?,
        pot_parameters_change: maybe_pot_parameters_change,
        next_solution_range: maybe_next_solution_range,
        segment_commitments,
        enable_solution_range_adjustment_and_override: maybe_enable_and_override_solution_range,
        root_plot_public_key_update: maybe_root_plot_public_key_update,
    })
}

/// Extract the Subspace pre digest from the given header. Pre-runtime digests are mandatory, the
/// function will return `Err` if none is found.
pub fn extract_pre_digest<Header>(header: &Header) -> Result<PreDigest<PublicKey>, Error>
where
    Header: HeaderT,
{
    // genesis block doesn't contain a pre digest so let's generate a
    // dummy one to not break any invariants in the rest of the code
    if header.number().is_zero() {
        return Ok(PreDigest::V0 {
            slot: Slot::from(0),
            solution: Solution::genesis_solution(
                PublicKey::from([0u8; 32]),
                PublicKey::from([0u8; 32]),
            ),
            pot_info: PreDigestPotInfo::V0 {
                proof_of_time: Default::default(),
                future_proof_of_time: Default::default(),
            },
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
    pub header_digests: &'a SubspaceDigestItems<PublicKey>,
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
    pub maybe_root_plot_public_key: &'a mut Option<PublicKey>,
}

/// Derives and verifies next digest items based on their respective intervals.
pub fn verify_next_digests<Header: HeaderT>(
    params: NextDigestsVerificationParams<Header>,
) -> Result<(), Error> {
    let NextDigestsVerificationParams {
        number,
        header_digests,
        era_duration,
        slot_probability,
        era_start_slot,
        should_adjust_solution_range,
        maybe_next_solution_range_override,
        maybe_root_plot_public_key: root_plot_public_key,
    } = params;

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
            current_slot: header_digests.pre_digest.slot(),
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

    if let Some(updated_root_plot_public_key) = header_digests.root_plot_public_key_update {
        match updated_root_plot_public_key {
            Some(updated_root_plot_public_key) => {
                if number.is_one()
                    && root_plot_public_key.is_none()
                    && header_digests.pre_digest.solution().public_key
                        == updated_root_plot_public_key
                {
                    root_plot_public_key.replace(updated_root_plot_public_key);
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
