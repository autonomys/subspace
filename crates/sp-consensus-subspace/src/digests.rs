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
use sp_std::collections::btree_map::{BTreeMap, Entry};
use sp_std::fmt;
use subspace_core_primitives::{
    EonIndex, PublicKey, Randomness, RecordsRoot, Salt, SegmentIndex, Solution, SolutionRange,
};
use subspace_verification::{
    derive_next_eon_index, derive_next_salt_from_randomness, derive_randomness,
};

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
    fn solution_range(solution_range: SolutionRange) -> Self;

    /// If this item is a Subspace solution range, return it.
    fn as_solution_range(&self) -> Option<SolutionRange>;

    /// Construct a digest item which contains a salt.
    fn salt(salt: Salt) -> Self;

    /// If this item is a Subspace salt, return it.
    fn as_salt(&self) -> Option<Salt>;

    /// Construct a digest item which contains next global randomness.
    fn next_global_randomness(global_randomness: Randomness) -> Self;

    /// If this item is a Subspace next global randomness, return it.
    fn as_next_global_randomness(&self) -> Option<Randomness>;

    /// Construct a digest item which contains next solution range.
    fn next_solution_range(solution_range: SolutionRange) -> Self;

    /// If this item is a Subspace next solution range, return it.
    fn as_next_solution_range(&self) -> Option<SolutionRange>;

    /// Construct a digest item which contains next salt.
    fn next_salt(salt: Salt) -> Self;

    /// If this item is a Subspace next salt, return it.
    fn as_next_salt(&self) -> Option<Salt>;

    /// Construct a digest item which contains records root.
    fn records_root(segment_index: SegmentIndex, records_root: RecordsRoot) -> Self;

    /// If this item is a Subspace records root, return it.
    fn as_records_root(&self) -> Option<(SegmentIndex, RecordsRoot)>;

    /// Construct digest item than indicates enabling of solution range adjustment and override next solution range.
    fn enable_solution_range_adjustment_and_override(
        override_solution_range: Option<SolutionRange>,
    ) -> Self;

    /// If this item is a Subspace Enable solution range adjustment and override next solution range, return it.
    fn as_enable_solution_range_adjustment_and_override(&self) -> Option<Option<SolutionRange>>;
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

    fn next_salt(salt: Salt) -> Self {
        Self::Consensus(SUBSPACE_ENGINE_ID, ConsensusLog::NextSalt(salt).encode())
    }

    fn as_next_salt(&self) -> Option<Salt> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::NextSalt(salt) = c {
                Some(salt)
            } else {
                None
            }
        })
    }

    fn records_root(segment_index: SegmentIndex, records_root: RecordsRoot) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::RecordsRoot((segment_index, records_root)).encode(),
        )
    }

    fn as_records_root(&self) -> Option<(SegmentIndex, RecordsRoot)> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID).and_then(|c| {
            if let ConsensusLog::RecordsRoot(records_root) = c {
                Some(records_root)
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
    /// Salt
    Salt,
    /// Next global randomness
    NextGlobalRandomness,
    /// Next solution range
    NextSolutionRange,
    /// Next salt
    NextSalt,
    /// Records root
    RecordsRoot,
    /// Generic consensus
    Consensus,
    /// Enable solution range adjustment and override solution range
    EnableSolutionRangeAdjustmentAndOverride,
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
            ErrorDigestType::Salt => {
                write!(f, "Salt")
            }
            ErrorDigestType::NextGlobalRandomness => {
                write!(f, "NextGlobalRandomness")
            }
            ErrorDigestType::NextSolutionRange => {
                write!(f, "NextSolutionRange")
            }
            ErrorDigestType::NextSalt => {
                write!(f, "NextSalt")
            }
            ErrorDigestType::RecordsRoot => {
                write!(f, "RecordsRoot")
            }
            ErrorDigestType::Consensus => {
                write!(f, "Consensus")
            }
            ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride => {
                write!(f, "EnableSolutionRangeAdjustmentAndOverride")
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
    fn from(error: Error) -> String {
        error.to_string()
    }
}

/// Digest items extracted from a header into convenient form
pub struct SubspaceDigestItems<PublicKey, RewardAddress, Signature> {
    /// Pre-runtime digest
    pub pre_digest: PreDigest<PublicKey, RewardAddress>,
    /// Signature (seal) if present
    pub signature: Option<Signature>,
    /// Global randomness
    pub global_randomness: Randomness,
    /// Solution range
    pub solution_range: SolutionRange,
    /// Salt
    pub salt: Salt,
    /// Next global randomness
    pub next_global_randomness: Option<Randomness>,
    /// Next solution range
    pub next_solution_range: Option<SolutionRange>,
    /// Next salt
    pub next_salt: Option<Salt>,
    /// Records roots
    pub records_roots: BTreeMap<SegmentIndex, RecordsRoot>,
    /// Enable solution range adjustment and Override solution range
    pub enable_solution_range_adjustment_and_override: Option<Option<SolutionRange>>,
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
    let mut maybe_salt = None;
    let mut maybe_next_global_randomness = None;
    let mut maybe_next_solution_range = None;
    let mut maybe_next_salt = None;
    let mut records_roots = BTreeMap::new();
    let mut maybe_enable_and_override_solution_range = None;

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
                    ConsensusLog::Salt(salt) => match maybe_salt {
                        Some(_) => {
                            return Err(Error::Duplicate(ErrorDigestType::Salt));
                        }
                        None => {
                            maybe_salt.replace(salt);
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
                    ConsensusLog::NextSalt(salt) => match maybe_next_salt {
                        Some(_) => {
                            return Err(Error::Duplicate(ErrorDigestType::NextSalt));
                        }
                        None => {
                            maybe_next_salt.replace(salt);
                        }
                    },
                    ConsensusLog::RecordsRoot((segment_index, records_root)) => {
                        if let Entry::Vacant(entry) = records_roots.entry(segment_index) {
                            entry.insert(records_root);
                        } else {
                            return Err(Error::Duplicate(ErrorDigestType::NextSalt));
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
        salt: maybe_salt.ok_or(Error::Missing(ErrorDigestType::Salt))?,
        next_global_randomness: maybe_next_global_randomness,
        next_solution_range: maybe_next_solution_range,
        next_salt: maybe_next_salt,
        records_roots,
        enable_solution_range_adjustment_and_override: maybe_enable_and_override_solution_range,
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

fn derive_next_global_randomness<Header: HeaderT>(
    number: NumberOf<Header>,
    global_randomness_interval: NumberOf<Header>,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> Result<Option<Randomness>, Error> {
    if number % global_randomness_interval != Zero::zero() {
        return Ok(None);
    }

    derive_randomness(
        &PublicKey::from(&pre_digest.solution.public_key),
        pre_digest.solution.tag,
        &pre_digest.solution.tag_signature,
    )
    .map(Some)
    .map_err(|_err| Error::NextDigestDerivationError(ErrorDigestType::GlobalRandomness))
}

fn derive_next_salt<Header: HeaderT>(
    eon_duration: u64,
    current_eon_index: EonIndex,
    genesis_slot: Slot,
    current_slot: Slot,
    maybe_randomness: Option<Randomness>,
) -> Result<Option<Salt>, Error> {
    // check if eon changes
    let maybe_next_eon_index = derive_next_eon_index(
        current_eon_index,
        eon_duration,
        u64::from(genesis_slot),
        u64::from(current_slot),
    );

    // eon has changed, derive salt from the randomness derived from header at which salt is revealed
    if maybe_next_eon_index.is_some() {
        if let Some(randomness) = maybe_randomness {
            return Ok(Some(derive_next_salt_from_randomness(
                current_eon_index,
                &randomness,
            )));
        }
    }

    Ok(None)
}

fn derive_next_solution_range<Header: HeaderT>(
    number: NumberOf<Header>,
    era_duration: NumberOf<Header>,
    slot_probability: (u64, u64),
    current_slot: Slot,
    current_solution_range: SolutionRange,
    era_start_slot: Slot,
) -> Result<Option<SolutionRange>, Error> {
    if number.is_zero() || number % era_duration != Zero::zero() {
        return Ok(None);
    }

    let next_solution_range = subspace_verification::derive_next_solution_range(
        u64::from(era_start_slot),
        u64::from(current_slot),
        slot_probability,
        current_solution_range,
        era_duration
            .try_into()
            .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
    );

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
    /// Eon Duration at which next derived salt is used.
    pub eon_duration: u64,
    /// Genesis slot of the chain.
    pub genesis_slot: Slot,
    /// Current Era start slot.
    pub era_start_slot: Slot,
    /// Current eon index.
    pub current_eon_index: EonIndex,
    /// Randomness used to derive next salt.
    pub maybe_randomness: Option<Randomness>,
}

/// Derives and verifies next digest items based on their respective intervals.
pub fn verify_next_digests<Header: HeaderT>(
    params: NextDigestsVerificationParams<Header>,
) -> Result<(), Error> {
    // verify if the randomness is supposed to derived at this block header
    let expected_next_randomness = derive_next_global_randomness::<Header>(
        params.number,
        params.global_randomness_interval,
        &params.header_digests.pre_digest,
    )?;
    if expected_next_randomness != params.header_digests.next_global_randomness {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::NextGlobalRandomness,
        ));
    }

    // verify if the solution range should be derived at this block header
    let expected_next_solution_range = derive_next_solution_range::<Header>(
        params.number,
        params.era_duration,
        params.slot_probability,
        params.header_digests.pre_digest.slot,
        params.header_digests.solution_range,
        params.era_start_slot,
    )?;
    if expected_next_solution_range != params.header_digests.next_solution_range {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::NextSolutionRange,
        ));
    }

    // verify if the next derived salt should be present in the block header
    let expected_next_salt = derive_next_salt::<Header>(
        params.eon_duration,
        params.current_eon_index,
        params.genesis_slot,
        params.header_digests.pre_digest.slot,
        params.maybe_randomness,
    )?;
    if expected_next_salt != params.header_digests.next_salt {
        return Err(Error::NextDigestVerificationError(
            ErrorDigestType::NextSalt,
        ));
    }
    Ok(())
}
