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
use sp_std::fmt;
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

    /// Construct a digest item which contains next global randomness.
    fn next_global_randomness(global_randomness: Randomness) -> Self;

    /// If this item is a Subspace next global randomness, return it.
    fn as_next_global_randomness(&self) -> Option<Randomness>;

    /// Construct a digest item which contains next solution range.
    fn next_solution_range(solution_range: u64) -> Self;

    /// If this item is a Subspace next solution range, return it.
    fn as_next_solution_range(&self) -> Option<u64>;

    /// Construct a digest item which contains next salt.
    fn next_salt(salt: Salt) -> Self;

    /// If this item is a Subspace next salt, return it.
    fn as_next_salt(&self) -> Option<Salt>;
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

    fn next_solution_range(solution_range: u64) -> Self {
        Self::Consensus(
            SUBSPACE_ENGINE_ID,
            ConsensusLog::NextSolutionRange(solution_range).encode(),
        )
    }

    fn as_next_solution_range(&self) -> Option<u64> {
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
    /// Generic consensus
    Consensus,
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
            ErrorDigestType::Consensus => {
                write!(f, "Consensus")
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
    /// Multiple Subspace digests
    #[cfg_attr(
        feature = "thiserror",
        error("Multiple Subspace {0} digests, rejecting!")
    )]
    Multiple(ErrorDigestType),
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
    pub solution_range: u64,
    /// Salt
    pub salt: Salt,
    /// Next global randomness
    pub next_global_randomness: Option<Randomness>,
    /// Next solution range
    pub next_solution_range: Option<u64>,
    /// Next salt
    pub next_salt: Option<Salt>,
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
                        return Err(Error::Multiple(ErrorDigestType::PreDigest));
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
                                return Err(Error::Multiple(ErrorDigestType::GlobalRandomness));
                            }
                            None => {
                                maybe_global_randomness.replace(global_randomness);
                            }
                        }
                    }
                    ConsensusLog::SolutionRange(solution_range) => match maybe_solution_range {
                        Some(_) => {
                            return Err(Error::Multiple(ErrorDigestType::SolutionRange));
                        }
                        None => {
                            maybe_solution_range.replace(solution_range);
                        }
                    },
                    ConsensusLog::Salt(salt) => match maybe_salt {
                        Some(_) => {
                            return Err(Error::Multiple(ErrorDigestType::Salt));
                        }
                        None => {
                            maybe_salt.replace(salt);
                        }
                    },
                    ConsensusLog::NextGlobalRandomness(global_randomness) => {
                        match maybe_next_global_randomness {
                            Some(_) => {
                                return Err(Error::Multiple(ErrorDigestType::NextGlobalRandomness));
                            }
                            None => {
                                maybe_next_global_randomness.replace(global_randomness);
                            }
                        }
                    }
                    ConsensusLog::NextSolutionRange(solution_range) => {
                        match maybe_next_solution_range {
                            Some(_) => {
                                return Err(Error::Multiple(ErrorDigestType::NextSolutionRange));
                            }
                            None => {
                                maybe_next_solution_range.replace(solution_range);
                            }
                        }
                    }
                    ConsensusLog::NextSalt(salt) => match maybe_next_salt {
                        Some(_) => {
                            return Err(Error::Multiple(ErrorDigestType::NextSalt));
                        }
                        None => {
                            maybe_next_salt.replace(salt);
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
                        return Err(Error::Multiple(ErrorDigestType::Seal));
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
            (Some(_), true) => return Err(Error::Multiple(ErrorDigestType::PreDigest)),
            (None, _) => trace!(target: "subspace", "Ignoring digest not meant for us"),
            (s, false) => pre_digest = s,
        }
    }
    pre_digest.ok_or(Error::Missing(ErrorDigestType::PreDigest))
}
