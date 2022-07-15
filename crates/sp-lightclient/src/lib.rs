// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

//! Light client substrate primitives for Subspace.
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use sp_consensus_subspace::digests::{
    find_global_randomness_descriptor, find_pre_digest, find_salt_descriptor,
    find_solution_range_descriptor, CompatibleDigestItem, Error as DigestError,
    GlobalRandomnessDescriptor, PreDigest, SaltDescriptor, SolutionRangeDescriptor,
};
use sp_consensus_subspace::FarmerPublicKey;
use sp_runtime::traits::Header as HeaderT;
use sp_std::cmp::Ordering;
use subspace_core_primitives::{PublicKey, Randomness, RewardSignature, Salt};
use subspace_solving::{derive_global_challenge, derive_target, REWARD_SIGNING_CONTEXT};
use subspace_verification::{check_reward_signature, verify_solution, VerifySolutionParams};

#[cfg(test)]
mod tests;

// TODO(ved): move them to consensus primitives and change usages across
/// Type of solution range
type SolutionRange = u64;

/// The size of data in one piece (in bytes).
type RecordSize = u32;

/// The size of encoded and plotted piece in segments of this size (in bytes).
type SegmentSize = u32;

/// BlockWeight type for fork choice rules
type BlockWeight = u128;

/// HeaderExt describes an extended block chain header at a specific height along with some computed values.
pub struct HeaderExt<Header> {
    /// Actual header of the subspace block chain at a specific height
    pub header: Header,
    /// Global randomness after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_global_randomness: Randomness,
    /// Solution range after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_solution_range: SolutionRange,
    /// Salt after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_salt: Salt,
    /// Cumulative weight of chain until this header
    pub total_weight: BlockWeight,
}

type HashOf<T> = <T as HeaderT>::Hash;

/// Storage responsible for storing headers
pub trait Storage<Header: HeaderT> {
    /// Record size
    fn record_size() -> RecordSize;

    /// Segment size
    fn segment_size() -> SegmentSize;

    /// Queries a header at a specific block number or block hash
    fn header(query: HashOf<Header>) -> Option<HeaderExt<Header>>;

    /// Stores the extended header.
    fn store_header(header_ext: HeaderExt<Header>);

    /// Prunes all the descendants of the header.
    fn prune_descendants_of(query: HashOf<Header>);

    /// Returns the best known tip of the chain
    fn best_header() -> HeaderExt<Header>;
}

/// Error during the header import.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError<Hash> {
    /// Header already imported.
    HeaderAlreadyImported,
    /// Missing parent header
    MissingParent(Hash),
    /// Error while extracting digests from header
    DigestExtractionError(DigestError),
    /// Invalid global randomness digest
    InvalidGlobalRandomnessDigest,
    /// Invalid solution range digest
    InvalidSolutionRangeDigest,
    /// Invalid salt digest
    InvalidSaltDigest,
    /// Invalid predigest
    InvalidPreDigest,
    /// Invalid slot when compared with parent header
    InvalidSlot,
    /// Block signature is invalid
    InvalidBlockSignature,
    /// Invalid solution
    InvalidSolution,
    /// Header being imported is part of non canonical chain
    NonCanonicalHeader,
}

impl<Hash> From<DigestError> for ImportError<Hash> {
    fn from(error: DigestError) -> Self {
        ImportError::DigestExtractionError(error)
    }
}

/// Verifies and import headers.
pub trait HeaderImporter<Header: HeaderT> {
    /// Storage type to store headers and other computed details.
    type Storage: Storage<Header>;

    /// Verifies header, computes consensus values for block progress and stores the HeaderExt.
    fn import_header(mut header: Header) -> Result<(), ImportError<HashOf<Header>>> {
        // check if the header is already imported
        match Self::Storage::header(header.hash()) {
            Some(_) => Err(ImportError::HeaderAlreadyImported),
            None => Ok(()),
        }?;

        // fetch parent header
        let parent_header = Self::Storage::header(*header.parent_hash())
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // TODO(ved): check for farmer equivocation

        // verify global randomness, solution range, and salt from the parent header
        let (global_randomness, solution_range, salt) =
            verify_header_digest_with_parent(&parent_header, &header)?;

        // extract subspace pre digest that contains the solution
        let pre_digest = find_pre_digest(&header).map_err(|_| ImportError::InvalidPreDigest)?;

        // slot must be strictly increasing from the parent header
        verify_slot(&parent_header.header, &pre_digest)?;

        // verify block signature
        verify_block_signature(&mut header, &pre_digest.solution.public_key)?;

        // verify solution
        verify_solution(
            &pre_digest.solution,
            pre_digest.slot.into(),
            VerifySolutionParams {
                global_randomness: &global_randomness.global_randomness,
                solution_range: solution_range.solution_range,
                salt: salt.salt,
                // TODO(ved): verify POAS once we have access to record root
                piece_check_params: None,
            },
        )
        .map_err(|_| ImportError::InvalidSolution)?;

        let block_weight =
            calculate_block_weight(&global_randomness.global_randomness, &pre_digest);
        let total_weight = parent_header.total_weight + block_weight;

        // last best header should ideally be parent header. if not check for forks and prune accordingly
        let last_best_header = Self::Storage::best_header();
        if last_best_header.header.hash() != parent_header.header.hash() {
            let last_best_weight = last_best_header.total_weight;
            let should_prune_and_import = match total_weight.cmp(&last_best_weight) {
                // current weight is greater than last best. pick this header
                Ordering::Greater => true,
                // if weights are equal, pick the longest chain
                Ordering::Equal => header.number() > last_best_header.header.number(),
                // we already are on the best chain
                Ordering::Less => false,
            };

            if !should_prune_and_import {
                return Err(ImportError::NonCanonicalHeader);
            }

            // re-org: prune all the descendants of the parent header and them import this header as best
            Self::Storage::prune_descendants_of(parent_header.header.hash());
        };

        // TODO(ved): derive randomness, solution range, salt if interval is met
        // TODO(ved): extract record roots from the header
        // TODO(ved); extract an equivocations from the header

        // store header
        let header_ext = HeaderExt {
            header,
            derived_global_randomness: global_randomness.global_randomness,
            derived_solution_range: solution_range.solution_range,
            derived_salt: salt.salt,
            total_weight,
        };
        Self::Storage::store_header(header_ext);

        Ok(())
    }
}

fn extract_header_digests<Header: HeaderT>(
    header: &Header,
) -> Result<
    (
        GlobalRandomnessDescriptor,
        SolutionRangeDescriptor,
        SaltDescriptor,
    ),
    ImportError<HashOf<Header>>,
> {
    let randomness = find_global_randomness_descriptor(header)?
        .ok_or(ImportError::InvalidGlobalRandomnessDigest)?;

    let solution_range =
        find_solution_range_descriptor(header)?.ok_or(ImportError::InvalidSolutionRangeDigest)?;

    let salt = find_salt_descriptor(header)?.ok_or(ImportError::InvalidSaltDigest)?;

    Ok((randomness, solution_range, salt))
}

fn verify_header_digest_with_parent<Header: HeaderT>(
    parent_header: &HeaderExt<Header>,
    header: &Header,
) -> Result<
    (
        GlobalRandomnessDescriptor,
        SolutionRangeDescriptor,
        SaltDescriptor,
    ),
    ImportError<HashOf<Header>>,
> {
    let (global_randomness, solution_range, salt) = extract_header_digests(header)?;
    if global_randomness.global_randomness != parent_header.derived_global_randomness {
        return Err(ImportError::InvalidGlobalRandomnessDigest);
    }

    if solution_range.solution_range != parent_header.derived_solution_range {
        return Err(ImportError::InvalidSolutionRangeDigest);
    }

    if salt.salt != parent_header.derived_salt {
        return Err(ImportError::InvalidSaltDigest);
    }

    Ok((global_randomness, solution_range, salt))
}

fn verify_slot<Header: HeaderT>(
    parent_header: &Header,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> Result<(), ImportError<HashOf<Header>>> {
    let parent_pre_digest =
        find_pre_digest(parent_header).map_err(|_| ImportError::InvalidPreDigest)?;

    if pre_digest.slot <= parent_pre_digest.slot {
        return Err(ImportError::InvalidSlot);
    }

    Ok(())
}

// verifies the block signature present as part of the last digest log
fn verify_block_signature<Header: HeaderT>(
    header: &mut Header,
    public_key: &FarmerPublicKey,
) -> Result<(), ImportError<HashOf<Header>>> {
    let seal = header
        .digest_mut()
        .pop()
        .ok_or(ImportError::InvalidBlockSignature)?;

    let signature = seal
        .as_subspace_seal()
        .ok_or(ImportError::InvalidBlockSignature)?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    // Verify that block is signed properly
    check_reward_signature(
        pre_hash.as_ref(),
        &Into::<RewardSignature>::into(&signature),
        &Into::<PublicKey>::into(public_key),
        &schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
    )
    .map_err(|_| ImportError::InvalidBlockSignature)?;

    // push the seal back into the header
    header.digest_mut().push(seal);
    Ok(())
}

fn calculate_block_weight(
    global_randomness: &Randomness,
    pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
) -> BlockWeight {
    let global_challenge = derive_global_challenge(global_randomness, pre_digest.slot.into());

    let target = u64::from_be_bytes(
        derive_target(
            &schnorrkel::PublicKey::from_bytes(pre_digest.solution.public_key.as_ref())
                .expect("Always correct length; qed"),
            global_challenge,
            &pre_digest.solution.local_challenge,
        )
        .expect("Verification of the local challenge was done before this; qed"),
    );
    let tag = u64::from_be_bytes(pre_digest.solution.tag);
    u128::from(u64::MAX - subspace_core_primitives::bidirectional_distance(&target, &tag))
}
