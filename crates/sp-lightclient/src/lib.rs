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

use sp_api::HeaderT;
use sp_consensus_subspace::digests::{
    find_global_randomness_descriptor, find_pre_digest, find_salt_descriptor,
    find_solution_range_descriptor, Error as DigestError, GlobalRandomnessDescriptor, PreDigest,
    SaltDescriptor, SolutionRangeDescriptor,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use subspace_core_primitives::{Randomness, RecordSize, Salt, SegmentSize, SolutionRange};

#[cfg(test)]
mod tests;

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
}

/// Type to fetch a block header based on the Number or Hash.
pub enum BlockNumberOrHash<Number, Hash> {
    /// Query block header by block number
    Number(Number),
    /// Query block header by block hash
    Hash(Hash),
}

type NumberOf<T> = <T as HeaderT>::Number;
type HashOf<T> = <T as HeaderT>::Hash;

/// Storage responsible for storing headers
pub trait Storage<Header: HeaderT> {
    /// Record size
    fn record_size() -> RecordSize;

    /// Segment size
    fn segment_size() -> SegmentSize;

    /// Queries a header at a specific block number or block hash
    fn header(
        query: BlockNumberOrHash<NumberOf<Header>, HashOf<Header>>,
    ) -> Option<HeaderExt<Header>>;

    /// Stores the extended header.
    fn store_header(header_ext: HeaderExt<Header>);

    /// Prunes the header and all its descendants starting from the query.
    fn prune_header(query: BlockNumberOrHash<NumberOf<Header>, HashOf<Header>>);
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
    InvaildPreDigest,
    /// Invalid slot when compared with parent header
    InvalidSlot,
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
    fn import_header(header: Header) -> Result<(), ImportError<HashOf<Header>>> {
        // check if the header is already imported
        match Self::Storage::header(BlockNumberOrHash::Hash(header.hash())) {
            Some(_) => Err(ImportError::HeaderAlreadyImported),
            None => Ok(()),
        }?;

        // fetch parent header
        let parent_hash = *header.parent_hash();
        let parent_header = Self::Storage::header(BlockNumberOrHash::Hash(parent_hash))
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // verify global randomness, solution range, and salt from the parent header
        let (global_randomness, solution_range, salt) =
            verify_header_digest_with_parent(&parent_header, &header)?;

        // extract subspace pre digest that contains the solution
        let pre_digest = find_pre_digest(&header).map_err(|_| ImportError::InvaildPreDigest)?;

        // slot must be strictly increasing from the parent header
        verify_slot(&parent_header.header, &pre_digest)?;

        // store header
        let header_ext = HeaderExt {
            header,
            derived_global_randomness: global_randomness.global_randomness,
            derived_solution_range: solution_range.solution_range,
            derived_salt: salt.salt,
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
        find_pre_digest(parent_header).map_err(|_| ImportError::InvaildPreDigest)?;

    if pre_digest.slot <= parent_pre_digest.slot {
        return Err(ImportError::InvalidSlot);
    }

    Ok(())
}
