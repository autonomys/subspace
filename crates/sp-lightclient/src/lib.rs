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
use subspace_core_primitives::{Randomness, RecordSize, Salt, SegmentSize, SolutionRange};

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

type NumberOf<T> = <<T as Storage>::Header as HeaderT>::Number;
type HashOf<T> = <<T as Storage>::Header as HeaderT>::Hash;

/// Storage responsible for storing headers
pub trait Storage {
    /// Actual header of the subspace block chain at a specific block number
    type Header: HeaderT;

    /// Record size
    fn record_size() -> RecordSize;

    /// Segment size
    fn segment_size() -> SegmentSize;

    /// Queries a header at a specific block number or block hash
    fn header(
        query: BlockNumberOrHash<NumberOf<Self>, HashOf<Self>>,
    ) -> Option<HeaderExt<Self::Header>>;

    /// Stores the extended header.
    fn store_header(header_ext: HeaderExt<Self::Header>);

    /// Prunes the header and all its descendants starting from the query.
    fn prune_header(query: BlockNumberOrHash<NumberOf<Self>, HashOf<Self>>);
}

type StorageHeaderOf<T> = <T as Storage>::Header;

/// Error during the header import.
pub enum ImportError<Hash> {
    /// Header already imported.
    HeaderAlreadyImported,
    /// Missing parent header
    MissingParent(Hash),
}

/// Verifies and import headers.
pub trait HeaderImporter {
    /// Storage type to store headers and other computed details.
    type Storage: Storage;

    /// Verifies header, computes consensus values for block progress and stores the HeaderExt.
    fn import_header(
        header: StorageHeaderOf<Self::Storage>,
    ) -> Result<(), ImportError<HashOf<Self::Storage>>> {
        // check if the header is already imported
        match Self::Storage::header(BlockNumberOrHash::Hash(header.hash())) {
            Some(_) => Err(ImportError::HeaderAlreadyImported),
            None => Ok(()),
        }?;

        // fetch parent header
        let parent_hash = *header.parent_hash();
        let parent_header = Self::Storage::header(BlockNumberOrHash::Hash(parent_hash))
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // store header
        let header_ext = HeaderExt {
            header,
            derived_global_randomness: parent_header.derived_global_randomness,
            derived_solution_range: parent_header.derived_solution_range,
            derived_salt: parent_header.derived_salt,
        };
        Self::Storage::store_header(header_ext);

        Ok(())
    }
}
