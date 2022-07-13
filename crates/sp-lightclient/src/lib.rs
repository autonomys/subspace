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

/// HeaderExt describes the block chain header at a specific height along with some computed values.
pub struct HeaderExt<Header> {
    /// Actual header light client imported
    pub header: Header,
}

/// Storage responsible for storing headers
pub trait Storage {}

/// Error during the header import.
pub enum ImportError {}

/// Verifies and import headers.
pub trait HeaderImporter {
    /// Storage type to store headers and other computed details
    type Storage: Storage;

    /// Verifies header, computes consensus values for block progress and stores the HeaderExt
    fn import_header<Header>(header: Header) -> Result<HeaderExt<Header>, ImportError>;
}
