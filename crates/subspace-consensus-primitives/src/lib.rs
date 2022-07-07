// Copyright (C) 2022 Subspace Labs, Inc.
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

//! Subspace consensus primitives

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use schnorrkel::SignatureError;

mod types;
pub use types::*;

mod verification;
pub use verification::*;

mod derivation;
pub use derivation::*;

/// Errors encountered by the Subspace consensus primitives.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ConsensusError {
    /// Tag verification failed
    #[cfg_attr(feature = "thiserror", error("Invalid tag for salt"))]
    InvalidTag,

    /// Piece encoding is invalid
    #[cfg_attr(feature = "thiserror", error("Invalid piece encoding"))]
    InvalidPieceEncoding,

    /// Piece verification failed
    #[cfg_attr(feature = "thiserror", error("Invalid piece"))]
    InvalidPiece,

    /// Invalid Local challenge
    #[cfg_attr(feature = "thiserror", error("Invalid local challenge"))]
    InvalidLocalChallenge(SignatureError),

    /// Solution is outside the challenge range
    #[cfg_attr(feature = "thiserror", error("Solution is outside the solution range"))]
    OutsideSolutionRange,

    /// Invalid solution signature
    #[cfg_attr(feature = "thiserror", error("Invalid solution signature"))]
    InvalidSolutionSignature(SignatureError),

    /// Solution is outside the MaxPlot
    #[cfg_attr(feature = "thiserror", error("Solution is outside max plot"))]
    OutsideMaxPlot,
}
