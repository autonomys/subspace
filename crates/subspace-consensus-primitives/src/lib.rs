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

use schnorrkel::context::SigningTranscript;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{PublicKey, Signature, SignatureError, SignatureResult};
use subspace_archiving::archiver;
use subspace_core_primitives::{
    Piece, PieceIndex, PieceIndexHash, Randomness, Salt, Sha256Hash, Solution, Tag, TagSignature,
    RANDOMNESS_CONTEXT, U256,
};
use subspace_solving::{
    create_tag_signature_transcript, derive_global_challenge, derive_target, is_tag_valid,
    verify_local_challenge, verify_tag_signature, SubspaceCodec,
};

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

/// Derive randomness from given key and the tag
pub fn derive_randomness(
    public_key: &PublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness> {
    let in_out = VRFOutput(tag_signature.output)
        .attach_input_hash(public_key, create_tag_signature_transcript(tag))?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Checks the signature validity.
pub fn check_signature<T: SigningTranscript>(
    signature: &Signature,
    public_key: &PublicKey,
    signing_transcript: T,
) -> Result<(), SignatureError> {
    public_key.verify::<T>(signing_transcript, signature)
}

/// Checks if the target range is within the solution range
pub fn is_within_solution_range(target: Tag, tag: Tag, solution_range: u64) -> bool {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) <= solution_range / 2
}

/// Checks if piece index is within farmer sector
pub fn is_within_max_plot(
    piece_index: PieceIndex,
    key: &PublicKey,
    total_pieces: u64,
    max_plot_size: u64,
) -> bool {
    if total_pieces < max_plot_size {
        return true;
    }
    let max_distance_one_direction = U256::MAX / total_pieces * max_plot_size / 2;
    U256::distance(&PieceIndexHash::from_index(piece_index), key.as_ref())
        <= max_distance_one_direction
}

/// Check if the tag of a solution's piece is valid.
pub fn check_piece_tag(salt: Salt, piece: &Piece, tag: Tag) -> Result<(), ConsensusError> {
    if !is_tag_valid(piece, salt, tag) {
        return Err(ConsensusError::InvalidTag);
    }

    Ok(())
}

/// Verifies encoded piece belongs to archival history
pub fn verify_piece(
    encoded_piece: &Piece,
    piece_index: PieceIndex,
    records_root: Sha256Hash,
    position: u64,
    record_size: u32,
    public_key: &PublicKey,
) -> Result<(), ConsensusError> {
    let mut piece = encoded_piece.clone();

    // Ensure piece is decodable.
    let subspace_codec = SubspaceCodec::new(public_key.as_ref());
    subspace_codec
        .decode(&mut piece, piece_index)
        .map_err(|_| ConsensusError::InvalidPieceEncoding)?;

    if !archiver::is_piece_valid(
        &piece,
        records_root,
        position as usize,
        record_size as usize,
    ) {
        return Err(ConsensusError::InvalidPiece);
    }

    Ok(())
}

/// Parameters for checking piece validity
pub struct PieceCheckParams {
    /// Records root of segment to which piece belongs
    pub records_root: Sha256Hash,
    /// Position of the piece in the segment
    pub position: u64,
    /// Record size, system parameter
    pub record_size: u32,
    /// Max plot size in pieces, system parameter
    pub max_plot_size: u64,
    /// Total number of pieces in the whole archival history
    pub total_pieces: u64,
}

/// Parameters for solution verification
pub struct VerifySolutionParams<'a> {
    /// Global randomness
    pub global_randomness: &'a Randomness,
    /// Solution range
    pub solution_range: u64,
    /// Salt
    pub salt: Salt,
    /// Parameters for checking piece validity.
    ///
    /// If `None`, piece validity check will be skipped.
    pub piece_check_params: Option<PieceCheckParams>,
}

/// Solution verification
pub fn verify_solution<FarmerPublicKey, RewardAddress, Slot>(
    solution: &Solution<FarmerPublicKey, RewardAddress>,
    params: VerifySolutionParams<'_>,
    slot: Slot,
) -> Result<(), ConsensusError>
where
    FarmerPublicKey: AsRef<[u8]>,
    Slot: Into<u64>,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        salt,
        piece_check_params,
    } = params;

    let public_key =
        PublicKey::from_bytes(solution.public_key.as_ref()).expect("Always correct length; qed");

    let slot = slot.into();
    // verify local challenge
    verify_local_challenge(
        &public_key,
        derive_global_challenge(global_randomness, slot),
        &solution.local_challenge,
    )
    .map_err(ConsensusError::InvalidLocalChallenge)?;

    let target = derive_target(
        &public_key,
        derive_global_challenge(global_randomness, slot),
        &solution.local_challenge,
    )
    .map_err(ConsensusError::InvalidLocalChallenge)?;

    if !is_within_solution_range(solution.tag, target, solution_range) {
        return Err(ConsensusError::OutsideSolutionRange);
    }

    verify_tag_signature(solution.tag, &solution.tag_signature, &public_key)
        .map_err(ConsensusError::InvalidSolutionSignature)?;

    check_piece_tag(salt, &solution.encoding, solution.tag)?;

    if let Some(PieceCheckParams {
        records_root,
        position,
        record_size,
        max_plot_size,
        total_pieces,
    }) = piece_check_params
    {
        if !is_within_max_plot(
            solution.piece_index,
            &public_key,
            total_pieces,
            max_plot_size,
        ) {
            return Err(ConsensusError::OutsideMaxPlot);
        }

        verify_piece(
            &solution.encoding,
            solution.piece_index,
            records_root,
            position,
            record_size,
            &public_key,
        )?;
    }

    Ok(())
}
