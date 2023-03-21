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

//! Verification primitives for Subspace.
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use schnorrkel::context::SigningContext;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{SignatureError, SignatureResult};
use sp_arithmetic::traits::SaturatedConversion;
use subspace_archiving::archiver;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    BlockNumber, ChunkSignature, PieceIndex, PublicKey, Randomness, RecordsRoot, RewardSignature,
    Scalar, SectorId, SlotNumber, Solution, SolutionRange, PIECES_IN_SECTOR, RANDOMNESS_CONTEXT,
};
use subspace_solving::{
    create_chunk_signature_transcript, derive_global_challenge, verify_chunk_signature,
};

/// Errors encountered by the Subspace consensus primitives.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
    /// Piece verification failed
    #[cfg_attr(feature = "thiserror", error("Invalid piece"))]
    InvalidPiece,

    /// Solution is outside the challenge range
    #[cfg_attr(feature = "thiserror", error("Solution is outside the solution range"))]
    OutsideSolutionRange,

    /// Invalid solution signature
    #[cfg_attr(feature = "thiserror", error("Invalid solution signature"))]
    InvalidSolutionSignature(SignatureError),

    /// Missing KZG instance
    #[cfg_attr(feature = "thiserror", error("Missing KZG instance"))]
    MissingKzgInstance,
}

/// Check the reward signature validity.
pub fn check_reward_signature(
    hash: &[u8],
    signature: &RewardSignature,
    public_key: &PublicKey,
    reward_signing_context: &SigningContext,
) -> Result<(), SignatureError> {
    let public_key = schnorrkel::PublicKey::from_bytes(public_key.as_ref())?;
    let signature = schnorrkel::Signature::from_bytes(signature.as_ref())?;
    public_key.verify(reward_signing_context.bytes(hash), &signature)
}

/// Check piece validity.
///
/// If `records_root` is `None`, piece validity check will be skipped.
pub fn check_piece<'a, FarmerPublicKey, RewardAddress>(
    kzg: &Kzg,
    pieces_in_segment: u32,
    records_root: &RecordsRoot,
    position: u32,
    solution: &'a Solution<FarmerPublicKey, RewardAddress>,
) -> Result<(), Error>
where
    &'a FarmerPublicKey: Into<PublicKey>,
{
    if !archiver::is_piece_record_hash_valid(
        kzg,
        pieces_in_segment,
        &solution.piece_record_hash,
        records_root,
        &solution.piece_witness,
        position,
    ) {
        return Err(Error::InvalidPiece);
    }

    Ok(())
}

/// Derive audit chunk from scalar bytes contained within plotted piece
pub fn derive_audit_chunk(chunk_bytes: &[u8; Scalar::FULL_BYTES]) -> SolutionRange {
    let hash = blake2b_256_hash(chunk_bytes);
    SolutionRange::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// Returns true if `solution.tag` is within the solution range.
pub fn is_within_solution_range(
    local_challenge: SolutionRange,
    audit_chunk: SolutionRange,
    solution_range: SolutionRange,
) -> bool {
    subspace_core_primitives::bidirectional_distance(&local_challenge, &audit_chunk)
        <= solution_range / 2
}

/// Parameters for checking piece validity
#[derive(Debug)]
pub struct PieceCheckParams {
    /// Records root of segment to which piece belongs
    pub records_root: RecordsRoot,
    /// Number of pieces in a segment
    pub pieces_in_segment: u32,
}

/// Parameters for solution verification
#[derive(Debug)]
pub struct VerifySolutionParams {
    /// Global randomness
    pub global_randomness: Randomness,
    /// Solution range
    pub solution_range: SolutionRange,
    /// Parameters for checking piece validity.
    ///
    /// If `None`, piece validity check will be skipped.
    pub piece_check_params: Option<PieceCheckParams>,
}

/// Solution verification.
///
/// KZG needs to be provided if [`VerifySolutionParams::piece_check_params`] is not `None`.
pub fn verify_solution<'a, FarmerPublicKey, RewardAddress>(
    solution: &'a Solution<FarmerPublicKey, RewardAddress>,
    slot: u64,
    params: &VerifySolutionParams,
    kzg: Option<&Kzg>,
) -> Result<(), Error>
where
    PublicKey: From<&'a FarmerPublicKey>,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        piece_check_params,
    } = params;

    let public_key = PublicKey::from(&solution.public_key);

    let sector_id = SectorId::new(&public_key, solution.sector_index);

    let local_challenge =
        sector_id.derive_local_challenge(&derive_global_challenge(global_randomness, slot));

    let chunk_bytes = solution.chunk.to_bytes();

    if !is_within_solution_range(
        local_challenge,
        derive_audit_chunk(&chunk_bytes),
        *solution_range,
    ) {
        return Err(Error::OutsideSolutionRange);
    }

    if let Err(error) = verify_chunk_signature(
        &chunk_bytes,
        &solution.chunk_signature,
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())
            .expect("Always correct length; qed"),
    ) {
        return Err(Error::InvalidSolutionSignature(error));
    }

    // TODO: Check if sector already expired once we have such notion

    if let Some(PieceCheckParams {
        records_root,
        pieces_in_segment,
    }) = piece_check_params
    {
        let audit_piece_offset: PieceIndex = local_challenge % PIECES_IN_SECTOR;
        let piece_index = sector_id.derive_piece_index(audit_piece_offset, solution.total_pieces);
        let position = u32::try_from(piece_index % u64::from(*pieces_in_segment))
            .expect("Position within segment always fits into u32; qed");

        // TODO: Check that chunk belongs to the encoded piece
        let kzg = match kzg {
            Some(kzg) => kzg,
            None => {
                return Err(Error::MissingKzgInstance);
            }
        };
        check_piece(kzg, *pieces_in_segment, records_root, position, solution)?;
    }

    Ok(())
}

/// Derive on-chain randomness from chunk signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness(
    public_key: &PublicKey,
    chunk_bytes: &[u8; Scalar::FULL_BYTES],
    chunk_signature: &ChunkSignature,
) -> SignatureResult<Randomness> {
    let in_out = VRFOutput(chunk_signature.output).attach_input_hash(
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?,
        create_chunk_signature_transcript(chunk_bytes),
    )?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Derives next solution range based on the total era slots and slot probability
pub fn derive_next_solution_range(
    start_slot: SlotNumber,
    current_slot: SlotNumber,
    slot_probability: (u64, u64),
    current_solution_range: SolutionRange,
    era_duration: BlockNumber,
) -> u64 {
    // calculate total slots within this era
    let era_slot_count = current_slot - start_slot;

    // Now we need to re-calculate solution range. The idea here is to keep block production at
    // the same pace while space pledged on the network changes. For this we adjust previous
    // solution range according to actual and expected number of blocks per era.

    // Below is code analogous to the following, but without using floats:
    // ```rust
    // let actual_slots_per_block = era_slot_count as f64 / era_duration as f64;
    // let expected_slots_per_block =
    //     slot_probability.1 as f64 / slot_probability.0 as f64;
    // let adjustment_factor =
    //     (actual_slots_per_block / expected_slots_per_block).clamp(0.25, 4.0);
    //
    // next_solution_range =
    //     (solution_ranges.current as f64 * adjustment_factor).round() as u64;
    // ```
    u64::saturated_from(
        u128::from(current_solution_range)
            .saturating_mul(u128::from(era_slot_count))
            .saturating_mul(u128::from(slot_probability.0))
            / u128::from(era_duration)
            / u128::from(slot_probability.1),
    )
    .clamp(
        current_solution_range / 4,
        current_solution_range.saturating_mul(4),
    )
}
