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
#![feature(array_chunks, portable_simd)]
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use core::mem;
use core::simd::Simd;
use schnorrkel::context::SigningContext;
use schnorrkel::SignatureError;
use sp_arithmetic::traits::SaturatedConversion;
use subspace_archiving::archiver;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::crypto::{
    blake2b_256_254_hash_to_scalar, blake2b_256_hash_list, blake2b_256_hash_with_key,
};
use subspace_core_primitives::{
    Blake2b256Hash, BlockNumber, BlockWeight, HistorySize, PublicKey, Randomness, Record,
    RewardSignature, SectorId, SectorSlotChallenge, SegmentCommitment, SlotNumber, Solution,
    SolutionRange,
};
use subspace_proof_of_space::Table;

/// Errors encountered by the Subspace consensus primitives.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
    /// Invalid piece offset
    #[cfg_attr(feature = "thiserror", error("Piece verification failed"))]
    InvalidPieceOffset {
        /// Index of the piece that failed verification
        piece_offset: u16,
        /// How many pieces one sector is supposed to contain (max)
        max_pieces_in_sector: u16,
    },
    /// Sector expired
    #[cfg_attr(feature = "thiserror", error("Sector expired"))]
    SectorExpired {
        /// Expiration history size
        expiration_history_size: HistorySize,
        /// Current history size
        current_history_size: HistorySize,
    },
    /// Piece verification failed
    #[cfg_attr(feature = "thiserror", error("Piece verification failed"))]
    InvalidPiece,
    /// Solution is outside of challenge range
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Solution distance {solution_distance} is outside of solution range \
            {half_solution_range} (half of actual solution range)"
        )
    )]
    OutsideSolutionRange {
        /// Half of solution range
        half_solution_range: SolutionRange,
        /// Solution distance
        solution_distance: SolutionRange,
    },
    /// Invalid proof of space
    #[cfg_attr(feature = "thiserror", error("Invalid proof of space"))]
    InvalidProofOfSpace,
    /// Invalid audit chunk offset
    #[cfg_attr(feature = "thiserror", error("Invalid audit chunk offset"))]
    InvalidAuditChunkOffset,
    /// Invalid chunk witness
    #[cfg_attr(feature = "thiserror", error("Invalid chunk witness"))]
    InvalidChunkWitness,
    /// Invalid history size
    #[cfg_attr(feature = "thiserror", error("Invalid history size"))]
    InvalidHistorySize,
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

/// Calculates solution distance for given parameters, is used as a primitive to check whether
/// solution distance is within solution range (see [`is_within_solution_range()`]).
fn calculate_solution_distance(
    global_challenge: &Blake2b256Hash,
    audit_chunk: SolutionRange,
    sector_slot_challenge: &SectorSlotChallenge,
) -> SolutionRange {
    let global_challenge_as_solution_range: SolutionRange = SolutionRange::from_le_bytes(
        *global_challenge
            .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
            .next()
            .expect("Solution range is smaller in size than global challenge; qed"),
    );
    let sector_slot_challenge_with_audit_chunk =
        blake2b_256_hash_with_key(sector_slot_challenge.as_ref(), &audit_chunk.to_le_bytes());
    let sector_slot_challenge_with_audit_chunk_as_solution_range: SolutionRange =
        SolutionRange::from_le_bytes(
            *sector_slot_challenge_with_audit_chunk
                .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
                .next()
                .expect("Solution range is smaller in size than blake2b-256 hash; qed"),
        );
    subspace_core_primitives::bidirectional_distance(
        &global_challenge_as_solution_range,
        &sector_slot_challenge_with_audit_chunk_as_solution_range,
    )
}

/// Returns true if solution distance is within the solution range for provided parameters.
pub fn is_within_solution_range(
    global_challenge: &Blake2b256Hash,
    audit_chunk: SolutionRange,
    sector_slot_challenge: &SectorSlotChallenge,
    solution_range: SolutionRange,
) -> bool {
    calculate_solution_distance(global_challenge, audit_chunk, sector_slot_challenge)
        <= solution_range / 2
}

/// Parameters for checking piece validity
#[derive(Debug, Clone, Encode, Decode, MaxEncodedLen)]
pub struct PieceCheckParams {
    /// How many pieces one sector is supposed to contain (max)
    pub max_pieces_in_sector: u16,
    /// Segment commitment of segment to which piece belongs
    pub segment_commitment: SegmentCommitment,
    /// Number of latest archived segments that are considered "recent history"
    pub recent_segments: HistorySize,
    /// Fraction of pieces from the "recent history" (`recent_segments`) in each sector
    pub recent_history_fraction: (HistorySize, HistorySize),
    /// Minimum lifetime of a plotted sector, measured in archived segment
    pub min_sector_lifetime: HistorySize,
    /// Current size of the history
    pub current_history_size: HistorySize,
    /// Segment commitment at `min_sector_lifetime` from sector creation (if exists)
    pub sector_expiration_check_segment_commitment: Option<SegmentCommitment>,
}

/// Parameters for solution verification
#[derive(Debug, Clone, Encode, Decode, MaxEncodedLen)]
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

/// Calculate weight derived from provided solution range
pub fn calculate_block_weight(solution_range: SolutionRange) -> BlockWeight {
    BlockWeight::from(SolutionRange::MAX - solution_range)
}

/// Verify whether solution is valid, returns solution distance that is `<= solution_range/2` on
/// success.
pub fn verify_solution<'a, PosTable, FarmerPublicKey, RewardAddress>(
    solution: &'a Solution<FarmerPublicKey, RewardAddress>,
    slot: SlotNumber,
    params: &'a VerifySolutionParams,
    kzg: &'a Kzg,
) -> Result<SolutionRange, Error>
where
    PosTable: Table,
    PublicKey: From<&'a FarmerPublicKey>,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        piece_check_params,
    } = params;

    let sector_id = SectorId::new(
        PublicKey::from(&solution.public_key).hash(),
        solution.sector_index,
    );

    let global_challenge = global_randomness.derive_global_challenge(slot);
    let sector_slot_challenge = sector_id.derive_sector_slot_challenge(&global_challenge);
    let s_bucket_audit_index = sector_slot_challenge.s_bucket_audit_index();

    // Check that proof of space is valid
    if PosTable::is_proof_valid(
        &sector_id.derive_evaluation_seed(solution.piece_offset, solution.history_size),
        s_bucket_audit_index.into(),
        &solution.proof_of_space,
    )
    .is_none()
    {
        return Err(Error::InvalidProofOfSpace);
    };

    let masked_chunk = (Simd::from(solution.chunk.to_bytes())
        ^ Simd::from(solution.proof_of_space.hash()))
    .to_array();
    // Extract audit chunk from masked chunk
    let audit_chunk = match masked_chunk
        .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
        .nth(usize::from(solution.audit_chunk_offset))
    {
        Some(audit_chunk) => SolutionRange::from_le_bytes(*audit_chunk),
        None => {
            return Err(Error::InvalidAuditChunkOffset);
        }
    };

    let solution_distance =
        calculate_solution_distance(&global_challenge, audit_chunk, &sector_slot_challenge);

    // Check that solution is within solution range
    if solution_distance > solution_range / 2 {
        return Err(Error::OutsideSolutionRange {
            half_solution_range: solution_range / 2,
            solution_distance,
        });
    }

    // Check that chunk belongs to the record
    if !kzg.verify(
        &solution.record_commitment,
        Record::NUM_S_BUCKETS,
        s_bucket_audit_index.into(),
        &solution.chunk,
        &solution.chunk_witness,
    ) {
        return Err(Error::InvalidChunkWitness);
    }

    // TODO: Check if sector already expired once we have such notion

    if let Some(PieceCheckParams {
        max_pieces_in_sector,
        segment_commitment,
        recent_segments,
        recent_history_fraction,
        min_sector_lifetime,
        current_history_size,
        sector_expiration_check_segment_commitment,
    }) = piece_check_params
    {
        if u16::from(solution.piece_offset) >= *max_pieces_in_sector {
            return Err(Error::InvalidPieceOffset {
                piece_offset: u16::from(solution.piece_offset),
                max_pieces_in_sector: *max_pieces_in_sector,
            });
        }
        if let Some(sector_expiration_check_segment_commitment) =
            sector_expiration_check_segment_commitment
        {
            let expiration_history_size = match sector_id.derive_expiration_history_size(
                solution.history_size,
                sector_expiration_check_segment_commitment,
                *min_sector_lifetime,
            ) {
                Some(expiration_history_size) => expiration_history_size,
                None => {
                    return Err(Error::InvalidHistorySize);
                }
            };

            if expiration_history_size <= *current_history_size {
                return Err(Error::SectorExpired {
                    expiration_history_size,
                    current_history_size: *current_history_size,
                });
            }
        }

        let position = sector_id
            .derive_piece_index(
                solution.piece_offset,
                solution.history_size,
                *max_pieces_in_sector,
                *recent_segments,
                *recent_history_fraction,
            )
            .position();

        // Check that piece is part of the blockchain history
        if !archiver::is_record_commitment_hash_valid(
            kzg,
            &blake2b_256_254_hash_to_scalar(&solution.record_commitment.to_bytes()),
            segment_commitment,
            &solution.record_witness,
            position,
        ) {
            return Err(Error::InvalidPiece);
        }
    }

    Ok(solution_distance)
}

/// Derive on-chain randomness from solution.
pub fn derive_randomness<PublicKey, RewardAddress>(
    solution: &Solution<PublicKey, RewardAddress>,
    slot: SlotNumber,
) -> Randomness {
    Randomness::from(blake2b_256_hash_list(&[
        &solution.chunk.to_bytes(),
        &slot.to_le_bytes(),
    ]))
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
