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
// `generic_const_exprs` is an incomplete feature
#![allow(incomplete_features)]
// TODO: This feature is not actually used in this crate, but is added as a workaround for
//  https://github.com/rust-lang/rust/issues/133199
#![feature(generic_const_exprs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(all(feature = "kzg", not(feature = "std")))]
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use core::mem;
#[cfg(feature = "kzg")]
use core::simd::Simd;
use schnorrkel::context::SigningContext;
use schnorrkel::SignatureError;
#[cfg(feature = "kzg")]
use subspace_core_primitives::hashes::blake3_254_hash_to_scalar;
use subspace_core_primitives::hashes::{blake3_hash_list, blake3_hash_with_key, Blake3Hash};
#[cfg(feature = "kzg")]
use subspace_core_primitives::pieces::{PieceArray, Record, RecordWitness};
use subspace_core_primitives::pot::PotOutput;
#[cfg(feature = "kzg")]
use subspace_core_primitives::sectors::SectorId;
use subspace_core_primitives::sectors::SectorSlotChallenge;
#[cfg(feature = "kzg")]
use subspace_core_primitives::segments::ArchivedHistorySegment;
use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
#[cfg(feature = "kzg")]
use subspace_core_primitives::solutions::Solution;
use subspace_core_primitives::solutions::{RewardSignature, SolutionRange};
use subspace_core_primitives::{BlockNumber, BlockWeight, PublicKey, ScalarBytes, SlotNumber};
#[cfg(feature = "kzg")]
use subspace_kzg::{Commitment, Kzg, Scalar, Witness};
#[cfg(feature = "kzg")]
use subspace_proof_of_space::Table;

/// Errors encountered by the Subspace consensus primitives.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Invalid piece offset
    #[error("Piece verification failed")]
    InvalidPieceOffset {
        /// Index of the piece that failed verification
        piece_offset: u16,
        /// How many pieces one sector is supposed to contain (max)
        max_pieces_in_sector: u16,
    },
    /// Sector expired
    #[error("Sector expired")]
    SectorExpired {
        /// Expiration history size
        expiration_history_size: HistorySize,
        /// Current history size
        current_history_size: HistorySize,
    },
    /// Piece verification failed
    #[error("Piece verification failed")]
    InvalidPiece,
    /// Solution is outside of challenge range
    #[error(
        "Solution distance {solution_distance} is outside of solution range \
        {half_solution_range} (half of actual solution range)"
    )]
    OutsideSolutionRange {
        /// Half of solution range
        half_solution_range: SolutionRange,
        /// Solution distance
        solution_distance: SolutionRange,
    },
    /// Invalid proof of space
    #[error("Invalid proof of space")]
    InvalidProofOfSpace,
    /// Invalid audit chunk offset
    #[error("Invalid audit chunk offset")]
    InvalidAuditChunkOffset,
    /// Invalid chunk
    #[error("Invalid chunk: {0}")]
    InvalidChunk(String),
    /// Invalid chunk witness
    #[error("Invalid chunk witness")]
    InvalidChunkWitness,
    /// Invalid history size
    #[error("Invalid history size")]
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
    global_challenge: &Blake3Hash,
    chunk: &[u8; 32],
    sector_slot_challenge: &SectorSlotChallenge,
) -> SolutionRange {
    let audit_chunk = blake3_hash_with_key(sector_slot_challenge, chunk);
    let audit_chunk_as_solution_range: SolutionRange = SolutionRange::from_le_bytes(
        *audit_chunk
            .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
            .next()
            .expect("Solution range is smaller in size than global challenge; qed"),
    );
    let global_challenge_as_solution_range: SolutionRange = SolutionRange::from_le_bytes(
        *global_challenge
            .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
            .next()
            .expect("Solution range is smaller in size than global challenge; qed"),
    );
    subspace_core_primitives::solutions::bidirectional_distance(
        &global_challenge_as_solution_range,
        &audit_chunk_as_solution_range,
    )
}

/// Returns `Some(solution_distance)` if solution distance is within the solution range for provided
/// parameters.
pub fn is_within_solution_range(
    global_challenge: &Blake3Hash,
    chunk: &[u8; 32],
    sector_slot_challenge: &SectorSlotChallenge,
    solution_range: SolutionRange,
) -> Option<SolutionRange> {
    let solution_distance =
        calculate_solution_distance(global_challenge, chunk, sector_slot_challenge);
    (solution_distance <= solution_range / 2).then_some(solution_distance)
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
    /// Proof of time for which solution is built
    pub proof_of_time: PotOutput,
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
#[cfg(feature = "kzg")]
pub fn verify_solution<'a, PosTable, RewardAddress>(
    solution: &'a Solution<RewardAddress>,
    slot: SlotNumber,
    params: &'a VerifySolutionParams,
    kzg: &'a Kzg,
) -> Result<SolutionRange, Error>
where
    PosTable: Table,
{
    let VerifySolutionParams {
        proof_of_time,
        solution_range,
        piece_check_params,
    } = params;

    let sector_id = SectorId::new(
        solution.public_key.hash(),
        solution.sector_index,
        solution.history_size,
    );

    let global_randomness = proof_of_time.derive_global_randomness();
    let global_challenge = global_randomness.derive_global_challenge(slot);
    let sector_slot_challenge = sector_id.derive_sector_slot_challenge(&global_challenge);
    let s_bucket_audit_index = sector_slot_challenge.s_bucket_audit_index();

    // Check that proof of space is valid
    if !PosTable::is_proof_valid(
        &sector_id.derive_evaluation_seed(solution.piece_offset),
        s_bucket_audit_index.into(),
        &solution.proof_of_space,
    ) {
        return Err(Error::InvalidProofOfSpace);
    };

    let masked_chunk =
        (Simd::from(*solution.chunk) ^ Simd::from(*solution.proof_of_space.hash())).to_array();

    let solution_distance =
        calculate_solution_distance(&global_challenge, &masked_chunk, &sector_slot_challenge);

    // Check that solution is within solution range
    if solution_distance > solution_range / 2 {
        return Err(Error::OutsideSolutionRange {
            half_solution_range: solution_range / 2,
            solution_distance,
        });
    }

    // Check that chunk belongs to the record
    if !kzg.verify(
        &Commitment::try_from(solution.record_commitment)
            .map_err(|_error| Error::InvalidChunkWitness)?,
        Record::NUM_S_BUCKETS,
        s_bucket_audit_index.into(),
        &Scalar::try_from(solution.chunk).map_err(Error::InvalidChunk)?,
        &Witness::try_from(solution.chunk_witness).map_err(|_error| Error::InvalidChunkWitness)?,
    ) {
        return Err(Error::InvalidChunkWitness);
    }

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
        if !is_record_commitment_hash_valid(
            kzg,
            &Scalar::try_from(blake3_254_hash_to_scalar(
                solution.record_commitment.as_ref(),
            ))
            .expect("Create correctly by dedicated hash function; qed"),
            segment_commitment,
            &solution.record_witness,
            position,
        ) {
            return Err(Error::InvalidPiece);
        }
    }

    Ok(solution_distance)
}

/// Validate witness embedded within a piece produced by archiver
#[cfg(feature = "kzg")]
pub fn is_piece_valid(
    kzg: &Kzg,
    piece: &PieceArray,
    segment_commitment: &SegmentCommitment,
    position: u32,
) -> bool {
    let (record, commitment, witness) = piece.split();
    let witness = match Witness::try_from_bytes(witness) {
        Ok(witness) => witness,
        _ => {
            return false;
        }
    };

    let mut scalars = Vec::with_capacity(record.len().next_power_of_two());

    for record_chunk in record.iter() {
        match Scalar::try_from(record_chunk) {
            Ok(scalar) => {
                scalars.push(scalar);
            }
            _ => {
                return false;
            }
        }
    }

    // Number of scalars for KZG must be a power of two elements
    scalars.resize(scalars.capacity(), Scalar::default());

    let polynomial = match kzg.poly(&scalars) {
        Ok(polynomial) => polynomial,
        _ => {
            return false;
        }
    };

    if kzg
        .commit(&polynomial)
        .map(|commitment| commitment.to_bytes())
        .as_ref()
        != Ok(commitment)
    {
        return false;
    }

    let Ok(segment_commitment) = Commitment::try_from(segment_commitment) else {
        return false;
    };

    let commitment_hash = Scalar::try_from(blake3_254_hash_to_scalar(commitment.as_ref()))
        .expect("Create correctly by dedicated hash function; qed");

    kzg.verify(
        &segment_commitment,
        ArchivedHistorySegment::NUM_PIECES,
        position,
        &commitment_hash,
        &witness,
    )
}

/// Validate witness for record commitment hash produced by archiver
#[cfg(feature = "kzg")]
pub fn is_record_commitment_hash_valid(
    kzg: &Kzg,
    record_commitment_hash: &Scalar,
    commitment: &SegmentCommitment,
    witness: &RecordWitness,
    position: u32,
) -> bool {
    let Ok(commitment) = Commitment::try_from(commitment) else {
        return false;
    };
    let Ok(witness) = Witness::try_from(witness) else {
        return false;
    };

    kzg.verify(
        &commitment,
        ArchivedHistorySegment::NUM_PIECES,
        position,
        record_commitment_hash,
        &witness,
    )
}

/// Derive proof of time entropy from chunk and proof of time for injection purposes.
#[inline]
pub fn derive_pot_entropy(chunk: &ScalarBytes, proof_of_time: PotOutput) -> Blake3Hash {
    blake3_hash_list(&[chunk.as_ref(), proof_of_time.as_ref()])
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
    u64::try_from(
        u128::from(current_solution_range)
            .saturating_mul(u128::from(era_slot_count))
            .saturating_mul(u128::from(slot_probability.0))
            / u128::from(era_duration)
            / u128::from(slot_probability.1),
    )
    .unwrap_or(u64::MAX)
    .clamp(
        current_solution_range / 4,
        current_solution_range.saturating_mul(4),
    )
}
