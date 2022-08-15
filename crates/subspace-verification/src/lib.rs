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

use core::mem;
use schnorrkel::context::SigningContext;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{SignatureError, SignatureResult};
use sp_arithmetic::traits::SaturatedConversion;
use subspace_archiving::archiver;
use subspace_core_primitives::{
    crypto, BlockNumber, EonIndex, PieceIndex, PieceIndexHash, PublicKey, Randomness, RecordsRoot,
    RewardSignature, Salt, Sha256Hash, SlotNumber, Solution, SolutionRange, Tag, TagSignature,
    RANDOMNESS_CONTEXT, RANDOMNESS_LENGTH, SALT_HASHING_PREFIX, SALT_SIZE, U256,
};
use subspace_solving::{
    create_tag_signature_transcript, derive_global_challenge, derive_target, is_tag_valid,
    verify_local_challenge, verify_tag_signature, SubspaceCodec,
};

const SALT_HASHING_PREFIX_LEN: usize = SALT_HASHING_PREFIX.len();

/// Errors encountered by the Subspace consensus primitives.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
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

/// Check if the tag of a solution's piece is valid.
fn check_piece_tag<FarmerPublicKey, RewardAddress>(
    salt: Salt,
    solution: &Solution<FarmerPublicKey, RewardAddress>,
) -> Result<(), Error> {
    if !is_tag_valid(&solution.encoding, salt, solution.tag) {
        return Err(Error::InvalidTag);
    }

    Ok(())
}

/// Check piece validity.
///
/// If `records_root` is `None`, piece validity check will be skipped.
pub fn check_piece<'a, FarmerPublicKey, RewardAddress>(
    records_root: Sha256Hash,
    position: u64,
    record_size: u32,
    solution: &'a Solution<FarmerPublicKey, RewardAddress>,
) -> Result<(), Error>
where
    &'a FarmerPublicKey: Into<PublicKey>,
{
    let mut piece = solution.encoding.clone();

    // Ensure piece is decodable.
    let public_key = Into::<PublicKey>::into(&solution.public_key);
    let subspace_codec = SubspaceCodec::new(public_key.as_ref());
    subspace_codec
        .decode(&mut piece, solution.piece_index)
        .map_err(|_| Error::InvalidPieceEncoding)?;

    if !archiver::is_piece_valid(
        &piece,
        records_root,
        position as usize,
        record_size as usize,
    ) {
        return Err(Error::InvalidPiece);
    }

    Ok(())
}

/// Returns true if `solution.tag` is within the solution range.
pub fn is_within_solution_range(target: Tag, tag: Tag, solution_range: SolutionRange) -> bool {
    let target = SolutionRange::from_be_bytes(target);
    let tag = SolutionRange::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) <= solution_range / 2
}

/// Returns true if piece index is within farmer sector
fn is_within_max_plot(
    piece_index: PieceIndex,
    public_key: &PublicKey,
    total_pieces: u64,
    max_plot_size: u64,
) -> bool {
    if total_pieces < max_plot_size {
        return true;
    }
    let max_distance_one_direction = U256::MAX / total_pieces * max_plot_size / 2;
    subspace_core_primitives::bidirectional_distance(
        &U256::from(PieceIndexHash::from_index(piece_index)),
        &U256::from_be_bytes(
            AsRef::<[u8]>::as_ref(public_key)
                .try_into()
                .expect("Always correct length; qed"),
        ),
    ) <= max_distance_one_direction
}

/// Parameters for checking piece validity
#[derive(Debug)]
pub struct PieceCheckParams {
    /// Records root of segment to which piece belongs
    pub records_root: RecordsRoot,
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
#[derive(Debug)]
pub struct VerifySolutionParams<'a> {
    /// Global randomness
    pub global_randomness: &'a Randomness,
    /// Solution range
    pub solution_range: SolutionRange,
    /// Salt
    pub salt: Salt,
    /// Parameters for checking piece validity.
    ///
    /// If `None`, piece validity check will be skipped.
    pub piece_check_params: Option<PieceCheckParams>,
}

/// Solution verification
pub fn verify_solution<'a, FarmerPublicKey, RewardAddress>(
    solution: &'a Solution<FarmerPublicKey, RewardAddress>,
    slot: u64,
    params: VerifySolutionParams<'_>,
) -> Result<(), Error>
where
    &'a FarmerPublicKey: Into<PublicKey>,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        salt,
        piece_check_params,
    } = params;

    let public_key = Into::<PublicKey>::into(&solution.public_key);
    let sc_pub_key =
        schnorrkel::PublicKey::from_bytes(public_key.as_ref()).expect("Always correct length; qed");
    if let Err(error) = verify_local_challenge(
        &sc_pub_key,
        derive_global_challenge(global_randomness, slot),
        &solution.local_challenge,
    ) {
        return Err(Error::InvalidLocalChallenge(error));
    }

    // Verification of the local challenge was done above
    let target = match derive_target(
        &sc_pub_key,
        derive_global_challenge(global_randomness, slot),
        &solution.local_challenge,
    ) {
        Ok(target) => target,
        Err(error) => {
            return Err(Error::InvalidLocalChallenge(error));
        }
    };

    if !is_within_solution_range(solution.tag, target, solution_range) {
        return Err(Error::OutsideSolutionRange);
    }

    if let Err(error) = verify_tag_signature(solution.tag, &solution.tag_signature, &sc_pub_key) {
        return Err(Error::InvalidSolutionSignature(error));
    }

    check_piece_tag(salt, solution)?;

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
            return Err(Error::OutsideMaxPlot);
        }

        check_piece(records_root, position, record_size, solution)?;
    }

    Ok(())
}

/// Derive on-chain randomness from tag signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness(
    public_key: &PublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness> {
    let in_out = VRFOutput(tag_signature.output).attach_input_hash(
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?,
        create_tag_signature_transcript(tag),
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

/// Derives next salt value from the randomness provided.
pub fn derive_next_salt_from_randomness(eon_index: u64, randomness: &Randomness) -> Salt {
    let mut input = [0u8; SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH + mem::size_of::<u64>()];
    input[..SALT_HASHING_PREFIX_LEN].copy_from_slice(SALT_HASHING_PREFIX);
    input[SALT_HASHING_PREFIX_LEN..SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH]
        .copy_from_slice(randomness);
    input[SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH..].copy_from_slice(&eon_index.to_le_bytes());

    crypto::sha256_hash(&input)[..SALT_SIZE]
        .try_into()
        .expect("Slice has exactly the size needed; qed")
}

/// Derives next eon index if eon index should change based on the current slot.
pub fn derive_next_eon_index(
    parent_eon_index: EonIndex,
    eon_duration: u64,
    genesis_slot: SlotNumber,
    current_slot: SlotNumber,
) -> Option<EonIndex> {
    // calculate current eon start slot from (eon_index * eon_duration) + genesis_slot
    let current_eon_start_slot: EonIndex = parent_eon_index
        .checked_mul(eon_duration)
        .and_then(|res| res.checked_add(genesis_slot))
        .expect("eon start slot should fit into u64");

    let should_eon_change = current_slot.saturating_sub(current_eon_start_slot) >= eon_duration;
    if should_eon_change {
        current_slot
            .checked_sub(genesis_slot)
            .and_then(|slot_diff| slot_diff.checked_div(eon_duration))
    } else {
        None
    }
}
