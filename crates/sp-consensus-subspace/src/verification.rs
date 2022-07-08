// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
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

//! Verification for Subspace headers.
use crate::digests::{CompatibleDigestItem, PreDigest};
use crate::{find_pre_digest, FarmerPublicKey, FarmerSignature, RANDOMNESS_CONTEXT};
use codec::Decode;
use core::mem;
use schnorrkel::context::SigningContext;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{PublicKey, Signature, SignatureResult};
use sp_api::HeaderT;
use sp_arithmetic::traits::SaturatedConversion;
use sp_consensus_slots::Slot;
use sp_runtime::DigestItem;
use subspace_archiving::archiver;
use subspace_core_primitives::{
    crypto, PieceIndex, PieceIndexHash, Randomness, Salt, Sha256Hash, Solution, Tag, TagSignature,
    RANDOMNESS_LENGTH, SALT_HASHING_PREFIX, SALT_SIZE, U256,
};
use subspace_solving::{
    create_tag_signature_transcript, derive_global_challenge, derive_target, is_tag_valid,
    verify_local_challenge, verify_tag_signature, SubspaceCodec,
};

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError<Header: HeaderT> {
    /// No Subspace pre-runtime digest found
    #[cfg_attr(feature = "thiserror", error("No Subspace pre-runtime digest found"))]
    NoPreRuntimeDigest,
    /// Header has a bad seal
    #[cfg_attr(feature = "thiserror", error("Header {0:?} has a bad seal"))]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[cfg_attr(feature = "thiserror", error("Header {0:?} is unsealed"))]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[cfg_attr(feature = "thiserror", error("Bad reward signature on {0:?}"))]
    BadRewardSignature(Header::Hash),
    /// Bad solution signature
    #[cfg_attr(
        feature = "thiserror",
        error("Bad solution signature on slot {0:?}: {1:?}")
    )]
    BadSolutionSignature(Slot, schnorrkel::SignatureError),
    /// Bad local challenge
    #[cfg_attr(
        feature = "thiserror",
        error("Local challenge is invalid for slot {0}: {1}")
    )]
    BadLocalChallenge(Slot, schnorrkel::SignatureError),
    /// Solution is outside of solution range
    #[cfg_attr(
        feature = "thiserror",
        error("Solution is outside of solution range for slot {0}")
    )]
    OutsideOfSolutionRange(Slot),
    /// Solution is outside of max plot size
    #[cfg_attr(
        feature = "thiserror",
        error("Solution is outside of max plot size {0}")
    )]
    OutsideOfMaxPlot(Slot),
    /// Invalid encoding of a piece
    #[cfg_attr(feature = "thiserror", error("Invalid encoding for slot {0}"))]
    InvalidEncoding(Slot),
    /// Invalid tag for salt
    #[cfg_attr(feature = "thiserror", error("Invalid tag for salt for slot {0}"))]
    InvalidTag(Slot),
}

/// A header which has been checked
pub enum CheckedHeader<H, S> {
    /// A header which has slot in the future. this is the full header (not stripped)
    /// and the slot in which it should be processed.
    Deferred(H, Slot),
    /// A header which is fully checked, including signature. This is the pre-header
    /// accompanied by the seal components.
    ///
    /// Includes the digest item that encoded the seal.
    Checked(H, S),
}

/// Subspace verification parameters
pub struct VerificationParams<'a, Header>
where
    Header: HeaderT + 'a,
{
    /// The header being verified.
    pub header: Header,
    /// The slot number of the current time.
    pub slot_now: Slot,
    /// Parameters for solution verification
    pub verify_solution_params: VerifySolutionParams<'a>,
    /// Signing context for reward signature
    pub reward_signing_context: &'a SigningContext,
}

/// Information from verified header
pub struct VerifiedHeaderInfo<RewardAddress> {
    /// Pre-digest
    pub pre_digest: PreDigest<FarmerPublicKey, RewardAddress>,
    /// Seal (signature)
    pub seal: DigestItem,
}

/// Check a header has been signed correctly and whether solution is correct. If the slot is too far
/// in the future, an error will be returned. If successful, returns the pre-header and the digest
/// item containing the seal.
///
/// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This is
/// required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
///
/// `pre_digest` argument is optional in case it is available to avoid doing the work of extracting
/// it from the header twice.
pub fn check_header<Header, RewardAddress>(
    params: VerificationParams<Header>,
    pre_digest: Option<PreDigest<FarmerPublicKey, RewardAddress>>,
) -> Result<CheckedHeader<Header, VerifiedHeaderInfo<RewardAddress>>, VerificationError<Header>>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    let VerificationParams {
        mut header,
        slot_now,
        verify_solution_params,
        reward_signing_context,
    } = params;

    let pre_digest = match pre_digest {
        Some(pre_digest) => pre_digest,
        None => find_pre_digest::<Header, RewardAddress>(&header)
            .ok_or(VerificationError::NoPreRuntimeDigest)?,
    };
    let slot = pre_digest.slot;

    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| VerificationError::HeaderUnsealed(header.hash()))?;

    let signature = seal
        .as_subspace_seal()
        .ok_or_else(|| VerificationError::HeaderBadSeal(header.hash()))?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    // Verify that block is signed properly
    if check_reward_signature(
        pre_hash.as_ref(),
        &signature,
        &pre_digest.solution.public_key,
        reward_signing_context,
    )
    .is_err()
    {
        return Err(VerificationError::BadRewardSignature(pre_hash));
    }

    // Verify that solution is valid
    verify_solution(&pre_digest.solution, slot, verify_solution_params)?;

    Ok(CheckedHeader::Checked(
        header,
        VerifiedHeaderInfo { pre_digest, seal },
    ))
}

/// Check the reward signature validity.
pub fn check_reward_signature(
    hash: &[u8],
    signature: &FarmerSignature,
    public_key: &FarmerPublicKey,
    reward_signing_context: &SigningContext,
) -> Result<(), schnorrkel::SignatureError> {
    let public_key = PublicKey::from_bytes(public_key.as_ref())?;
    let signature = Signature::from_bytes(signature)?;
    public_key.verify(reward_signing_context.bytes(hash), &signature)
}

/// Check if the tag of a solution's piece is valid.
fn check_piece_tag<Header, RewardAddress>(
    slot: Slot,
    salt: Salt,
    solution: &Solution<FarmerPublicKey, RewardAddress>,
) -> Result<(), VerificationError<Header>>
where
    Header: HeaderT,
{
    if !is_tag_valid(&solution.encoding, salt, solution.tag) {
        return Err(VerificationError::InvalidTag(slot));
    }

    Ok(())
}

/// Check piece validity.
///
/// If `records_root` is `None`, piece validity check will be skipped.
pub fn check_piece<Header, RewardAddress>(
    slot: Slot,
    records_root: Sha256Hash,
    position: u64,
    record_size: u32,
    solution: &Solution<FarmerPublicKey, RewardAddress>,
) -> Result<(), VerificationError<Header>>
where
    Header: HeaderT,
{
    let mut piece = solution.encoding.clone();

    // Ensure piece is decodable.
    let subspace_codec = SubspaceCodec::new(solution.public_key.as_ref());
    subspace_codec
        .decode(&mut piece, solution.piece_index)
        .map_err(|_| VerificationError::InvalidEncoding(slot))?;

    if !archiver::is_piece_valid(
        &piece,
        records_root,
        position as usize,
        record_size as usize,
    ) {
        return Err(VerificationError::InvalidEncoding(slot));
    }

    Ok(())
}

/// Returns true if `solution.tag` is within the solution range.
pub fn is_within_solution_range(target: Tag, tag: Tag, solution_range: u64) -> bool {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) <= solution_range / 2
}

/// Returns true if piece index is within farmer sector
fn is_within_max_plot(
    piece_index: PieceIndex,
    public_key: &FarmerPublicKey,
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
            AsRef::<[u8]>::as_ref(&public_key)
                .try_into()
                .expect("Always correct length; qed"),
        ),
    ) <= max_distance_one_direction
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
pub fn verify_solution<Header, RewardAddress>(
    solution: &Solution<FarmerPublicKey, RewardAddress>,
    slot: Slot,
    params: VerifySolutionParams,
) -> Result<(), VerificationError<Header>>
where
    Header: HeaderT,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        salt,
        piece_check_params,
    } = params;

    let public_key =
        PublicKey::from_bytes(solution.public_key.as_ref()).expect("Always correct length; qed");

    if let Err(error) = verify_local_challenge(
        &public_key,
        derive_global_challenge(global_randomness, slot.into()),
        &solution.local_challenge,
    ) {
        return Err(VerificationError::BadLocalChallenge(slot, error));
    }

    // Verification of the local challenge was done above
    let target = match derive_target(
        &public_key,
        derive_global_challenge(global_randomness, slot.into()),
        &solution.local_challenge,
    ) {
        Ok(target) => target,
        Err(error) => {
            return Err(VerificationError::BadLocalChallenge(slot, error));
        }
    };

    if !is_within_solution_range(solution.tag, target, solution_range) {
        return Err(VerificationError::OutsideOfSolutionRange(slot));
    }

    if let Err(error) = verify_tag_signature(solution.tag, &solution.tag_signature, &public_key) {
        return Err(VerificationError::BadSolutionSignature(slot, error));
    }

    check_piece_tag(slot, salt, solution)?;

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
            &solution.public_key,
            total_pieces,
            max_plot_size,
        ) {
            return Err(VerificationError::OutsideOfMaxPlot(slot));
        }

        check_piece(slot, records_root, position, record_size, solution)?;
    }

    Ok(())
}

/// Derive on-chain randomness from tag signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness(
    public_key: &FarmerPublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness> {
    let in_out = VRFOutput(tag_signature.output).attach_input_hash(
        &PublicKey::from_bytes(public_key.as_ref())?,
        create_tag_signature_transcript(tag),
    )?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Derives next solution range based on the total era slots and slot probability
pub fn derive_next_solution_range(
    start_slot: u64,
    current_slot: u64,
    slot_probability: (u64, u64),
    current_solution_range: u64,
    era_duration: u64,
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

const SALT_HASHING_PREFIX_LEN: usize = SALT_HASHING_PREFIX.len();

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
