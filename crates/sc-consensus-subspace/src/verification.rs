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
use super::{subspace_err, BlockT, Error};
use log::{debug, trace};
use sc_consensus_slots::CheckedHeader;
use schnorrkel::context::SigningContext;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::crypto::ByteArray;
use sp_runtime::traits::Header;
use sp_runtime::{DigestItem, RuntimeAppPublic};
use subspace_archiving::archiver;
use subspace_core_primitives::{PieceIndex, Randomness, Salt, Sha256Hash, Solution};
use subspace_solving::{
    derive_global_challenge, is_local_challenge_valid, PieceDistance, SubspaceCodec,
};

/// Subspace verification parameters
pub(super) struct VerificationParams<'a, B: 'a + BlockT> {
    /// The header being verified.
    pub(super) header: B::Header,
    /// The pre-digest of the header being verified to avoid duplicated work.
    pub(super) pre_digest: PreDigest<FarmerPublicKey>,
    /// The slot number of the current time.
    pub(super) slot_now: Slot,
    /// Parameters for solution verification
    pub(super) verify_solution_params: VerifySolutionParams<'a>,
}

/// Check a header has been signed by the right key. If the slot is too far in
/// the future, an error will be returned. If successful, returns the pre-header
/// and the digest item containing the seal.
///
/// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This is
/// required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
pub(super) fn check_header<B: BlockT + Sized>(
    params: VerificationParams<B>,
) -> Result<CheckedHeader<B::Header, VerifiedHeaderInfo>, Error<B>> {
    let VerificationParams {
        mut header,
        pre_digest,
        slot_now,
        verify_solution_params,
    } = params;

    trace!(target: "subspace", "Checking header");
    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| subspace_err(Error::HeaderUnsealed(header.hash())))?;

    let sig = seal
        .as_subspace_seal()
        .ok_or_else(|| subspace_err(Error::HeaderBadSeal(header.hash())))?;

    // The pre-hash of the header doesn't include the seal and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    debug!(
        target: "subspace",
        "Verifying primary block #{} at slot: {}",
        header.number(),
        pre_digest.slot,
    );

    // Verify that block is signed properly
    if !pre_digest.solution.public_key.verify(&pre_hash, &sig) {
        return Err(subspace_err(Error::BadSignature(pre_hash)));
    }

    // Verify that solution is valid
    verify_solution(&pre_digest.solution, verify_solution_params)?;

    Ok(CheckedHeader::Checked(
        header,
        VerifiedHeaderInfo { pre_digest, seal },
    ))
}

pub(super) struct VerifiedHeaderInfo {
    pub(super) pre_digest: PreDigest<FarmerPublicKey>,
    pub(super) seal: DigestItem,
}

/// Check the solution signature validity.
fn check_signature(
    signing_context: &SigningContext,
    solution: &Solution<FarmerPublicKey>,
) -> Result<(), schnorrkel::SignatureError> {
    let public_key = schnorrkel::PublicKey::from_bytes(solution.public_key.as_slice())?;
    let signature = schnorrkel::Signature::from_bytes(&solution.signature)?;
    public_key.verify(signing_context.bytes(&solution.tag), &signature)
}

/// Check if the tag of a solution's piece is valid.
fn check_piece_tag<B: BlockT>(
    slot: Slot,
    salt: Salt,
    solution: &Solution<FarmerPublicKey>,
) -> Result<(), Error<B>> {
    if !subspace_solving::is_tag_valid(&solution.encoding, salt, solution.tag) {
        return Err(Error::InvalidTag(slot));
    }

    Ok(())
}

/// Check piece validity.
///
/// If `records_root` is `None`, piece validity check will be skipped.
pub(crate) fn check_piece<B: BlockT>(
    slot: Slot,
    records_root: Sha256Hash,
    position: u64,
    record_size: u32,
    solution: &Solution<FarmerPublicKey>,
) -> Result<(), Error<B>> {
    let mut piece = solution.encoding;

    // Ensure piece is decodable.
    let subspace_codec = SubspaceCodec::new(&solution.public_key);
    subspace_codec
        .decode(&mut piece, solution.piece_index)
        .map_err(|_| Error::InvalidEncoding(slot))?;

    if !archiver::is_piece_valid(
        &piece,
        records_root,
        position as usize,
        record_size as usize,
    ) {
        return Err(Error::InvalidEncoding(slot));
    }

    Ok(())
}

/// Returns true if `solution.tag` is within the solution range.
fn is_within_solution_range(solution: &Solution<FarmerPublicKey>, solution_range: u64) -> bool {
    let target = u64::from_be_bytes(solution.local_challenge.derive_target());
    let (lower, is_lower_overflowed) = target.overflowing_sub(solution_range / 2);
    let (upper, is_upper_overflowed) = target.overflowing_add(solution_range / 2);

    let solution_tag = u64::from_be_bytes(solution.tag);

    if is_lower_overflowed || is_upper_overflowed {
        upper <= solution_tag || solution_tag <= lower
    } else {
        lower <= solution_tag && solution_tag <= upper
    }
}

/// Returns true if piece index is within farmer sector
fn is_within_max_plot(
    piece_index: PieceIndex,
    key: &FarmerPublicKey,
    total_pieces: u64,
    max_plot_size: u64,
) -> bool {
    if total_pieces < max_plot_size {
        return true;
    }
    let max_distance = PieceDistance::MAX / total_pieces * max_plot_size;
    PieceDistance::xor_distance(&piece_index.into(), key) <= max_distance
}

pub(crate) struct PieceCheckParams {
    pub(crate) records_root: Sha256Hash,
    pub(crate) position: u64,
    pub(crate) record_size: u32,
    pub(super) max_plot_size: u64,
    pub(super) total_pieces: u64,
}

/// If `piece_check_params` is `None`, piece validity check will be skipped.
pub(crate) struct VerifySolutionParams<'a> {
    pub(crate) global_randomness: &'a Randomness,
    pub(crate) solution_range: u64,
    pub(crate) slot: Slot,
    pub(crate) salt: Salt,
    pub(crate) piece_check_params: Option<PieceCheckParams>,
    pub(crate) signing_context: &'a SigningContext,
}

pub(crate) fn verify_solution<B: BlockT>(
    solution: &Solution<FarmerPublicKey>,
    params: VerifySolutionParams,
) -> Result<(), Error<B>> {
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        slot,
        salt,
        piece_check_params,
        signing_context,
    } = params;

    if let Err(error) = is_local_challenge_valid(
        derive_global_challenge(global_randomness, slot),
        &solution.local_challenge,
        &solution.public_key,
    ) {
        return Err(Error::BadLocalChallenge(slot, error));
    }

    if !is_within_solution_range(solution, solution_range) {
        return Err(Error::OutsideOfSolutionRange(slot));
    }

    check_signature(signing_context, solution).map_err(|e| Error::BadSolutionSignature(slot, e))?;

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
            return Err(Error::OutsideOfMaxPlot(slot));
        }

        check_piece(slot, records_root, position, record_size, solution)?;
    }

    Ok(())
}
