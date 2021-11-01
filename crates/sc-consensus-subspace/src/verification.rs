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
use super::{find_pre_digest, subspace_err, BlockT, Epoch, Error};
use log::{debug, trace};
use sc_consensus_slots::CheckedHeader;
use schnorrkel::context::SigningContext;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest, Solution};
use sp_core::Public;
use sp_runtime::{traits::DigestItemFor, traits::Header, RuntimeAppPublic};
use subspace_archiving::archiver;
use subspace_core_primitives::{crypto, Piece, Randomness, Salt, Sha256Hash};
use subspace_solving::{derive_global_challenge, derive_local_challenge, SubspaceCodec};

/// Subspace verification parameters
pub(super) struct VerificationParams<'a, B: 'a + BlockT> {
    /// The header being verified.
    pub(super) header: B::Header,
    /// The pre-digest of the header being verified. this is optional - if prior
    /// verification code had to read it, it can be included here to avoid duplicate
    /// work.
    pub(super) pre_digest: Option<PreDigest>,
    /// The slot number of the current time.
    pub(super) slot_now: Slot,
    /// Epoch descriptor of the epoch this block _should_ be under, if it's valid.
    pub(super) epoch: &'a Epoch,
    /// Solution range corresponding to this block.
    pub(super) solution_range: u64,
    /// Salt corresponding to this block.
    pub(super) salt: Salt,
    /// Merkle Root hash for pieces in the segment to which solution in `pre_digest` belongs to
    pub(super) merkle_root: &'a Sha256Hash,
    /// Position within segment of a piece from solution in `pre_digest`
    pub(super) position: u64,
    /// Record size for a segment to which solution in `pre_digest` belongs to
    pub(super) record_size: u32,
    /// Signing context for verifying signatures
    pub(super) signing_context: &'a SigningContext,
}

/// Check a header has been signed by the right key. If the slot is too far in
/// the future, an error will be returned. If successful, returns the pre-header
/// and the digest item containing the seal.
///
/// The seal must be the last digest.  Otherwise, the whole header is considered
/// unsigned.  This is required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
pub(super) fn check_header<B: BlockT + Sized>(
    params: VerificationParams<B>,
) -> Result<CheckedHeader<B::Header, VerifiedHeaderInfo<B>>, Error<B>>
where
    DigestItemFor<B>: CompatibleDigestItem,
{
    let VerificationParams {
        mut header,
        pre_digest,
        slot_now,
        epoch,
        solution_range,
        salt,
        merkle_root,
        position,
        record_size,
        signing_context,
    } = params;

    let pre_digest = pre_digest
        .map(Ok)
        .unwrap_or_else(|| find_pre_digest::<B>(&header))?;

    trace!(target: "subspace", "Checking header");
    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| subspace_err(Error::HeaderUnsealed(header.hash())))?;

    let sig = seal
        .as_subspace_seal()
        .ok_or_else(|| subspace_err(Error::HeaderBadSeal(header.hash())))?;

    // the pre-hash of the header doesn't include the seal
    // and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    debug!(target: "subspace",
        "Verifying primary block #{} at slot: {}",
        header.number(),
        pre_digest.slot,
    );

    // Verify that block is signed properly
    if !pre_digest.solution.public_key.verify(&pre_hash, &sig) {
        return Err(subspace_err(Error::BadSignature(pre_hash)));
    }

    // Verify that solution is valid
    verify_solution(
        &pre_digest.solution,
        VerifySolutionParams {
            epoch_randomness: &epoch.randomness,
            solution_range,
            slot: pre_digest.slot,
            salt,
            merkle_root,
            position,
            record_size,
            signing_context,
        },
    )?;

    let info = VerifiedHeaderInfo {
        pre_digest: CompatibleDigestItem::subspace_pre_digest(pre_digest),
        seal,
    };
    Ok(CheckedHeader::Checked(header, info))
}

pub(super) struct VerifiedHeaderInfo<B: BlockT> {
    pub(super) pre_digest: DigestItemFor<B>,
    pub(super) seal: DigestItemFor<B>,
}

/// Check the solution signature validity.
fn check_signature(
    signing_context: &SigningContext,
    solution: &Solution,
) -> Result<(), schnorrkel::SignatureError> {
    let public_key = schnorrkel::PublicKey::from_bytes(solution.public_key.as_slice())?;
    let signature = schnorrkel::Signature::from_bytes(&solution.signature)?;
    public_key.verify(signing_context.bytes(&solution.tag), &signature)
}

/// Check if the tag of a solution's piece is valid.
fn check_piece_tag<B: BlockT>(slot: Slot, salt: Salt, solution: &Solution) -> Result<(), Error<B>> {
    let piece: Piece = solution
        .encoding
        .as_slice()
        .try_into()
        .map_err(|_error| Error::EncodingOfWrongSize)?;

    if !subspace_solving::is_tag_valid(salt, &piece, solution.tag) {
        return Err(Error::InvalidTag(slot));
    }

    Ok(())
}

/// Check piece validity.
fn check_piece<B: BlockT>(
    slot: Slot,
    salt: Salt,
    merkle_root: &Sha256Hash,
    position: u64,
    record_size: u32,
    solution: &Solution,
) -> Result<(), Error<B>> {
    check_piece_tag(slot, salt, solution)?;

    let mut piece = solution.encoding.clone();

    // Ensure piece is decodable.
    let subspace_codec = SubspaceCodec::new(&solution.public_key);
    subspace_codec
        .decode(solution.piece_index, &mut piece)
        .map_err(|_| Error::InvalidEncoding(slot))?;

    if !archiver::is_piece_valid(
        &piece,
        *merkle_root,
        position as usize,
        record_size as usize,
    ) {
        return Err(Error::InvalidEncoding(slot));
    }

    Ok(())
}

/// Check solution range validity.
fn check_solution_range<B: BlockT>(
    epoch_randomness: &Randomness,
    slot: Slot,
    solution_range: u64,
    solution: &Solution,
) -> Result<(), Error<B>> {
    if !is_within_solution_range(
        solution,
        derive_global_challenge(epoch_randomness, slot),
        solution_range,
    ) {
        return Err(Error::OutsideOfSolutionRange(slot));
    }

    Ok(())
}

pub(crate) struct VerifySolutionParams<'a> {
    pub(crate) epoch_randomness: &'a Randomness,
    pub(crate) solution_range: u64,
    pub(crate) slot: Slot,
    pub(crate) salt: Salt,
    pub(crate) merkle_root: &'a Sha256Hash,
    pub(crate) position: u64,
    pub(crate) record_size: u32,
    pub(crate) signing_context: &'a SigningContext,
}

pub(crate) fn verify_solution<B: BlockT>(
    solution: &Solution,
    params: VerifySolutionParams,
) -> Result<(), Error<B>> {
    let VerifySolutionParams {
        epoch_randomness,
        solution_range,
        slot,
        salt,
        merkle_root,
        position,
        record_size,
        signing_context,
    } = params;

    check_solution_range(epoch_randomness, slot, solution_range, solution)?;

    check_signature(signing_context, solution).map_err(|e| Error::BadSolutionSignature(slot, e))?;

    check_piece(slot, salt, merkle_root, position, record_size, solution)?;

    Ok(())
}

fn is_within_solution_range(
    solution: &Solution,
    global_challenge: [u8; 8],
    solution_range: u64,
) -> bool {
    let farmer_public_key_hash = crypto::sha256_hash(&solution.public_key);
    let local_challenge = derive_local_challenge(global_challenge, farmer_public_key_hash);

    let target = u64::from_be_bytes(local_challenge);
    let (lower, is_lower_overflowed) = target.overflowing_sub(solution_range / 2);
    let (upper, is_upper_overflowed) = target.overflowing_add(solution_range / 2);

    let solution_tag = u64::from_be_bytes(solution.tag);

    if is_lower_overflowed || is_upper_overflowed {
        upper <= solution_tag || solution_tag <= lower
    } else {
        lower <= solution_tag && solution_tag <= upper
    }
}
