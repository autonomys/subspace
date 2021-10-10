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

//! Verification for PoC headers.
use super::{find_pre_digest, poc_err, BlockT, Epoch, Error};
use log::{debug, trace};
use ring::digest;
use sc_consensus_slots::CheckedHeader;
use schnorrkel::context::SigningContext;
use sp_consensus_poc::digests::{CompatibleDigestItem, PreDigest, Solution};
use sp_consensus_slots::Slot;
use sp_core::Public;
use sp_runtime::{traits::DigestItemFor, traits::Header, RuntimeAppPublic};
use subspace_archiving::archiver;
use subspace_core_primitives::{crypto, Randomness};
use subspace_core_primitives::{Piece, Salt, Sha256Hash};
use subspace_solving::SubspaceCodec;

/// PoC verification parameters
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
/// This digest item will always return `Some` when used with `as_poc_pre_digest`.
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

    trace!(target: "poc", "Checking header");
    let seal = header
        .digest_mut()
        .pop()
        .ok_or_else(|| poc_err(Error::HeaderUnsealed(header.hash())))?;

    let sig = seal
        .as_poc_seal()
        .ok_or_else(|| poc_err(Error::HeaderBadSeal(header.hash())))?;

    // the pre-hash of the header doesn't include the seal
    // and that's what we sign
    let pre_hash = header.hash();

    if pre_digest.slot > slot_now {
        header.digest_mut().push(seal);
        return Ok(CheckedHeader::Deferred(header, pre_digest.slot));
    }

    debug!(target: "poc",
        "Verifying primary block #{} at slot: {}",
        header.number(),
        pre_digest.slot,
    );

    // Verify that block is signed properly
    if !pre_digest.solution.public_key.verify(&pre_hash, &sig) {
        return Err(poc_err(Error::BadSignature(pre_hash)));
    }

    // Verify that solution is valid
    verify_solution(
        &pre_digest.solution,
        &epoch.randomness,
        solution_range,
        pre_digest.slot,
        salt,
        merkle_root,
        position,
        record_size,
        signing_context,
    )?;

    let info = VerifiedHeaderInfo {
        pre_digest: CompatibleDigestItem::poc_pre_digest(pre_digest),
        seal,
    };
    Ok(CheckedHeader::Checked(header, info))
}

pub(super) struct VerifiedHeaderInfo<B: BlockT> {
    pub(super) pre_digest: DigestItemFor<B>,
    pub(super) seal: DigestItemFor<B>,
}

/// TODO: Probably a struct for arguments
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_solution<B: BlockT + Sized>(
    solution: &Solution,
    epoch_randomness: &Randomness,
    solution_range: u64,
    slot: Slot,
    salt: Salt,
    merkle_root: &Sha256Hash,
    position: u64,
    record_size: u32,
    signing_context: &SigningContext,
) -> Result<(), Error<B>> {
    if !is_within_solution_range(
        solution,
        crate::create_global_challenge(epoch_randomness, slot),
        solution_range,
    ) {
        return Err(Error::OutsideOfSolutionRange(slot));
    }

    let piece: Piece = solution
        .encoding
        .as_slice()
        .try_into()
        .map_err(|_error| Error::EncodingOfWrongSize)?;

    if !subspace_solving::is_commitment_valid(&piece, solution.tag, salt) {
        return Err(Error::InvalidCommitment(slot));
    }

    if !is_signature_valid(signing_context, solution) {
        return Err(Error::BadSolutionSignature(slot));
    }

    let subspace_solving = SubspaceCodec::new(&solution.public_key);

    let mut piece = solution.encoding.clone();
    if subspace_solving
        .decode(solution.piece_index, &mut piece)
        .is_err()
    {
        return Err(Error::InvalidEncoding(slot));
    }

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

// TODO: Move at least below functions into `subspace-solving`
fn is_within_solution_range(
    solution: &Solution,
    global_challenge: [u8; 8],
    solution_range: u64,
) -> bool {
    let farmer_public_key_hash = crypto::sha256_hash(&solution.public_key);
    let local_challenge = derive_local_challenge(&global_challenge, &farmer_public_key_hash);

    let target = u64::from_be_bytes(local_challenge);
    let tag = u64::from_be_bytes(solution.tag);

    let (lower, is_lower_overflowed) = target.overflowing_sub(solution_range / 2);
    let (upper, is_upper_overflowed) = target.overflowing_add(solution_range / 2);
    if is_lower_overflowed || is_upper_overflowed {
        upper <= tag || tag <= lower
    } else {
        lower <= tag && tag <= upper
    }
}

fn is_signature_valid(signing_context: &SigningContext, solution: &Solution) -> bool {
    let public_key = match schnorrkel::PublicKey::from_bytes(solution.public_key.as_slice()) {
        Ok(public_key) => public_key,
        Err(_) => {
            return false;
        }
    };
    let signature = match schnorrkel::Signature::from_bytes(&solution.signature) {
        Ok(signature) => signature,
        Err(_) => {
            return false;
        }
    };
    public_key
        .verify(signing_context.bytes(&solution.tag), &signature)
        .is_ok()
}

pub(crate) fn derive_local_challenge(
    global_challenge: &[u8],
    farmer_public_key_hash: &[u8],
) -> [u8; 8] {
    digest::digest(&digest::SHA256, &{
        let mut data = Vec::with_capacity(global_challenge.len() + farmer_public_key_hash.len());
        data.extend_from_slice(global_challenge);
        data.extend_from_slice(farmer_public_key_hash);
        data
    })
    .as_ref()[..8]
        .try_into()
        .unwrap()
}
