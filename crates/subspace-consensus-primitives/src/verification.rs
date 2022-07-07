// Copyright (C) 2021 Subspace Labs, Inc.
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

use crate::{
    create_local_challenge_transcript, create_tag, create_tag_signature_transcript,
    derive_global_challenge, derive_target, ConsensusError, PieceCheckParams, VerifySolutionParams,
    REWARD_SIGNING_CONTEXT,
};
use schnorrkel::vrf::{VRFInOut, VRFOutput, VRFProof};
use schnorrkel::{PublicKey, SignatureError, SignatureResult};
use subspace_archiving::archiver;
use subspace_codec::SubspaceCodec;
use subspace_core_primitives::{
    LocalChallenge, Piece, PieceIndex, PieceIndexHash, Salt, Sha256Hash, Solution, Tag,
    TagSignature, U256,
};

/// Check whether commitment tag of a piece is valid for a particular salt, which is used as a
/// Proof-of-Replication
pub fn is_tag_valid(piece: &Piece, salt: Salt, tag: Tag) -> bool {
    create_tag(piece, salt) == tag
}

/// Verify local challenge for farmer's public key that was derived from the global challenge.
pub fn verify_local_challenge(
    public_key: &PublicKey,
    global_challenge: Sha256Hash,
    local_challenge: &LocalChallenge,
) -> SignatureResult<VRFInOut> {
    public_key
        .vrf_verify(
            create_local_challenge_transcript(&global_challenge),
            &VRFOutput(local_challenge.output),
            &VRFProof::from_bytes(&local_challenge.proof)?,
        )
        .map(|(in_out, _)| in_out)
}

/// Verify that tag signature was created correctly.
pub fn verify_tag_signature(
    tag: Tag,
    tag_signature: &TagSignature,
    public_key: &PublicKey,
) -> SignatureResult<VRFInOut> {
    public_key
        .vrf_verify(
            create_tag_signature_transcript(tag),
            &VRFOutput(tag_signature.output),
            &VRFProof::from_bytes(&tag_signature.proof)?,
        )
        .map(|(in_out, _)| in_out)
}

/// Checks the signature validity.
pub fn verify_reward_signature<PublicKey, Signature, Message>(
    message: &Message,
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), SignatureError>
where
    PublicKey: AsRef<[u8]>,
    Signature: AsRef<[u8]>,
    Message: AsRef<[u8]>,
{
    let public_key = &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?;
    let signature = &schnorrkel::Signature::from_bytes(signature.as_ref())?;
    let signing_transcript =
        schnorrkel::signing_context(REWARD_SIGNING_CONTEXT).bytes(message.as_ref());
    public_key.verify(signing_transcript, signature)
}

/// Checks if the target range is within the solution range
pub fn is_within_solution_range(target: Tag, tag: Tag, solution_range: u64) -> bool {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) <= solution_range / 2
}

/// Checks if piece index is within farmer sector
fn is_within_max_plot<PublicKey: AsRef<[u8]>>(
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
fn verify_piece_tag(salt: Salt, piece: &Piece, tag: Tag) -> Result<(), ConsensusError> {
    if !is_tag_valid(piece, salt, tag) {
        return Err(ConsensusError::InvalidTag);
    }

    Ok(())
}

/// Verifies encoded piece belongs to archival history
pub fn verify_piece<PublicKey: AsRef<[u8]>>(
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

/// Solution verification
///
/// If `PieceCheckParams` is `None`, piece validity check will be skipped.
pub fn verify_solution<PublicKey, RewardAddress, Slot>(
    solution: &Solution<PublicKey, RewardAddress>,
    slot: Slot,
    params: VerifySolutionParams<'_>,
) -> Result<(), ConsensusError>
where
    PublicKey: AsRef<[u8]>,
    Slot: Into<u64>,
{
    let VerifySolutionParams {
        global_randomness,
        solution_range,
        salt,
        piece_check_params,
    } = params;

    let public_key = schnorrkel::PublicKey::from_bytes(solution.public_key.as_ref())
        .expect("Always correct length; qed");

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

    verify_piece_tag(salt, &solution.encoding, solution.tag)?;

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
