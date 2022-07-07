use crate::{ConsensusError, PieceCheckParams, VerifySolutionParams};
use schnorrkel::context::SigningTranscript;
use schnorrkel::SignatureError;
use subspace_archiving::archiver;
use subspace_core_primitives::{
    Piece, PieceIndex, PieceIndexHash, Salt, Sha256Hash, Solution, Tag, U256,
};
use subspace_solving::{
    derive_global_challenge, derive_target, is_tag_valid, verify_local_challenge,
    verify_tag_signature, SubspaceCodec,
};

/// Checks the signature validity.
pub fn verify_signature<PublicKey, Signature, ST>(
    signature: &Signature,
    public_key: &PublicKey,
    signing_transcript: ST,
) -> Result<(), SignatureError>
where
    PublicKey: AsRef<[u8]>,
    Signature: AsRef<[u8]>,
    ST: SigningTranscript,
{
    let public_key = &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?;
    let signature = &schnorrkel::Signature::from_bytes(signature.as_ref())?;
    public_key.verify::<ST>(signing_transcript, signature)
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
