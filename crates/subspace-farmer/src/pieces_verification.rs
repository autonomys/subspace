use crate::RpcClient;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::{
    FlatPieces, PieceIndex, MERKLE_NUM_LEAVES, PIECE_SIZE, RECORD_SIZE,
};
use thiserror::Error;

/// Pieces verification errors.
#[derive(Error, Debug)]
pub enum PiecesVerificationError {
    /// Invalid pieces data provided
    #[error("Invalid pieces data provided")]
    InvalidRawData,
    /// Pieces verification failed.
    #[error("Pieces verification failed.")]
    InvalidPieces,
    /// RPC client failed.
    #[error("RPC client failed. jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    /// RPC client returned empty records_root.
    #[error("RPC client returned empty records_root.")]
    NoRecordsRootFound,
}

//TODO: Optimize: parallel execution, batch execution.
/// Verifies pieces against the blockchain.
pub async fn verify_pieces_at_blockchain<RC: RpcClient>(
    verification_client: &RC,
    piece_indexes: &[PieceIndex],
    pieces: &FlatPieces,
) -> Result<(), PiecesVerificationError> {
    if piece_indexes.len() != (pieces.len() / PIECE_SIZE) {
        return Err(PiecesVerificationError::InvalidRawData);
    }
    for (index, piece) in pieces.as_pieces().enumerate() {
        let piece_index = piece_indexes[index];

        let segment_index: u64 = piece_index / MERKLE_NUM_LEAVES as u64;
        let position: u64 = piece_index % MERKLE_NUM_LEAVES as u64;

        let root = verification_client
            .records_root(segment_index)
            .await
            .map_err(|err| PiecesVerificationError::RpcError(err))?
            .ok_or(PiecesVerificationError::NoRecordsRootFound)?;

        if !is_piece_valid(piece, root, position as usize, RECORD_SIZE as usize) {
            return Err(PiecesVerificationError::InvalidPieces);
        }
    }

    Ok(())
}
