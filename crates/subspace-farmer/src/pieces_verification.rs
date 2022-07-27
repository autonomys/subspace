use crate::RpcClient;
use num_traits::Zero;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::{FlatPieces, PieceIndex, PIECE_SIZE};
use subspace_rpc_primitives::FarmerProtocolInfo;
use thiserror::Error;

/// Pieces verification errors.
#[derive(Error, Debug)]
pub enum PiecesVerificationError {
    /// Invalid pieces data provided
    #[error("Invalid pieces data provided")]
    InvalidRawData,
    /// Invalid farmer protocol info provided
    #[error("Invalid farmer protocol info provided")]
    InvalidFarmerProtocolInfo,
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
    farmer_protocol_info: FarmerProtocolInfo,
    piece_indexes: &[PieceIndex],
    pieces: &FlatPieces,
) -> Result<(), PiecesVerificationError> {
    if piece_indexes.len() != pieces.count() {
        return Err(PiecesVerificationError::InvalidRawData);
    }

    let records_per_segment =
        farmer_protocol_info.recorded_history_segment_size as usize / PIECE_SIZE;
    if farmer_protocol_info.record_size.is_zero() || records_per_segment.is_zero() {
        return Err(PiecesVerificationError::InvalidFarmerProtocolInfo);
    }

    for (piece, piece_index) in pieces.as_pieces().zip(piece_indexes) {
        let segment_index: u64 = piece_index / records_per_segment as u64;
        let position: u64 = piece_index % records_per_segment as u64;

        let root = verification_client
            .records_root(segment_index)
            .await
            .map_err(|err| PiecesVerificationError::RpcError(err))?
            .ok_or(PiecesVerificationError::NoRecordsRootFound)?;

        if !is_piece_valid(
            piece,
            root,
            position as usize,
            farmer_protocol_info.record_size as usize,
        ) {
            return Err(PiecesVerificationError::InvalidPieces);
        }
    }

    Ok(())
}
