use crate::single_disk_plot::piece_receiver::PieceReceiver;
use crate::single_disk_plot::{PlottingError, SectorMetadata};
use bitvec::order::Lsb0;
use bitvec::prelude::*;
use parity_scale_codec::Encode;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use subspace_core_primitives::{
    plot_sector_size, PieceIndex, PublicKey, SectorId, SectorIndex, PIECE_SIZE,
};
use subspace_rpc_primitives::FarmerProtocolInfo;
use subspace_solving::derive_chunk_otp;
use thiserror::Error;
use tracing::debug;

/// Information about sector that was plotted
#[derive(Debug, Clone)]
pub struct PlottedSector {
    /// Sector ID
    pub sector_id: SectorId,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Sector metadata
    pub sector_metadata: SectorMetadata,
    /// Indexes of pieces that were plotted
    pub piece_indexes: Vec<PieceIndex>,
}

/// Plotting status
#[derive(Debug, Error)]
pub enum PlotSectorError {
    /// Plotting was cancelled
    #[error("Plotting was cancelled")]
    Cancelled,
    /// Plotting failed
    #[error("Plotting failed: {0}")]
    Plotting(#[from] PlottingError),
}

/// Plot a single sector, where `sector` and `sector_metadata` must be positioned correctly (seek to
/// desired offset before calling this function if necessary)
///
/// NOTE: Even though this function is async, it has blocking code inside and must be running in a
/// separate thread in order to prevent blocking an executor.
pub async fn plot_sector<PR, S, SM>(
    public_key: &PublicKey,
    sector_index: u64,
    piece_receiver: &PR,
    cancelled: &AtomicBool,
    farmer_protocol_info: &FarmerProtocolInfo,
    mut sector_output: S,
    mut sector_metadata_output: SM,
) -> Result<PlottedSector, PlotSectorError>
where
    PR: PieceReceiver,
    S: io::Write,
    SM: io::Write,
{
    let sector_id = SectorId::new(public_key, sector_index);
    let plot_sector_size = plot_sector_size(farmer_protocol_info.space_l);
    // TODO: Consider adding number of pieces in a sector to protocol info
    //  explicitly and, ideally, we need to remove 2x replication
    //  expectation from other places too
    let current_segment_index = farmer_protocol_info.total_pieces.get()
        / u64::from(farmer_protocol_info.recorded_history_segment_size)
        / u64::from(farmer_protocol_info.record_size.get())
        * 2;
    let expires_at = current_segment_index + farmer_protocol_info.sector_expiration;

    let piece_indexes: Vec<PieceIndex> = (0u64..)
        .take(plot_sector_size as usize / PIECE_SIZE)
        .map(|piece_offset| {
            sector_id.derive_piece_index(
                piece_offset as PieceIndex,
                farmer_protocol_info.total_pieces,
            )
        })
        .collect();

    for piece_index in piece_indexes.iter().copied() {
        if cancelled.load(Ordering::Acquire) {
            debug!(
                %sector_index,
                "Plotting was cancelled, interrupting plotting"
            );
            return Err(PlotSectorError::Cancelled);
        }

        let mut piece = piece_receiver
            .get_piece(piece_index)
            .await
            .map_err(|error| PlottingError::FailedToRetrievePiece { piece_index, error })?
            .ok_or(PlottingError::PieceNotFound { piece_index })?;

        // TODO: We are skipping witness part of the piece or else it is not
        //  decodable
        // TODO: Last bits may not be encoded if record size is not multiple
        //  of `space_l`
        // Encode piece
        let (record, witness_bytes) =
            piece.split_at_mut(farmer_protocol_info.record_size.get() as usize);
        // TODO: Extract encoding into separate function reusable in
        //  farmer and otherwise
        record
            .view_bits_mut::<Lsb0>()
            .chunks_mut(farmer_protocol_info.space_l.get() as usize)
            .enumerate()
            .for_each(|(chunk_index, bits)| {
                // Derive one-time pad
                let mut otp = derive_chunk_otp(&sector_id, witness_bytes, chunk_index as u32);
                // XOR chunk bit by bit with one-time pad
                bits.iter_mut()
                    .zip(otp.view_bits_mut::<Lsb0>().iter())
                    .for_each(|(mut a, b)| {
                        *a ^= *b;
                    });
            });

        sector_output.write_all(&piece).map_err(PlottingError::Io)?;
    }

    let sector_metadata = SectorMetadata {
        total_pieces: farmer_protocol_info.total_pieces,
        expires_at,
    };

    sector_metadata_output
        .write_all(&sector_metadata.encode())
        .map_err(PlottingError::Io)?;

    Ok(PlottedSector {
        sector_id,
        sector_index,
        sector_metadata,
        piece_indexes,
    })
}
