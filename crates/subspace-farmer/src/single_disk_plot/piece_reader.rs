use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use subspace_core_primitives::{Piece, PieceOffset, PublicKey, SectorId, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::reading;
use subspace_farmer_components::sector::{sector_size, SectorMetadata};
use subspace_proof_of_space::Table;
use tracing::{error, warn};

#[derive(Debug)]
pub(super) struct ReadPieceRequest {
    pub(super) sector_index: SectorIndex,
    pub(super) piece_offset: PieceOffset,
    pub(super) response_sender: oneshot::Sender<Option<Piece>>,
}

/// Wrapper data structure that can be used to read pieces from single disk plot
#[derive(Debug, Clone)]
pub struct PieceReader {
    read_piece_sender: mpsc::Sender<ReadPieceRequest>,
}

impl PieceReader {
    pub(super) fn new() -> (Self, mpsc::Receiver<ReadPieceRequest>) {
        let (read_piece_sender, read_piece_receiver) = mpsc::channel::<ReadPieceRequest>(10);

        (Self { read_piece_sender }, read_piece_receiver)
    }

    pub(super) fn close_all_readers(&mut self) {
        self.read_piece_sender.close_channel();
    }

    /// Read piece from sector by offset, `None` means input parameters are incorrect or piece
    /// reader was shut down
    pub async fn read_piece(
        &mut self,
        sector_index: SectorIndex,
        piece_offset: PieceOffset,
    ) -> Option<Piece> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.read_piece_sender
            .send(ReadPieceRequest {
                sector_index,
                piece_offset,
                response_sender,
            })
            .await
            .ok()?;
        response_receiver.await.ok()?
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn read_piece<PosTable>(
    public_key: &PublicKey,
    piece_offset: PieceOffset,
    pieces_in_sector: u16,
    sector_count: usize,
    first_sector_index: SectorIndex,
    sector_metadata: &SectorMetadata,
    global_plot: &[u8],
    erasure_coding: &ErasureCoding,
) -> Option<Piece>
where
    PosTable: Table,
{
    let sector_index = sector_metadata.sector_index;
    if sector_index < first_sector_index {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect first sector index"
        );
        return None;
    }
    let sector_offset = (sector_index - first_sector_index) as usize;
    // Sector must be plotted
    if sector_offset >= sector_count {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect sector offset"
        );
        return None;
    }
    // Piece must be within sector
    if u16::from(piece_offset) >= pieces_in_sector {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect piece offset"
        );
        return None;
    }

    let sector_id = SectorId::new(public_key.hash(), sector_index);
    let sector_size = sector_size(pieces_in_sector);
    // TODO: Would be nicer to have list of plots here and just index it
    let sector = &global_plot[sector_size * sector_offset..][..sector_size];

    let piece = match reading::read_piece::<PosTable>(
        piece_offset,
        &sector_id,
        sector_metadata,
        sector,
        erasure_coding,
    ) {
        Ok(piece) => piece,
        Err(error) => {
            error!(
                %sector_index,
                %piece_offset,
                %sector_count,
                %first_sector_index,
                %error,
                "Failed to read piece from sector"
            );
            return None;
        }
    };

    Some(piece)
}
