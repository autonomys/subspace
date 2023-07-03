use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use memmap2::Mmap;
use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceOffset, PublicKey, SectorId, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::reading;
use subspace_farmer_components::sector::{sector_size, SectorMetadata};
use subspace_proof_of_space::Table;
use tracing::{error, warn};

#[derive(Debug)]
struct ReadPieceRequest {
    sector_index: SectorIndex,
    piece_offset: PieceOffset,
    response_sender: oneshot::Sender<Option<Piece>>,
}

/// Wrapper data structure that can be used to read pieces from single disk plot
#[derive(Debug, Clone)]
pub struct PieceReader {
    read_piece_sender: mpsc::Sender<ReadPieceRequest>,
}

impl PieceReader {
    /// Creates new piece reader instance and background future that handles reads internally.
    ///
    /// NOTE: Background future is async, but does blocking operations and should be running in
    /// dedicated thread.
    pub(super) fn new<PosTable>(
        public_key: PublicKey,
        pieces_in_sector: u16,
        first_sector_index: SectorIndex,
        global_plot_mmap: Mmap,
        sectors_metadata: Arc<RwLock<Vec<SectorMetadata>>>,
        erasure_coding: ErasureCoding,
    ) -> (Self, impl Future<Output = ()>)
    where
        PosTable: Table,
    {
        let (read_piece_sender, read_piece_receiver) = mpsc::channel(10);

        let reading_fut = read_pieces::<PosTable>(
            public_key,
            pieces_in_sector,
            first_sector_index,
            global_plot_mmap,
            sectors_metadata,
            erasure_coding,
            read_piece_receiver,
        );

        (Self { read_piece_sender }, reading_fut)
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

async fn read_pieces<PosTable>(
    public_key: PublicKey,
    pieces_in_sector: u16,
    first_sector_index: SectorIndex,
    global_plot_mmap: Mmap,
    sectors_metadata: Arc<RwLock<Vec<SectorMetadata>>>,
    erasure_coding: ErasureCoding,
    mut read_piece_receiver: mpsc::Receiver<ReadPieceRequest>,
) where
    PosTable: Table,
{
    #[cfg(unix)]
    {
        if let Err(error) = global_plot_mmap.advise(memmap2::Advice::Random) {
            error!(%error, "Failed to set random access on global plot mmap");
        }
    }

    while let Some(read_piece_request) = read_piece_receiver.next().await {
        let ReadPieceRequest {
            sector_index,
            piece_offset,
            response_sender,
        } = read_piece_request;

        if response_sender.is_canceled() {
            continue;
        }

        let (sector_metadata, sector_count) = {
            let sectors_metadata = sectors_metadata.read();

            let sector_offset = (sector_index - first_sector_index) as usize;
            let sector_count = sectors_metadata.len();

            let sector_metadata = match sectors_metadata.get(sector_offset) {
                Some(sector_metadata) => sector_metadata.clone(),
                None => {
                    error!(
                        %sector_index,
                        %first_sector_index,
                        %sector_count,
                        "Tried to read piece from sector that is not yet \
                        plotted"
                    );
                    continue;
                }
            };

            (sector_metadata, sector_count)
        };

        let maybe_piece = read_piece::<PosTable>(
            &public_key,
            piece_offset,
            pieces_in_sector,
            sector_count,
            first_sector_index,
            &sector_metadata,
            &global_plot_mmap,
            &erasure_coding,
        );

        // Doesn't matter if receiver still cares about it
        let _ = response_sender.send(maybe_piece);
    }
}

#[allow(clippy::too_many_arguments)]
fn read_piece<PosTable>(
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
