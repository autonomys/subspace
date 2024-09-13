//! Piece reader for single disk farm

use crate::farm::{FarmError, PieceReader};
#[cfg(windows)]
use crate::single_disk_farm::unbuffered_io_file_windows::UnbufferedIoFileWindows;
use async_lock::Mutex as AsyncMutex;
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use std::collections::HashSet;
#[cfg(not(windows))]
use std::fs::File;
use std::future::Future;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceOffset, PublicKey, SectorId, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::{sector_size, SectorMetadataChecksummed};
use subspace_farmer_components::{reading, ReadAt, ReadAtAsync, ReadAtSync};
use subspace_proof_of_space::Table;
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{error, warn};

#[derive(Debug)]
struct ReadPieceRequest {
    sector_index: SectorIndex,
    piece_offset: PieceOffset,
    response_sender: oneshot::Sender<Option<Piece>>,
}

/// Wrapper data structure that can be used to read pieces from single disk farm
#[derive(Debug, Clone)]
pub struct DiskPieceReader {
    read_piece_sender: mpsc::Sender<ReadPieceRequest>,
}

#[async_trait]
impl PieceReader for DiskPieceReader {
    #[inline]
    async fn read_piece(
        &self,
        sector_index: SectorIndex,
        piece_offset: PieceOffset,
    ) -> Result<Option<Piece>, FarmError> {
        Ok(self.read_piece(sector_index, piece_offset).await)
    }
}

impl DiskPieceReader {
    /// Creates new piece reader instance and background future that handles reads internally.
    ///
    /// NOTE: Background future is async, but does blocking operations and should be running in
    /// dedicated thread.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<PosTable>(
        public_key: PublicKey,
        pieces_in_sector: u16,
        #[cfg(not(windows))] plot_file: Arc<File>,
        #[cfg(windows)] plot_file: Arc<UnbufferedIoFileWindows>,
        sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
        erasure_coding: ErasureCoding,
        sectors_being_modified: Arc<AsyncRwLock<HashSet<SectorIndex>>>,
        read_sector_record_chunks_mode: ReadSectorRecordChunksMode,
        global_mutex: Arc<AsyncMutex<()>>,
    ) -> (Self, impl Future<Output = ()>)
    where
        PosTable: Table,
    {
        let (read_piece_sender, read_piece_receiver) = mpsc::channel(10);

        let reading_fut = async move {
            read_pieces::<PosTable, _>(
                public_key,
                pieces_in_sector,
                &*plot_file,
                sectors_metadata,
                erasure_coding,
                sectors_being_modified,
                read_piece_receiver,
                read_sector_record_chunks_mode,
                global_mutex,
            )
            .await
        };

        (Self { read_piece_sender }, reading_fut)
    }

    pub(super) fn close_all_readers(&mut self) {
        self.read_piece_sender.close_channel();
    }

    /// Read piece from sector by offset, `None` means input parameters are incorrect or piece
    /// reader was shut down
    pub async fn read_piece(
        &self,
        sector_index: SectorIndex,
        piece_offset: PieceOffset,
    ) -> Option<Piece> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.read_piece_sender
            .clone()
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
async fn read_pieces<PosTable, S>(
    public_key: PublicKey,
    pieces_in_sector: u16,
    plot_file: S,
    sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    erasure_coding: ErasureCoding,
    sectors_being_modified: Arc<AsyncRwLock<HashSet<SectorIndex>>>,
    mut read_piece_receiver: mpsc::Receiver<ReadPieceRequest>,
    mode: ReadSectorRecordChunksMode,
    global_mutex: Arc<AsyncMutex<()>>,
) where
    PosTable: Table,
    S: ReadAtSync,
{
    let mut table_generator = PosTable::generator();

    while let Some(read_piece_request) = read_piece_receiver.next().await {
        let ReadPieceRequest {
            sector_index,
            piece_offset,
            response_sender,
        } = read_piece_request;

        if response_sender.is_canceled() {
            continue;
        }

        let sectors_being_modified = &*sectors_being_modified.read().await;

        if sectors_being_modified.contains(&sector_index) {
            // Skip sector that is being modified right now
            continue;
        }

        let (sector_metadata, sector_count) = {
            let sectors_metadata = sectors_metadata.read().await;

            let sector_count = sectors_metadata.len() as SectorIndex;

            let sector_metadata = match sectors_metadata.get(sector_index as usize) {
                Some(sector_metadata) => sector_metadata.clone(),
                None => {
                    error!(
                        %sector_index,
                        %sector_count,
                        "Tried to read piece from sector that is not yet plotted"
                    );
                    continue;
                }
            };

            (sector_metadata, sector_count)
        };

        // Sector must be plotted
        if sector_index >= sector_count {
            warn!(
                %sector_index,
                %piece_offset,
                %sector_count,
                "Incorrect sector offset"
            );
            // Doesn't matter if receiver still cares about it
            let _ = response_sender.send(None);
            continue;
        }
        // Piece must be within sector
        if u16::from(piece_offset) >= pieces_in_sector {
            warn!(
                %sector_index,
                %piece_offset,
                %sector_count,
                "Incorrect piece offset"
            );
            // Doesn't matter if receiver still cares about it
            let _ = response_sender.send(None);
            continue;
        }

        let sector_size = sector_size(pieces_in_sector);
        let sector = plot_file.offset(u64::from(sector_index) * sector_size as u64);

        // Take mutex briefly to make sure piece reading is allowed right now
        global_mutex.lock().await;

        let maybe_piece = read_piece::<PosTable, _, _>(
            &public_key,
            piece_offset,
            &sector_metadata,
            // TODO: Async
            &ReadAt::from_sync(&sector),
            &erasure_coding,
            mode,
            &mut table_generator,
        )
        .await;

        // Doesn't matter if receiver still cares about it
        let _ = response_sender.send(maybe_piece);
    }
}

async fn read_piece<PosTable, S, A>(
    public_key: &PublicKey,
    piece_offset: PieceOffset,
    sector_metadata: &SectorMetadataChecksummed,
    sector: &ReadAt<S, A>,
    erasure_coding: &ErasureCoding,
    mode: ReadSectorRecordChunksMode,
    table_generator: &mut PosTable::Generator,
) -> Option<Piece>
where
    PosTable: Table,
    S: ReadAtSync,
    A: ReadAtAsync,
{
    let sector_index = sector_metadata.sector_index;

    let sector_id = SectorId::new(public_key.hash(), sector_index);

    let piece = match reading::read_piece::<PosTable, _, _>(
        piece_offset,
        &sector_id,
        sector_metadata,
        sector,
        erasure_coding,
        mode,
        table_generator,
    )
    .await
    {
        Ok(piece) => piece,
        Err(error) => {
            error!(
                %sector_index,
                %piece_offset,
                %error,
                "Failed to read piece from sector"
            );
            return None;
        }
    };

    Some(piece)
}
