use std::collections::HashMap;
use std::future::Future;
use subspace_core_primitives::{Piece, PieceIndexHash, SectorIndex};
use subspace_farmer::single_disk_plot::piece_reader::PieceReader;
use tracing::{trace, warn};

#[derive(Debug, Copy, Clone)]
pub struct PieceDetails {
    pub plot_offset: usize,
    pub sector_index: SectorIndex,
    pub piece_offset: u64,
}

/// Wrapper data structure for pieces plotted under multiple plots and corresponding piece readers.
#[derive(Debug)]
pub(crate) struct ReadersAndPieces {
    readers: Vec<PieceReader>,
    pieces: HashMap<PieceIndexHash, PieceDetails>,
}

impl ReadersAndPieces {
    pub(crate) fn new(
        readers: Vec<PieceReader>,
        pieces: HashMap<PieceIndexHash, PieceDetails>,
    ) -> Self {
        // TODO: Verify that plot offset and piece offset are correct
        Self { readers, pieces }
    }

    /// Check if piece is known and can be retrieved
    pub(crate) fn contains_piece(&self, piece_index_hash: &PieceIndexHash) -> bool {
        self.pieces.contains_key(piece_index_hash)
    }

    /// Read piece from one of the associated readers.
    ///
    /// If piece doesn't exist `None` is returned, if by the time future is polled piece is no
    /// longer in the plot, future will resolve with `None`.
    pub(crate) fn read_piece(
        &self,
        piece_index_hash: &PieceIndexHash,
    ) -> Option<impl Future<Output = Option<Piece>> + 'static> {
        let piece_details = match self.pieces.get(piece_index_hash).copied() {
            Some(piece_details) => piece_details,
            None => {
                trace!(
                    ?piece_index_hash,
                    "Piece is not stored in any of the local plots"
                );
                return None;
            }
        };
        let mut reader = match self.readers.get(piece_details.plot_offset).cloned() {
            Some(reader) => reader,
            None => {
                warn!(?piece_index_hash, ?piece_details, "Plot offset is invalid");
                return None;
            }
        };

        Some(async move {
            reader
                .read_piece(piece_details.sector_index, piece_details.piece_offset)
                .await
        })
    }

    /// Add more pieces from iterator.
    ///
    /// [`PieceDetails`] containing plot offset or piece offset will be silently ignored.
    pub(crate) fn add_pieces<I>(&mut self, pieces: I)
    where
        I: Iterator<Item = (PieceIndexHash, PieceDetails)>,
    {
        // TODO: Verify that plot offset and piece offset are correct
        self.pieces.extend(pieces)
    }

    pub(crate) fn piece_index_hashes(&self) -> impl Iterator<Item = &PieceIndexHash> {
        self.pieces.keys()
    }
}
