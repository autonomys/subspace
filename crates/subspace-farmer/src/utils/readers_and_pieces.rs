use crate::single_disk_plot::piece_reader::PieceReader;
use crate::utils::archival_storage_pieces::ArchivalStoragePieces;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use subspace_core_primitives::{Piece, PieceIndexHash, PieceOffset, SectorIndex};
use subspace_farmer_components::plotting::PlottedSector;
use tracing::{trace, warn};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct PieceDetails {
    disk_farm_index: u8,
    sector_index: SectorIndex,
    piece_offset: PieceOffset,
}

/// Wrapper data structure for pieces plotted under multiple plots and corresponding piece readers.
#[derive(Debug)]
pub struct ReadersAndPieces {
    readers: Vec<PieceReader>,
    pieces: HashMap<PieceIndexHash, Vec<PieceDetails>>,
    archival_storage_pieces: ArchivalStoragePieces,
}

impl ReadersAndPieces {
    pub fn new(readers: Vec<PieceReader>, archival_storage_pieces: ArchivalStoragePieces) -> Self {
        Self {
            readers,
            pieces: HashMap::new(),
            archival_storage_pieces,
        }
    }

    /// Check if piece is known and can be retrieved
    pub fn contains_piece(&self, piece_index_hash: &PieceIndexHash) -> bool {
        self.pieces.contains_key(piece_index_hash)
    }

    /// Read piece from one of the associated readers.
    ///
    /// If piece doesn't exist `None` is returned, if by the time future is polled piece is no
    /// longer in the plot, future will resolve with `None`.
    pub fn read_piece(
        &self,
        piece_index_hash: &PieceIndexHash,
    ) -> Option<impl Future<Output = Option<Piece>> + 'static> {
        let piece_details = match self.pieces.get(piece_index_hash) {
            Some(piece_details) => piece_details
                .first()
                .copied()
                .expect("Empty lists are not stored in the map; qed"),
            None => {
                trace!(
                    ?piece_index_hash,
                    "Piece is not stored in any of the local plots"
                );
                return None;
            }
        };
        let mut reader = match self.readers.get(usize::from(piece_details.disk_farm_index)) {
            Some(reader) => reader.clone(),
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

    pub fn add_sector(&mut self, disk_farm_index: u8, plotted_sector: &PlottedSector) {
        let mut new_piece_indices = Vec::new();

        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let piece_details = PieceDetails {
                disk_farm_index,
                sector_index: plotted_sector.sector_index,
                piece_offset,
            };

            match self.pieces.entry(piece_index.hash()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(piece_details);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![piece_details]);
                    new_piece_indices.push(piece_index);
                }
            }
        }

        if !new_piece_indices.is_empty() {
            self.archival_storage_pieces.add_pieces(&new_piece_indices);
        }
    }

    pub fn delete_sector(&mut self, disk_farm_index: u8, plotted_sector: &PlottedSector) {
        let mut deleted_piece_indices = Vec::new();

        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let searching_piece_details = PieceDetails {
                disk_farm_index,
                sector_index: plotted_sector.sector_index,
                piece_offset,
            };

            if let Entry::Occupied(mut entry) = self.pieces.entry(piece_index.hash()) {
                let piece_details = entry.get_mut();
                if let Some(index) =
                    piece_details
                        .iter()
                        .enumerate()
                        .find_map(|(index, piece_details)| {
                            (piece_details == &searching_piece_details).then_some(index)
                        })
                {
                    piece_details.swap_remove(index);
                }

                // We do not store empty lists
                if piece_details.is_empty() {
                    entry.remove_entry();
                    deleted_piece_indices.push(piece_index);
                }
            }
        }

        if !deleted_piece_indices.is_empty() {
            self.archival_storage_pieces
                .delete_pieces(&deleted_piece_indices);
        }
    }

    pub fn piece_index_hashes(&self) -> impl Iterator<Item = &PieceIndexHash> {
        self.pieces.keys()
    }
}
