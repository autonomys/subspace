use crate::single_disk_farm::piece_reader::DiskPieceReader;
use rand::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use subspace_core_primitives::{Piece, PieceIndex, PieceOffset, SectorIndex};
use subspace_farmer_components::plotting::PlottedSector;
use tracing::{trace, warn};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct PieceDetails {
    disk_farm_index: u8,
    sector_index: SectorIndex,
    piece_offset: PieceOffset,
}

/// Wrapper data structure for pieces plotted under multiple plots.
#[derive(Debug)]
pub struct PlottedPieces {
    readers: Vec<DiskPieceReader>,
    pieces: HashMap<PieceIndex, Vec<PieceDetails>>,
}

impl PlottedPieces {
    /// Initialize with readers for each farm
    pub fn new(readers: Vec<DiskPieceReader>) -> Self {
        Self {
            readers,
            pieces: HashMap::new(),
        }
    }

    /// Check if piece is known and can be retrieved
    pub fn contains_piece(&self, piece_index: &PieceIndex) -> bool {
        self.pieces.contains_key(piece_index)
    }

    /// Read plotted piece from one of the farms.
    ///
    /// If piece doesn't exist `None` is returned, if by the time future is polled piece is no
    /// longer in the plot, future will resolve with `None`.
    pub fn read_piece(
        &self,
        piece_index: &PieceIndex,
    ) -> Option<impl Future<Output = Option<Piece>> + 'static> {
        let piece_details = match self.pieces.get(piece_index) {
            Some(piece_details) => piece_details
                .choose(&mut thread_rng())
                .copied()
                .expect("Empty lists are not stored in the map; qed"),
            None => {
                trace!(
                    ?piece_index,
                    "Piece is not stored in any of the local plots"
                );
                return None;
            }
        };
        let mut reader = match self.readers.get(usize::from(piece_details.disk_farm_index)) {
            Some(reader) => reader.clone(),
            None => {
                warn!(?piece_index, ?piece_details, "Plot offset is invalid");
                return None;
            }
        };

        Some(async move {
            reader
                .read_piece(piece_details.sector_index, piece_details.piece_offset)
                .await
        })
    }

    /// Add new sector to collect plotted pieces
    pub fn add_sector(&mut self, disk_farm_index: u8, plotted_sector: &PlottedSector) {
        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let piece_details = PieceDetails {
                disk_farm_index,
                sector_index: plotted_sector.sector_index,
                piece_offset,
            };

            match self.pieces.entry(piece_index) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(piece_details);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![piece_details]);
                }
            }
        }
    }

    /// Add old sector from plotted pieces (happens on replotting)
    pub fn delete_sector(&mut self, disk_farm_index: u8, plotted_sector: &PlottedSector) {
        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let searching_piece_details = PieceDetails {
                disk_farm_index,
                sector_index: plotted_sector.sector_index,
                piece_offset,
            };

            if let Entry::Occupied(mut entry) = self.pieces.entry(piece_index) {
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
                }
            }
        }
    }

    /// Iterator over all unique piece indices plotted
    pub fn piece_indices(&self) -> impl Iterator<Item = &PieceIndex> {
        self.pieces.keys()
    }
}
