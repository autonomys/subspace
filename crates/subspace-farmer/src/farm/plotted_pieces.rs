//! Wrapper for pieces plotted under multiple plots

use crate::farm::{FarmError, PieceReader};
use async_trait::async_trait;
use rand::prelude::*;
use rayon::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use subspace_core_primitives::pieces::{Piece, PieceIndex, PieceOffset};
use subspace_core_primitives::sectors::SectorIndex;
use subspace_farmer_components::plotting::PlottedSector;
use tracing::{trace, warn};

#[derive(Debug)]
struct DummyReader;

#[async_trait]
impl PieceReader for DummyReader {
    #[inline]
    async fn read_piece(
        &self,
        _sector_index: SectorIndex,
        _piece_offset: PieceOffset,
    ) -> Result<Option<Piece>, FarmError> {
        Ok(None)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct PieceDetails<FarmIndex> {
    farm_index: FarmIndex,
    sector_index: SectorIndex,
    piece_offset: PieceOffset,
}

/// Wrapper data structure for pieces plotted under multiple plots
#[derive(Debug, Default)]
pub struct PlottedPieces<FarmIndex> {
    readers: Vec<Arc<dyn PieceReader>>,
    pieces: HashMap<PieceIndex, Vec<PieceDetails<FarmIndex>>>,
}

impl<FarmIndex> PlottedPieces<FarmIndex>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
{
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
        piece_index: PieceIndex,
    ) -> Option<impl Future<Output = Option<Piece>> + 'static> {
        let piece_details = match self.pieces.get(&piece_index) {
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
        let reader = match self.readers.get(usize::from(piece_details.farm_index)) {
            Some(reader) => reader.clone(),
            None => {
                warn!(
                    ?piece_index,
                    ?piece_details,
                    "No piece reader for associated farm index"
                );
                return None;
            }
        };

        Some(async move {
            reader
                .read_piece(piece_details.sector_index, piece_details.piece_offset)
                .await
                .unwrap_or_else(|error| {
                    warn!(
                        %error,
                        %piece_index,
                        farm_index = ?piece_details.farm_index,
                        sector_index = piece_details.sector_index,
                        "Failed to retrieve piece"
                    );
                    None
                })
        })
    }

    /// Add new sector to collect plotted pieces
    pub fn add_sector(&mut self, farm_index: FarmIndex, plotted_sector: &PlottedSector) {
        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let piece_details = PieceDetails {
                farm_index,
                sector_index: plotted_sector.sector_index,
                piece_offset,
            };

            self.pieces
                .entry(piece_index)
                .or_default()
                .push(piece_details);
        }
    }

    /// Add old sector from plotted pieces (happens on replotting)
    pub fn delete_sector(&mut self, farm_index: FarmIndex, plotted_sector: &PlottedSector) {
        for (piece_offset, &piece_index) in
            (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes.iter())
        {
            let searching_piece_details = PieceDetails {
                farm_index,
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

    /// Add new farm with corresponding piece reader
    pub fn add_farm(&mut self, farm_index: FarmIndex, piece_reader: Arc<dyn PieceReader>) {
        let farm_index = usize::from(farm_index);

        if self.readers.len() <= farm_index {
            self.readers.resize(farm_index, Arc::new(DummyReader));
            self.readers.push(piece_reader);
        } else {
            self.readers[farm_index] = piece_reader;
        }
    }

    /// Add all sectors of the farm
    pub fn delete_farm(&mut self, farm_index: FarmIndex) {
        if let Some(reader) = self.readers.get_mut(usize::from(farm_index)) {
            // Replace reader with a dummy one to maintain farm order
            *reader = Arc::new(DummyReader);

            let piece_indices_to_remove = self
                .pieces
                .par_iter_mut()
                .filter_map(|(&piece_index, piece_details)| {
                    piece_details.retain(|piece_details| piece_details.farm_index != farm_index);

                    piece_details.is_empty().then_some(piece_index)
                })
                .collect::<Vec<_>>();

            // Remove pieces for which this was the only farm storing them
            for piece_index in piece_indices_to_remove {
                self.pieces.remove(&piece_index);
            }
        }
    }

    /// Iterator over all unique piece indices plotted
    pub fn piece_indices(&self) -> impl Iterator<Item = &PieceIndex> {
        self.pieces.keys()
    }
}
