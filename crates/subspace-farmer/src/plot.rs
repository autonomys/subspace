use std::{path::Path, sync::Arc};

use subspace_core_primitives::{FlatPieces, Piece, PieceIndex, PublicKey, RootBlock};
use thiserror::Error;

mod single_plot;
#[cfg(test)]
mod single_plot_tests;

pub use single_plot::SinglePlot;

use crate::Identity;

use self::single_plot::WriteResult;

/// Index of piece on disk
pub(crate) type PieceOffset = u64;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Plot open error: {0}")]
    PlotOpen(std::io::Error),
    #[error("Metadata DB open error: {0}")]
    MetadataDbOpen(rocksdb::Error),
    #[error("Index DB open error: {0}")]
    IndexDbOpen(rocksdb::Error),
    #[error("Offset DB open error: {0}")]
    OffsetDbOpen(std::io::Error),
    #[error("Failed to create directory for plotting: {0}")]
    DirectoryCreateError(std::io::Error),
    #[error("Failed to open or create identity for plotting: {0}")]
    IdentityOpenError(anyhow::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Abstraction around many plots which allows to store multiple replicas of data.
#[derive(Clone)]
pub struct MultiPlot {
    pub plots: Vec<SinglePlot>,
}

impl MultiPlot {
    /// Creates or opens several plots for persisting encoded pieces on disk.
    /// - `base_directory` - directory which will store all the plots (each plot will be stored in
    /// one of directories in `base_directory`)
    /// - `max_pieces_count` - vector of number of pieces for each plot (Amount of plots is taken
    /// from it implicitly)
    pub fn open_or_create(
        base_directory: impl AsRef<Path>,
        max_pieces_count: Vec<u64>,
    ) -> Result<(Self, Vec<Identity>)> {
        let base_directory = base_directory.as_ref();
        let plots_and_identities = max_pieces_count
            .into_iter()
            .zip((0..).map(|i| base_directory.join(format!("replica{i}"))))
            .map(|(max_piece_count, base_directory)| {
                std::fs::create_dir_all(&base_directory).map_err(Error::DirectoryCreateError)?;
                let identity =
                    Identity::open_or_create(&base_directory).map_err(Error::IdentityOpenError)?;
                let address = identity.public_key().to_bytes().into();
                let plot = SinglePlot::open_or_create(base_directory, address, max_piece_count)?;
                Ok((plot, identity))
            })
            .collect::<Result<Vec<_>>>()?;
        let (plots, identities) = plots_and_identities.into_iter().unzip();
        Ok((Self { plots }, identities))
    }

    pub(crate) fn open_or_create_single_plot(
        base_directory: impl AsRef<Path>,
        max_piece_count: u64,
    ) -> Result<(Self, Identity)> {
        let (multiplot, identities) = Self::open_or_create(base_directory, vec![max_piece_count])?;
        Ok((multiplot, identities.into_iter().next().unwrap()))
    }

    pub(crate) fn open_or_create_single_plot_with_address(
        base_directory: impl AsRef<Path>,
        address: PublicKey,
        max_piece_count: u64,
    ) -> Result<Self> {
        let base_directory = base_directory.as_ref();
        std::fs::create_dir_all(&base_directory).map_err(Error::DirectoryCreateError)?;
        let plot = SinglePlot::open_or_create(base_directory, address, max_piece_count)?;
        Ok(Self { plots: vec![plot] })
    }

    /// Whether plots don't have anything in them
    pub(crate) fn get_last_root_block(&self) -> Result<Option<RootBlock>, rocksdb::Error> {
        let mut last_root_block = None;
        for plot in &self.plots {
            last_root_block = last_root_block.max(plot.get_last_root_block()?)
        }
        Ok(last_root_block)
    }

    /// Whether plots don't have anything in them
    pub(crate) fn is_empty(&self) -> bool {
        self.plots.iter().all(|plot| plot.is_empty())
    }

    /// Writes a piece/s to all plot by index, will overwrite if piece exists (updates)
    pub fn write_many(
        &self,
        encodings: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
    ) -> std::io::Result<Vec<WriteResult>> {
        self.plots
            .iter()
            .map(|plot| plot.write_many(encodings.clone(), piece_indexes.clone()))
            .collect()
    }
}
