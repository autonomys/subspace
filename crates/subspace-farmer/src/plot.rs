use thiserror::Error;

mod single_plot;
#[cfg(test)]
mod single_plot_tests;

pub use single_plot::SinglePlot;

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
}

type Result<T, E = Error> = std::result::Result<T, E>;
