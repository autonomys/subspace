mod piece_index_hash_to_offset_db;
mod piece_offset_to_index_db;
#[cfg(test)]
mod tests;
mod worker;

use crate::plot::worker::{PlotWorker, Request, RequestPriority, RequestWithPriority, WriteResult};
use event_listener_primitives::{Bag, HandlerId};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::{fmt, io};
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PublicKey, PIECE_SIZE, U256,
};
use subspace_solving::SubspaceCodec;
use thiserror::Error;
use tracing::error;

/// Distance to piece index hash from farmer identity
pub type PieceDistance = U256;

/// Index of piece on disk
pub type PieceOffset = u64;

/// Trait for mocking plot behaviour
pub trait PlotFile {
    /// Get number of pieces in plot
    fn piece_count(&mut self) -> io::Result<u64>;

    /// Write pieces sequentially under some offset
    fn write(&mut self, pieces: impl AsRef<[u8]>, offset: PieceOffset) -> io::Result<()>;
    /// Read pieces from disk under some offset
    fn read(&mut self, offset: PieceOffset, buf: impl AsMut<[u8]>) -> io::Result<()>;
}

impl<T> PlotFile for T
where
    T: Read + Write + Seek,
{
    fn piece_count(&mut self) -> io::Result<u64> {
        let plot_file_size = self.seek(SeekFrom::End(0))?;

        Ok(plot_file_size / PIECE_SIZE as u64)
    }

    /// Write pieces sequentially under some offset
    fn write(&mut self, pieces: impl AsRef<[u8]>, offset: PieceOffset) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset * PIECE_SIZE as u64))?;
        self.write_all(pieces.as_ref())
    }

    fn read(&mut self, offset: PieceOffset, mut buf: impl AsMut<[u8]>) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset * PIECE_SIZE as u64))?;
        self.read_exact(buf.as_mut())
    }
}

#[derive(Debug, Error)]
pub enum PlotError {
    #[error("Plot open error: {0}")]
    PlotOpen(io::Error),
    #[error("Metadata DB open error: {0}")]
    MetadataDbOpen(rocksdb::Error),
    #[error("Index DB open error: {0}")]
    IndexDbOpen(rocksdb::Error),
    #[error("Offset DB open error: {0}")]
    OffsetDbOpen(io::Error),
}

#[derive(Debug, Copy, Clone)]
pub struct PlottedPieces {
    pub plotted_piece_count: usize,
}

#[derive(Default, Debug)]
struct Handlers {
    progress_change: Bag<Arc<dyn Fn(&PlottedPieces) + Send + Sync + 'static>, PlottedPieces>,
}

struct Inner {
    handlers: Handlers,
    requests_sender: mpsc::SyncSender<RequestWithPriority>,
    piece_count: Arc<AtomicU64>,
    public_key: PublicKey,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let (result_sender, result_receiver) = mpsc::channel();

        if self
            .requests_sender
            .send(RequestWithPriority {
                request: Request::Exit { result_sender },
                priority: RequestPriority::Low,
            })
            .is_ok()
        {
            // We don't care why this returns
            let _ = result_receiver.recv();
        }
    }
}

/// Retrieves and decodes a single piece from multiple plots
pub fn retrieve_piece_from_plots(
    plots: &[Plot],
    piece_index: PieceIndex,
) -> io::Result<Option<Piece>> {
    let piece_index_hash = PieceIndexHash::from_index(piece_index);
    let mut plots = plots.iter().collect::<Vec<_>>();
    plots
        .sort_by_key(|plot| PieceDistance::distance(&piece_index_hash, plot.public_key().as_ref()));

    plots
        .iter()
        .take(2)
        .find_map(|plot| {
            plot.read_piece(piece_index_hash)
                .map(|piece| (piece, plot.public_key()))
                .ok()
        })
        .map(|(mut piece, public_key)| {
            // TODO: Do not recreate codec each time
            SubspaceCodec::new(&public_key)
                .decode(&mut piece, piece_index)
                .map_err(|_| io::Error::other("Failed to decode piece"))
                .map(move |()| piece)
        })
        .transpose()
}

/// `Plot` is an abstraction for plotted pieces and some mappings.
///
/// Pieces plotted for single identity, that's why it is required to supply both public key of
/// single replica farmer and maximum number of pieces to be stored. It offloads disk writing to
/// separate worker, which runs in the background.
///
/// The worker converts requests to internal reads/writes to the plot database to direct disk
/// reads/writes. It prioritizes reads over writes by having separate queues for high and low
/// priority requests, read requests are executed until exhausted after which at most 1 write
/// request is handled and the cycle repeats. This allows finding solution with as little delay as
/// possible while introducing changes to the plot at the same time.
#[derive(Clone)]
pub struct Plot {
    inner: Arc<Inner>,
}

impl fmt::Debug for Plot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plot").finish()
    }
}

impl Plot {
    /// Creates a new plot for persisting encoded pieces to disk
    pub fn open_or_create(
        plot_directory: &Path,
        metadata_directory: &Path,
        public_key: PublicKey,
        max_piece_count: u64,
    ) -> Result<Plot, PlotError> {
        let plot = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(plot_directory.join("plot.bin"))
            .map_err(PlotError::PlotOpen)?;

        Self::with_plot_file(plot, metadata_directory, public_key, max_piece_count)
    }

    /// Creates a new plot from any kind of plot file
    pub fn with_plot_file<P>(
        plot: P,
        metadata_directory: &Path,
        public_key: PublicKey,
        max_piece_count: u64,
    ) -> Result<Plot, PlotError>
    where
        P: PlotFile + Send + 'static,
    {
        let plot_worker = PlotWorker::new(plot, metadata_directory, public_key, max_piece_count)?;

        let (requests_sender, requests_receiver) = mpsc::sync_channel(100);

        let piece_count = Arc::clone(plot_worker.piece_count());
        tokio::task::spawn_blocking(move || plot_worker.run(requests_receiver));

        let inner = Inner {
            handlers: Handlers::default(),
            requests_sender,
            piece_count,
            public_key,
        };

        Ok(Plot {
            inner: Arc::new(inner),
        })
    }

    /// How many pieces are there in the plot
    pub fn piece_count(&self) -> PieceOffset {
        self.inner.piece_count.load(Ordering::Acquire)
    }

    /// Public key for which pieces were plotted
    fn public_key(&self) -> PublicKey {
        self.inner.public_key
    }

    /// Whether plot doesn't have anything in it
    pub fn is_empty(&self) -> bool {
        self.piece_count() == 0
    }

    /// Returns range which contains all of the pieces
    pub fn get_piece_range(&self) -> io::Result<Option<RangeInclusive<PieceIndexHash>>> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::GetPieceRange { result_sender },
                priority: RequestPriority::Low,
            })
            .map_err(|error| {
                io::Error::other(format!("Failed sending piece range request: {error}"))
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!("Piece range result sender was dropped: {error}"))
        })?
    }

    /// Reads a piece from plot by piece index hash
    pub(crate) fn read_piece(&self, piece_index_hash: PieceIndexHash) -> io::Result<Piece> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::ReadEncoding {
                    index_hash: piece_index_hash,
                    result_sender,
                },
                priority: RequestPriority::High,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encoding request: {}", error),
                )
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Read encoding result sender was dropped: {}", error),
            )
        })?
    }

    /// Writes a piece/s to the plot by index, will overwrite if piece exists (updates)
    pub fn write_many(
        &self,
        encodings: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
    ) -> io::Result<WriteResult> {
        if encodings.is_empty() {
            return Ok(Default::default());
        }
        self.inner
            .handlers
            .progress_change
            .call_simple(&PlottedPieces {
                plotted_piece_count: encodings.len(),
            });

        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::WriteEncodings {
                    encodings,
                    piece_indexes,
                    result_sender,
                },
                priority: RequestPriority::Low,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending write many request: {}", error),
                )
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!("Write many result sender was dropped: {error}"))
        })?
    }

    pub(crate) fn read_piece_with_index(
        &self,
        piece_offset: PieceOffset,
    ) -> io::Result<(Piece, PieceIndex)> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::ReadEncodingWithIndex {
                    piece_offset,
                    result_sender,
                },
                priority: RequestPriority::High,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encodings request: {}", error),
                )
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!(
                "Read encodings result sender was dropped: {}",
                error
            ))
        })?
    }

    /// Returns pieces packed one after another in contiguous `Vec<u8>`
    pub(crate) fn read_pieces(&self, piece_offset: PieceOffset, count: u64) -> io::Result<Vec<u8>> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::ReadEncodings {
                    piece_offset,
                    count,
                    result_sender,
                },
                priority: RequestPriority::High,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encodings request: {}", error),
                )
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!(
                "Read encodings result sender was dropped: {}",
                error
            ))
        })?
    }

    /// Returns sequential piece indexes for piece retrieval
    pub(crate) fn read_sequential_piece_indexes(
        &self,
        from_index_hash: PieceIndexHash,
        count: u64,
    ) -> io::Result<Vec<PieceIndex>> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::ReadPieceIndexes {
                    from_index_hash,
                    count,
                    result_sender,
                },
                priority: RequestPriority::Low,
            })
            .map_err(|error| {
                io::Error::other(format!(
                    "Failed sending read piece indexes request: {error}"
                ))
            })?;

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!(
                "Read piece indexes result sender was dropped: {error}",
            ))
        })?
    }

    // TODO: Return (Vec<PieceIndex>, FlatPieces) instead
    /// Returns pieces and their indexes starting from supplied piece index hash (`from`)
    pub(crate) fn get_sequential_pieces(
        &self,
        from: PieceIndexHash,
        count: u64,
    ) -> io::Result<Vec<(PieceIndex, Piece)>> {
        self.read_sequential_piece_indexes(from, count)?
            .into_iter()
            .map(|index| {
                self.read_piece(PieceIndexHash::from_index(index))
                    .map(|piece| (index, piece))
            })
            .collect()
    }

    pub fn on_progress_change(
        &self,
        callback: Arc<dyn Fn(&PlottedPieces) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.inner.handlers.progress_change.add(callback)
    }
}
