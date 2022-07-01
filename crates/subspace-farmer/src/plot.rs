#[cfg(test)]
mod tests;

use event_listener_primitives::{Bag, HandlerId};
use num_traits::{WrappingAdd, WrappingSub};
use rocksdb::DB;
use std::collections::{BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Weak};
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PublicKey, PIECE_SIZE, SHA256_HASH_SIZE, U256,
};
use subspace_solving::SubspaceCodec;
use thiserror::Error;
use tracing::{error, info};

/// Distance to piece index hash from farmer identity
pub type PieceDistance = U256;

/// Index of piece on disk
pub type PieceOffset = u64;

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

#[derive(Debug, Default)]
pub struct WriteResult {
    pieces: Arc<FlatPieces>,
    piece_offsets: Vec<Option<PieceOffset>>,
    evicted_pieces: Vec<Piece>,
}

impl WriteResult {
    /// Iterator over tuple of piece offset and piece itself as memory slice
    pub fn to_recommitment_iterator(&self) -> impl Iterator<Item = (PieceOffset, &[u8])> {
        self.piece_offsets
            .iter()
            .zip(self.pieces.as_pieces())
            .filter_map(|(maybe_piece_offset, piece)| {
                maybe_piece_offset.map(|piece_offset| (piece_offset, piece))
            })
    }

    pub fn evicted_pieces(&self) -> &[Piece] {
        &self.evicted_pieces
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PlottedPieces {
    pub plotted_piece_count: usize,
}

#[derive(Default, Debug)]
struct Handlers {
    progress_change: Bag<Arc<dyn Fn(&PlottedPieces) + Send + Sync + 'static>, PlottedPieces>,
}

#[derive(Debug)]
enum Request {
    ReadEncoding {
        index_hash: PieceIndexHash,
        result_sender: mpsc::Sender<io::Result<Piece>>,
    },
    ReadEncodingWithIndex {
        piece_offset: PieceOffset,
        result_sender: mpsc::Sender<io::Result<(Piece, PieceIndex)>>,
    },
    ReadEncodings {
        /// Can be from 0 to the `piece_count`
        piece_offset: PieceOffset,
        count: u64,
        /// Vector containing all of the pieces as contiguous block of memory
        result_sender: mpsc::Sender<io::Result<Vec<u8>>>,
    },
    ReadPieceIndexes {
        from_index_hash: PieceIndexHash,
        count: u64,
        result_sender: mpsc::Sender<io::Result<Vec<PieceIndex>>>,
    },
    GetPieceRange {
        result_sender: mpsc::Sender<io::Result<Option<RangeInclusive<PieceIndexHash>>>>,
    },
    WriteEncodings {
        encodings: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
        /// Returns offsets of all new pieces and pieces which were replaced
        result_sender: mpsc::Sender<io::Result<WriteResult>>,
    },
    Exit {
        result_sender: mpsc::Sender<()>,
    },
}

#[derive(Debug)]
enum RequestPriority {
    Low,
    High,
}

#[derive(Debug)]
struct RequestWithPriority {
    request: Request,
    priority: RequestPriority,
}

struct Inner {
    handlers: Handlers,
    requests_sender: mpsc::SyncSender<RequestWithPriority>,
    piece_count: Arc<AtomicU64>,
    address: PublicKey,
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
    let piece_index_hash = PieceIndexHash::from(piece_index);
    let mut plots = plots.iter().collect::<Vec<_>>();
    plots
        .sort_by_key(|plot| PieceDistance::distance(&piece_index_hash, plot.public_key().as_ref()));

    plots
        .iter()
        .take(2)
        .find_map(|plot| {
            plot.read(piece_index_hash)
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
/// Pieces plotted for single identity, that's why it is required to supply both address of single
/// replica farmer and maximum amount of pieces to be stored. It offloads disk writing to separate
/// worker, which runs in the background.
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

impl Plot {
    /// Creates a new plot for persisting encoded pieces to disk
    pub fn open_or_create<B: AsRef<Path>>(
        base_directory: B,
        address: PublicKey,
        max_piece_count: u64,
    ) -> Result<Plot, PlotError> {
        let plot_worker =
            PlotWorker::from_base_directory(base_directory.as_ref(), address, max_piece_count)?;

        let (requests_sender, requests_receiver) = mpsc::sync_channel(100);

        let piece_count = Arc::clone(&plot_worker.piece_count);
        tokio::task::spawn_blocking(move || plot_worker.run(requests_receiver));

        let inner = Inner {
            handlers: Handlers::default(),
            requests_sender,
            piece_count,
            address,
        };

        Ok(Plot {
            inner: Arc::new(inner),
        })
    }

    /// Creates a new plot from any kind of plot file
    pub fn with_plot_file<P>(
        plot: P,
        base_directory: impl AsRef<Path>,
        address: PublicKey,
        max_piece_count: u64,
    ) -> Result<Plot, PlotError>
    where
        P: PlotFile + Send + 'static,
    {
        let plot_worker =
            PlotWorker::with_plot_file(plot, base_directory.as_ref(), address, max_piece_count)?;

        let (requests_sender, requests_receiver) = mpsc::sync_channel(100);

        let piece_count = Arc::clone(&plot_worker.piece_count);
        tokio::task::spawn_blocking(move || plot_worker.run(requests_receiver));

        let inner = Inner {
            handlers: Handlers::default(),
            requests_sender,
            piece_count,
            address,
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
    pub fn public_key(&self) -> PublicKey {
        self.inner.address
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

    /// Reads a piece from plot by index
    pub(crate) fn read(&self, index_hash: impl Into<PieceIndexHash>) -> io::Result<Piece> {
        let (result_sender, result_receiver) = mpsc::channel();
        let index_hash = index_hash.into();

        self.inner
            .requests_sender
            .send(RequestWithPriority {
                request: Request::ReadEncoding {
                    index_hash,
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

    pub(crate) fn downgrade(&self) -> WeakPlot {
        WeakPlot {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn read_piece(&self, index_hash: impl Into<PieceIndexHash>) -> io::Result<Vec<u8>> {
        self.read(index_hash).map(Into::into)
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
            .map(|index| self.read(index).map(|piece| (index, piece)))
            .collect()
    }

    pub fn on_progress_change(
        &self,
        callback: Arc<dyn Fn(&PlottedPieces) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.inner.handlers.progress_change.add(callback)
    }

    /// Helper function for ignoring the error that given file/directory does not exist.
    fn try_remove<P: AsRef<Path>>(
        path: P,
        remove: impl FnOnce(P) -> io::Result<()>,
    ) -> io::Result<()> {
        if path.as_ref().exists() {
            remove(path)?;
        }
        Ok(())
    }

    // TODO: Remove with the next snapshot (as it is unused by now)
    /// Erases plot in specific directory
    pub fn erase(path: impl AsRef<Path>) -> io::Result<()> {
        info!("Erasing the plot");
        Self::try_remove(path.as_ref().join("plot.bin"), fs::remove_file)?;
        info!("Erasing the plot offset to index db");
        Self::try_remove(
            path.as_ref().join("plot-offset-to-index.bin"),
            fs::remove_file,
        )?;
        info!("Erasing the plot index to offset db");
        Self::try_remove(
            path.as_ref().join("plot-index-to-offset"),
            fs::remove_dir_all,
        )?;
        info!("Erasing plot metadata");
        Self::try_remove(path.as_ref().join("plot-metadata"), fs::remove_dir_all)?;
        info!("Erasing plot commitments");
        Self::try_remove(path.as_ref().join("commitments"), fs::remove_dir_all)?;
        info!("Erasing object mappings");
        Self::try_remove(path.as_ref().join("object-mappings"), fs::remove_dir_all)?;

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct WeakPlot {
    inner: Weak<Inner>,
}

impl WeakPlot {
    pub(crate) fn upgrade(&self) -> Option<Plot> {
        self.inner.upgrade().map(|inner| Plot { inner })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BidirectionalDistanceSorted<T> {
    distance: T,
    value: T,
}

impl<T: PartialOrd> PartialOrd for BidirectionalDistanceSorted<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.distance.partial_cmp(&other.distance)
    }
}

impl<T: Ord> Ord for BidirectionalDistanceSorted<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance.cmp(&other.distance)
    }
}

impl BidirectionalDistanceSorted<PieceDistance> {
    pub fn new(value: PieceDistance) -> Self {
        let distance =
            subspace_core_primitives::bidirectional_distance(&value, &PieceDistance::MIDDLE);
        Self { value, distance }
    }
}

/// Mapping from piece index hash to piece offset.
///
/// Piece index hashes are transformed in the following manner:
/// - Assume that farmer address is the middle (`2 ^ 255`) of the `PieceDistance` field
/// - Move every piece according to that
#[derive(Debug)]
struct IndexHashToOffsetDB {
    inner: DB,
    address: PublicKey,
    max_distance_cache: BTreeSet<BidirectionalDistanceSorted<PieceDistance>>,
}

impl IndexHashToOffsetDB {
    /// Max distance cache size.
    ///
    /// You can find discussion of derivation of this number here:
    /// https://github.com/subspace/subspace/pull/449
    const MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP: usize = 8000;

    fn open_default(path: impl AsRef<Path>, address: PublicKey) -> Result<Self, PlotError> {
        let inner = DB::open_default(path.as_ref()).map_err(PlotError::IndexDbOpen)?;
        let mut me = Self {
            inner,
            address: address,
            max_distance_cache: BTreeSet::new(),
        };
        me.update_max_distance_cache();
        Ok(me)
    }

    fn update_max_distance_cache(&mut self) {
        let mut iter = self.inner.raw_iterator();

        iter.seek_to_first();
        self.max_distance_cache.extend(
            std::iter::from_fn(|| {
                let piece_index_hash = iter.key().map(PieceDistance::from_big_endian);
                if piece_index_hash.is_some() {
                    iter.next();
                }
                piece_index_hash
            })
            .take(Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP)
            .map(BidirectionalDistanceSorted::new),
        );

        iter.seek_to_last();
        self.max_distance_cache.extend(
            std::iter::from_fn(|| {
                let piece_index_hash = iter.key().map(PieceDistance::from_big_endian);
                if piece_index_hash.is_some() {
                    iter.prev();
                }
                piece_index_hash
            })
            .take(Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP)
            .map(BidirectionalDistanceSorted::new),
        );
        while self.max_distance_cache.len() > Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
            self.max_distance_cache.pop_first();
        }
    }

    fn max_distance_key(&mut self) -> Option<PieceDistance> {
        if self.max_distance_cache.is_empty() {
            self.update_max_distance_cache();
        }
        self.max_distance_cache
            .last()
            .map(|distance| distance.value)
    }

    fn piece_hash_to_distance(&self, index_hash: &PieceIndexHash) -> PieceDistance {
        // We permute distance such that if piece index hash is equal to the `self.address` then it
        // lands to the `PieceDistance::MIDDLE`
        PieceDistance::from_big_endian(&index_hash.0)
            .wrapping_sub(&PieceDistance::from_big_endian(self.address.as_ref()))
            .wrapping_add(&PieceDistance::MIDDLE)
    }

    fn piece_distance_to_hash(&self, distance: PieceDistance) -> PieceIndexHash {
        let mut piece_index_hash = PieceIndexHash([0; SHA256_HASH_SIZE]);
        distance
            .wrapping_sub(&PieceDistance::MIDDLE)
            .wrapping_add(&PieceDistance::from_big_endian(self.address.as_ref()))
            .to_big_endian(&mut piece_index_hash.0);
        piece_index_hash
    }

    // TODO: optimize fast path using `max_distance_cache`
    fn get_piece_range(&self) -> io::Result<Option<RangeInclusive<PieceIndexHash>>> {
        let mut iter = self.inner.raw_iterator();

        iter.seek_to_first();
        let start = match iter.key() {
            Some(key) => PieceDistance::from_big_endian(key),
            None => return Ok(None),
        };
        iter.seek_to_last();
        let end = iter
            .key()
            .map(PieceDistance::from_big_endian)
            .expect("Must have at least one key");

        Ok(Some(RangeInclusive::new(
            self.piece_distance_to_hash(start),
            self.piece_distance_to_hash(end),
        )))
    }

    fn get(&self, index_hash: &PieceIndexHash) -> io::Result<Option<PieceOffset>> {
        self.inner
            .get(&self.piece_hash_to_distance(index_hash).to_bytes())
            .map_err(io::Error::other)
            .and_then(|opt_val| {
                opt_val
                    .map(|val| <[u8; 8]>::try_from(val).map(PieceOffset::from_le_bytes))
                    .transpose()
                    .map_err(|_| io::Error::other("Offsets in rocksdb supposed to be 8 bytes long"))
            })
    }

    /// Returns `true` if piece plot will not result in exceeding plot size and doesn't exist
    /// already
    fn should_store(&mut self, index_hash: &PieceIndexHash) -> bool {
        self.max_distance_key()
            .map(|max_distance_key| {
                subspace_core_primitives::bidirectional_distance(
                    &max_distance_key,
                    &PieceDistance::MIDDLE,
                ) >= PieceDistance::distance(index_hash, self.address.as_ref())
            })
            .unwrap_or(true)
    }

    fn remove_furthest(&mut self) -> io::Result<Option<PieceOffset>> {
        let max_distance = match self.max_distance_key() {
            Some(max_distance) => max_distance,
            None => return Ok(None),
        };

        let result = self
            .inner
            .get(&max_distance.to_bytes())
            .map_err(io::Error::other)?
            .map(|buffer| *<&[u8; 8]>::try_from(&*buffer).unwrap())
            .map(PieceOffset::from_le_bytes);
        self.inner
            .delete(&max_distance.to_bytes())
            .map_err(io::Error::other)?;
        self.max_distance_cache
            .remove(&BidirectionalDistanceSorted::new(max_distance));

        Ok(result)
    }

    fn put(&mut self, index_hash: &PieceIndexHash, offset: PieceOffset) -> io::Result<()> {
        let key = self.piece_hash_to_distance(index_hash);
        self.inner
            .put(&key.to_bytes(), offset.to_le_bytes())
            .map_err(io::Error::other)?;

        if let Some(first) = self.max_distance_cache.first() {
            let key = BidirectionalDistanceSorted::new(key);
            if key > *first {
                self.max_distance_cache.insert(key);
                if self.max_distance_cache.len() > 2 * Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
                    self.max_distance_cache.pop_first();
                }
            }
        }

        Ok(())
    }

    fn get_sequential(
        &self,
        from: &PieceIndexHash,
        count: usize,
    ) -> Vec<(PieceIndexHash, PieceOffset)> {
        if count == 0 {
            return vec![];
        }

        let mut iter = self.inner.raw_iterator();

        let mut piece_index_hashes_and_offsets = Vec::with_capacity(count);

        iter.seek(self.piece_hash_to_distance(from).to_bytes());

        while piece_index_hashes_and_offsets.len() < count {
            if iter.key().is_none() {
                break;
            }

            let offset = PieceOffset::from_le_bytes(
                iter.value()
                    .unwrap()
                    .try_into()
                    .expect("Failed to decode piece offsets from rocksdb"),
            );
            let index_hash =
                self.piece_distance_to_hash(PieceDistance::from_big_endian(iter.key().unwrap()));
            piece_index_hashes_and_offsets.push((index_hash, offset));
            iter.next();
        }

        piece_index_hashes_and_offsets
    }
}

/// Trait for mocking plot behaviour
pub trait PlotFile {
    /// Get number of pieces in plot
    fn piece_count(&mut self) -> io::Result<u64>;

    /// Write pieces sequentially under some offset
    fn write(&mut self, pieces: impl AsRef<[u8]>, offset: PieceOffset) -> io::Result<()>;
    /// Read pieces from disk under some offset
    fn read(&mut self, offset: PieceOffset, buf: impl AsMut<[u8]>) -> io::Result<()>;

    /// Sync all writes to the plot
    fn sync_all(&mut self) -> io::Result<()>;
}

impl PlotFile for File {
    fn piece_count(&mut self) -> io::Result<u64> {
        self.metadata()
            .map(|metadata| metadata.len() / PIECE_SIZE as u64)
    }

    fn write(&mut self, pieces: impl AsRef<[u8]>, offset: PieceOffset) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset * PIECE_SIZE as u64))?;
        self.write_all(pieces.as_ref())
    }

    fn read(&mut self, offset: PieceOffset, mut buf: impl AsMut<[u8]>) -> io::Result<()> {
        self.seek(SeekFrom::Start(offset * PIECE_SIZE as u64))?;
        self.read_exact(buf.as_mut())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(&*self)
    }
}

struct PieceOffsetToIndexDb(File);

impl PieceOffsetToIndexDb {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map(Self)
    }

    pub fn get_piece_index(&mut self, offset: PieceOffset) -> io::Result<PieceIndex> {
        let mut buf = [0; 8];
        self.0.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.0.read_exact(&mut buf)?;
        Ok(PieceIndex::from_le_bytes(buf))
    }

    pub fn put_piece_index(
        &mut self,
        offset: PieceOffset,
        piece_index: PieceIndex,
    ) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.0.write_all(&piece_index.to_le_bytes())
    }

    pub fn put_piece_indexes(
        &mut self,
        start_offset: PieceOffset,
        piece_indexes: &[PieceIndex],
    ) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(
            start_offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        let piece_indexes = piece_indexes
            .iter()
            .flat_map(|piece_index| piece_index.to_le_bytes())
            .collect::<Vec<_>>();
        self.0.write_all(&piece_indexes)
    }
}

struct PlotWorker<T> {
    plot: T,
    piece_index_hash_to_offset_db: IndexHashToOffsetDB,
    piece_offset_to_index: PieceOffsetToIndexDb,
    piece_count: Arc<AtomicU64>,
    max_piece_count: u64,
}

impl PlotWorker<File> {
    fn from_base_directory(
        base_directory: impl AsRef<Path>,
        address: PublicKey,
        max_piece_count: u64,
    ) -> Result<Self, PlotError> {
        let plot = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(base_directory.as_ref().join("plot.bin"))
            .map_err(PlotError::PlotOpen)?;
        Self::with_plot_file(plot, base_directory, address, max_piece_count)
    }
}

impl<T: PlotFile> PlotWorker<T> {
    fn with_plot_file(
        mut plot: T,
        base_directory: impl AsRef<Path>,
        address: PublicKey,
        max_piece_count: u64,
    ) -> Result<Self, PlotError> {
        let piece_count = plot
            .piece_count()
            .map_err(PlotError::PlotOpen)
            .map(AtomicU64::new)
            .map(Arc::new)?;

        let piece_offset_to_index =
            PieceOffsetToIndexDb::open(base_directory.as_ref().join("plot-offset-to-index.bin"))
                .map_err(PlotError::OffsetDbOpen)?;

        // TODO: handle `piece_count.load() > max_piece_count`, we should discard some of the pieces
        //  here

        let piece_index_hash_to_offset_db = IndexHashToOffsetDB::open_default(
            base_directory.as_ref().join("plot-index-to-offset"),
            address,
        )?;

        Ok(Self {
            plot,
            piece_index_hash_to_offset_db,
            piece_offset_to_index,
            piece_count,
            max_piece_count,
        })
    }

    fn read_encoding(&mut self, piece_index_hash: PieceIndexHash) -> io::Result<Piece> {
        let mut buffer = Piece::default();
        let offset = self
            .piece_index_hash_to_offset_db
            .get(&piece_index_hash)?
            .ok_or_else(|| {
                io::Error::other(format!("Piece with hash {piece_index_hash:?} not found"))
            })?;
        self.plot.read(offset, &mut buffer).map(|()| buffer)
    }

    // TODO: Add error recovery
    fn write_encodings(
        &mut self,
        pieces: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
    ) -> io::Result<WriteResult> {
        let current_piece_count = self.piece_count.load(Ordering::SeqCst);
        let pieces_left_until_full_plot =
            (self.max_piece_count - current_piece_count).min(pieces.count() as u64);

        // Split pieces and indexes in those that can be appended to the end of plot (thus written
        // sequentially) and those that need to be checked individually and plotted one by one in
        // place of old pieces
        let (sequential_pieces, _) =
            pieces.split_at(pieces_left_until_full_plot as usize * PIECE_SIZE);
        // Iterator is more convenient for random pieces, otherwise we could take it from above
        let random_pieces = pieces
            .as_pieces()
            .skip(pieces_left_until_full_plot as usize);
        let (sequential_piece_indexes, random_piece_indexes) =
            piece_indexes.split_at(pieces_left_until_full_plot as usize);

        // Process sequential pieces
        {
            self.plot.write(sequential_pieces, current_piece_count)?;

            for (piece_offset, &piece_index) in
                (current_piece_count..).zip(sequential_piece_indexes)
            {
                self.piece_index_hash_to_offset_db
                    .put(&piece_index.into(), piece_offset)?;
            }

            self.piece_offset_to_index
                .put_piece_indexes(current_piece_count, sequential_piece_indexes)?;

            self.piece_count
                .fetch_add(pieces_left_until_full_plot, Ordering::AcqRel);
        }

        let mut piece_offsets = Vec::<Option<PieceOffset>>::with_capacity(pieces.count());
        piece_offsets.extend(
            (current_piece_count..)
                .take(pieces_left_until_full_plot as usize)
                .map(Some),
        );
        piece_offsets.resize(piece_offsets.capacity(), None);
        let mut evicted_pieces =
            Vec::with_capacity(pieces.count() - pieces_left_until_full_plot as usize);

        // Process random pieces
        for ((piece, &piece_index), maybe_piece_offset) in
            random_pieces.zip(random_piece_indexes).zip(
                piece_offsets
                    .iter_mut()
                    .skip(pieces_left_until_full_plot as usize),
            )
        {
            // Check if piece is out of plot range or if it is in the plot
            if !self
                .piece_index_hash_to_offset_db
                .should_store(&piece_index.into())
            {
                continue;
            }

            let piece_offset = self
                .piece_index_hash_to_offset_db
                .remove_furthest()?
                .expect("Must be always present as plot is non-empty; qed");

            let mut old_piece = Piece::default();
            self.plot.read(piece_offset, &mut old_piece)?;

            self.plot.write(piece, piece_offset)?;

            self.piece_index_hash_to_offset_db
                .put(&piece_index.into(), piece_offset)?;
            self.piece_offset_to_index
                .put_piece_index(piece_offset, piece_index)?;

            // TODO: This is a bit inefficient when pieces from previous iterations of this loop are
            //  evicted, causing extra tags overrides during recommitment
            maybe_piece_offset.replace(piece_offset);
            evicted_pieces.push(old_piece);
        }

        Ok(WriteResult {
            pieces,
            piece_offsets,
            evicted_pieces,
        })
    }

    fn read_piece_indexes(
        &mut self,
        from: &PieceIndexHash,
        count: u64,
    ) -> io::Result<Vec<PieceIndex>> {
        self.piece_index_hash_to_offset_db
            .get_sequential(from, count as usize)
            .into_iter()
            .map(|(_, offset)| self.piece_offset_to_index.get_piece_index(offset))
            .collect()
    }

    fn run(mut self, requests_receiver: mpsc::Receiver<RequestWithPriority>) {
        let mut low_priority_requests = VecDeque::new();
        let mut exit_result_sender = None;

        // Process as many high priority as possible, interleaved with single low priority request
        // in case no high priority requests are available.
        'outer: while let Ok(request_with_priority) = requests_receiver.recv() {
            let RequestWithPriority {
                mut request,
                mut priority,
            } = request_with_priority;

            loop {
                if matches!(priority, RequestPriority::Low) {
                    low_priority_requests.push_back(request);
                } else {
                    match request {
                        Request::ReadEncoding {
                            index_hash,
                            result_sender,
                        } => {
                            let _ = result_sender.send(self.read_encoding(index_hash));
                        }
                        Request::ReadEncodingWithIndex {
                            piece_offset,
                            result_sender,
                        } => {
                            let result = try {
                                let mut buffer = Piece::default();
                                self.plot.read(piece_offset, &mut buffer)?;
                                let index =
                                    self.piece_offset_to_index.get_piece_index(piece_offset)?;
                                (buffer, index)
                            };
                            let _ = result_sender.send(result);
                        }
                        Request::ReadEncodings {
                            piece_offset,
                            count,
                            result_sender,
                        } => {
                            let result = try {
                                let mut buffer = vec![0u8; count as usize * PIECE_SIZE];
                                self.plot.read(piece_offset, &mut buffer)?;
                                buffer
                            };
                            let _ = result_sender.send(result);
                        }
                        Request::ReadPieceIndexes {
                            from_index_hash,
                            count,
                            result_sender,
                        } => {
                            let _ = result_sender
                                .send(self.read_piece_indexes(&from_index_hash, count));
                        }
                        Request::GetPieceRange { result_sender } => {
                            let _ = result_sender
                                .send(self.piece_index_hash_to_offset_db.get_piece_range());
                        }
                        Request::WriteEncodings {
                            encodings,
                            piece_indexes,
                            result_sender,
                        } => {
                            let _ =
                                result_sender.send(self.write_encodings(encodings, piece_indexes));
                        }
                        Request::Exit { result_sender } => {
                            exit_result_sender.replace(result_sender);
                            break 'outer;
                        }
                    }
                }

                match requests_receiver.try_recv() {
                    Ok(some_request_with_priority) => {
                        request = some_request_with_priority.request;
                        priority = some_request_with_priority.priority;
                        continue;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        // If no high priority requests available, process one low priority request.
                        if let Some(low_priority_request) = low_priority_requests.pop_front() {
                            request = low_priority_request;
                            priority = RequestPriority::High;
                            continue;
                        }
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Ignore
                    }
                }

                break;
            }
        }

        if let Err(error) = self.plot.sync_all() {
            error!(%error, "Failed to sync plot file before exit");
        }

        if let Err(error) = self.piece_offset_to_index.0.sync_all() {
            error!(%error, "Failed to sync piece offset to index file before exit");
        }

        // Close the rest of databases
        drop(self);
    }
}
