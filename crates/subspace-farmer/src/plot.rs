#[cfg(test)]
mod tests;

use event_listener_primitives::{Bag, HandlerId};
use log::error;
use rocksdb::DB;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Weak};
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PieceOffset, RootBlock, PIECE_SIZE,
};
use thiserror::Error;

const LAST_ROOT_BLOCK_KEY: &[u8] = b"last_root_block";

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

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum ReadRequests {
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
}

#[derive(Debug)]
enum WriteRequests {
    WriteEncodings {
        encodings: Arc<FlatPieces>,
        first_index: PieceIndex,
        result_sender: mpsc::Sender<io::Result<()>>,
    },
}

struct Inner {
    any_requests_sender: Option<mpsc::SyncSender<()>>,
    handlers: Handlers,
    read_requests_sender: Option<mpsc::SyncSender<ReadRequests>>,
    write_requests_sender: Option<mpsc::SyncSender<WriteRequests>>,
    plot_metadata_db: Option<Arc<DB>>,
    piece_count: Arc<AtomicU64>,
}

/// `Plot` struct is an abstraction on top of both plot and tags database.
///
/// It converts requests to internal reads/writes to the plot and tags database. It
/// prioritizes reads over writes by having separate queues for reads and writes requests, read
/// requests are executed until exhausted after which at most 1 write request is handled and the
/// cycle repeats. This allows finding solution with as little delay as possible while introducing
/// changes to the plot at the same time (re-plotting on salt changes or extending plot size).
#[derive(Clone)]
pub struct Plot {
    inner: Arc<Inner>,
}

impl Plot {
    /// Creates a new plot for persisting encoded pieces to disk
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Plot, PlotError> {
        let background_worker = PlotWorker::from_base_directory(base_directory.as_ref())?;

        let plot_metadata_db = DB::open_default(base_directory.as_ref().join("plot-metadata"))
            .map_err(PlotError::MetadataDbOpen)?;

        // Channel with at most single element to throttle loop below if there are no updates
        let (any_requests_sender, any_requests_receiver) = mpsc::sync_channel::<()>(1);
        let (read_requests_sender, read_requests_receiver) =
            mpsc::sync_channel::<ReadRequests>(100);
        let (write_requests_sender, write_requests_receiver) =
            mpsc::sync_channel::<WriteRequests>(100);

        let piece_count = Arc::clone(&background_worker.piece_count);
        tokio::task::spawn_blocking(move || {
            background_worker.do_plot(
                any_requests_receiver,
                read_requests_receiver,
                write_requests_receiver,
            )
        });

        let inner = Inner {
            any_requests_sender: Some(any_requests_sender),
            handlers: Handlers::default(),
            read_requests_sender: Some(read_requests_sender),
            write_requests_sender: Some(write_requests_sender),
            plot_metadata_db: Some(Arc::new(plot_metadata_db)),
            piece_count,
        };

        Ok(Plot {
            inner: Arc::new(inner),
        })
    }

    /// How many pieces are there in the plot
    pub(crate) fn piece_count(&self) -> PieceOffset {
        self.inner.piece_count.load(Ordering::Acquire)
    }

    /// Whether plot doesn't have anything in it
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.piece_count.load(Ordering::Acquire) == 0
    }

    /// Reads a piece from plot by index
    pub(crate) fn read(&self, index_hash: impl Into<PieceIndexHash>) -> io::Result<Piece> {
        let (result_sender, result_receiver) = mpsc::channel();
        let index_hash = index_hash.into();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncoding {
                index_hash,
                result_sender,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encoding request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.recv().map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Read encoding result sender was dropped: {}", error),
            )
        })?
    }

    /// Writes a piece/s to the plot by index, will overwrite if piece exists (updates)
    pub(crate) fn write_many(
        &self,
        encodings: Arc<FlatPieces>,
        first_index: PieceIndex,
    ) -> io::Result<()> {
        if encodings.is_empty() {
            return Ok(());
        }
        self.inner
            .handlers
            .progress_change
            .call_simple(&PlottedPieces {
                plotted_piece_count: encodings.len(),
            });

        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .write_requests_sender
            .clone()
            .unwrap()
            .send(WriteRequests::WriteEncodings {
                encodings,
                first_index,
                result_sender,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending write many request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.recv().map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write many result sender was dropped: {}", error),
            )
        })?
    }

    /// Get last root block
    pub(crate) fn get_last_root_block(&self) -> Result<Option<RootBlock>, rocksdb::Error> {
        self.inner
            .plot_metadata_db
            .as_ref()
            .unwrap()
            .get(LAST_ROOT_BLOCK_KEY)
            .map(|maybe_last_root_block| {
                maybe_last_root_block.as_ref().map(|last_root_block| {
                    serde_json::from_slice(last_root_block)
                        .expect("Database contains incorrect last root block")
                })
            })
    }

    /// Store last root block
    pub(crate) fn set_last_root_block(
        &self,
        last_root_block: &RootBlock,
    ) -> Result<(), rocksdb::Error> {
        let last_root_block = serde_json::to_vec(&last_root_block).unwrap();
        self.inner
            .plot_metadata_db
            .as_ref()
            .unwrap()
            .put(LAST_ROOT_BLOCK_KEY, last_root_block)
    }

    pub(crate) fn downgrade(&self) -> WeakPlot {
        WeakPlot {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn read_piece(&self, index_hash: impl Into<PieceIndexHash>) -> io::Result<Vec<u8>> {
        self.read(index_hash)
            .map(|piece| <[u8; PIECE_SIZE]>::from(piece).to_vec())
    }

    pub(crate) fn read_piece_with_index(
        &self,
        piece_offset: PieceOffset,
    ) -> io::Result<(Piece, PieceIndex)> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncodingWithIndex {
                piece_offset,
                result_sender,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encodings request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

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
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncodings {
                piece_offset,
                count,
                result_sender,
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encodings request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.recv().map_err(|error| {
            io::Error::other(format!(
                "Read encodings result sender was dropped: {}",
                error
            ))
        })?
    }

    pub fn on_progress_change(
        &self,
        callback: Arc<dyn Fn(&PlottedPieces) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.inner.handlers.progress_change.add(callback)
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

#[derive(Debug)]
pub(crate) struct IndexHashToOffsetDB {
    inner: DB,
}

impl IndexHashToOffsetDB {
    pub fn open_default(path: impl AsRef<Path>) -> Result<Self, PlotError> {
        DB::open_default(path.as_ref())
            .map(|inner| Self { inner })
            .map_err(PlotError::IndexDbOpen)
    }

    pub fn get(&self, index_hash: PieceIndexHash) -> io::Result<Option<PieceOffset>> {
        self.inner
            .get(&index_hash.0)
            .map_err(io::Error::other)
            .and_then(|opt_val| {
                opt_val
                    .map(|val| <[u8; 8]>::try_from(val).map(PieceOffset::from_le_bytes))
                    .transpose()
                    .map_err(|_| io::Error::other("Offsets in rocksdb supposed to be 8 bytes long"))
            })
    }

    pub fn put(&self, index: PieceIndex, offset: PieceOffset) -> io::Result<()> {
        self.inner
            .put(&PieceIndexHash::from(index).0, offset.to_le_bytes())
            .map_err(io::Error::other)
    }
}

struct PlotWorker {
    plot: File,
    piece_index_hash_to_offset_db: IndexHashToOffsetDB,
    piece_offset_to_index_file: File,
    piece_count: Arc<AtomicU64>,
}

impl PlotWorker {
    pub fn from_base_directory(base_directory: impl AsRef<Path>) -> Result<Self, PlotError> {
        let plot = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(base_directory.as_ref().join("plot.bin"))
            .map_err(PlotError::PlotOpen)?;

        let plot_size = plot
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(PlotError::PlotOpen)?;

        let piece_count = Arc::new(AtomicU64::new(plot_size / PIECE_SIZE as u64));

        let piece_offset_to_index_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(base_directory.as_ref().join("plot-offset-to-index.bin"))
            .map_err(PlotError::OffsetDbOpen)?;

        let piece_index_hash_to_offset_db = IndexHashToOffsetDB::open_default(
            base_directory.as_ref().join("plot-index-to-offset"),
        )?;

        Ok(Self {
            plot,
            piece_index_hash_to_offset_db,
            piece_offset_to_index_file,
            piece_count,
        })
    }

    pub fn read_encoding(
        &mut self,
        piece_index_hash: PieceIndexHash,
        mut buffer: impl AsMut<[u8]>,
    ) -> io::Result<()> {
        let offset = self
            .piece_index_hash_to_offset_db
            .get(piece_index_hash)?
            .ok_or_else(|| {
                io::Error::other(format!("Piece with hash {piece_index_hash:?} not found"))
            })?;
        self.plot.seek(SeekFrom::Start(offset))?;
        self.plot.read_exact(buffer.as_mut())
    }

    fn get_piece_index(&mut self, offset: PieceOffset) -> io::Result<PieceIndex> {
        let mut buf = [0; 8];
        self.piece_offset_to_index_file.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.piece_offset_to_index_file.read_exact(&mut buf)?;
        Ok(PieceIndex::from_le_bytes(buf))
    }

    fn put_piece_index(&mut self, offset: PieceOffset, piece_index: PieceIndex) -> io::Result<()> {
        self.piece_offset_to_index_file.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.piece_offset_to_index_file
            .write_all(&piece_index.to_le_bytes())
    }

    pub fn do_plot(
        mut self,
        any_requests_receiver: mpsc::Receiver<()>,
        read_requests_receiver: mpsc::Receiver<ReadRequests>,
        write_requests_receiver: mpsc::Receiver<WriteRequests>,
    ) {
        let mut did_nothing = true;
        loop {
            if did_nothing {
                // Wait for stuff to come in
                if any_requests_receiver.recv().is_err() {
                    break;
                }
            }

            did_nothing = true;

            // Process as many read requests as there is
            while let Ok(read_request) = read_requests_receiver.try_recv() {
                did_nothing = false;

                match read_request {
                    ReadRequests::ReadEncoding {
                        index_hash,
                        result_sender,
                    } => {
                        let mut buffer = Piece::default();
                        let result = self.read_encoding(index_hash, &mut buffer).map(|()| buffer);
                        let _ = result_sender.send(result);
                    }
                    ReadRequests::ReadEncodingWithIndex {
                        piece_offset,
                        result_sender,
                    } => {
                        let result = try {
                            let mut buffer = Piece::default();
                            self.plot.seek(SeekFrom::Start(piece_offset))?;
                            self.plot.read_exact(buffer.as_mut())?;
                            let index = self.get_piece_index(piece_offset)?;
                            (buffer, index)
                        };
                        let _ = result_sender.send(result);
                    }
                    ReadRequests::ReadEncodings {
                        piece_offset,
                        count,
                        result_sender,
                    } => {
                        let result = try {
                            self.plot
                                .seek(SeekFrom::Start(piece_offset * PIECE_SIZE as u64))?;
                            let mut buffer = Vec::with_capacity(count as usize * PIECE_SIZE);
                            buffer.resize(buffer.capacity(), 0);
                            self.plot.read_exact(&mut buffer)?;
                            buffer
                        };
                        let _ = result_sender.send(result);
                    }
                }
            }

            let write_request = write_requests_receiver.try_recv();
            if write_request.is_ok() {
                did_nothing = false;
            }
            // Process at most write request since reading is higher priority
            if let Ok(WriteRequests::WriteEncodings {
                encodings,
                first_index,
                result_sender,
            }) = write_request
            {
                // TODO: Add error recovery
                let result = try {
                    let current_piece_count = self.piece_count.load(Ordering::SeqCst);
                    self.plot
                        .seek(SeekFrom::Start(current_piece_count * PIECE_SIZE as u64))?;
                    self.plot.write_all(&encodings)?;

                    for (offset, index) in (current_piece_count..)
                        .zip(first_index..)
                        .take(encodings.len() / PIECE_SIZE)
                    {
                        self.piece_index_hash_to_offset_db.put(index, offset)?;
                        self.put_piece_index(offset, index)?;
                        self.piece_count.fetch_add(1, Ordering::AcqRel);
                    }
                };

                let _ = result_sender.send(result);
            }
        }

        if let Err(error) = self.plot.sync_all() {
            error!("Failed to sync plot file before exit: {}", error);
        }
    }
}
