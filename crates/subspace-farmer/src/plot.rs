#[cfg(test)]
mod tests;

use log::error;
use rocksdb::DB;
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Weak};
use subspace_core_primitives::{FlatPieces, Piece, RootBlock, PIECE_SIZE};
use thiserror::Error;

const LAST_ROOT_BLOCK_KEY: &[u8] = b"last_root_block";

#[derive(Debug, Error)]
pub enum PlotError {
    #[error("Plot open error: {0}")]
    PlotOpen(io::Error),
    #[error("Metadata DB open error: {0}")]
    MetadataDbOpen(rocksdb::Error),
}

#[derive(Debug)]
enum ReadRequests {
    ReadEncoding {
        index: u64,
        result_sender: mpsc::Sender<io::Result<Piece>>,
    },
    ReadEncodings {
        first_index: u64,
        count: u64,
        /// Vector containing all of the pieces as contiguous block of memory
        result_sender: mpsc::Sender<io::Result<Vec<u8>>>,
    },
}

#[derive(Debug)]
enum WriteRequests {
    WriteEncodings {
        encodings: Arc<FlatPieces>,
        first_index: u64,
        result_sender: mpsc::Sender<io::Result<()>>,
    },
}

struct Inner {
    any_requests_sender: Option<mpsc::SyncSender<()>>,
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
        let mut plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(base_directory.as_ref().join("plot.bin"))
            .map_err(PlotError::PlotOpen)?;

        let plot_size = plot_file.metadata().map_err(PlotError::PlotOpen)?.len();

        let piece_count = Arc::new(AtomicU64::new(plot_size / PIECE_SIZE as u64));

        let plot_metadata_db = DB::open_default(base_directory.as_ref().join("plot-metadata"))
            .map_err(PlotError::MetadataDbOpen)?;

        // Channel with at most single element to throttle loop below if there are no updates
        let (any_requests_sender, any_requests_receiver) = mpsc::sync_channel::<()>(1);
        let (read_requests_sender, read_requests_receiver) =
            mpsc::sync_channel::<ReadRequests>(100);
        let (write_requests_sender, write_requests_receiver) =
            mpsc::sync_channel::<WriteRequests>(100);

        tokio::task::spawn_blocking({
            let piece_count = Arc::clone(&piece_count);

            move || {
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
                                index,
                                result_sender,
                            } => {
                                let _ = result_sender.send(
                                    try {
                                        plot_file
                                            .seek(SeekFrom::Start(index * PIECE_SIZE as u64))?;
                                        let mut buffer = Piece::default();
                                        plot_file.read_exact(&mut buffer)?;
                                        buffer
                                    },
                                );
                            }
                            ReadRequests::ReadEncodings {
                                first_index,
                                count,
                                result_sender,
                            } => {
                                let _ = result_sender.send(
                                    try {
                                        plot_file.seek(SeekFrom::Start(
                                            first_index * PIECE_SIZE as u64,
                                        ))?;
                                        let mut buffer =
                                            Vec::with_capacity(count as usize * PIECE_SIZE);
                                        buffer.resize(buffer.capacity(), 0);
                                        plot_file.read_exact(&mut buffer)?;
                                        buffer
                                    },
                                );
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
                        let _ = result_sender.send(
                            try {
                                plot_file.seek(SeekFrom::Start(first_index * PIECE_SIZE as u64))?;
                                {
                                    plot_file.write_all(&encodings)?;
                                    piece_count.fetch_max(
                                        first_index + encodings.count() as u64,
                                        Ordering::AcqRel,
                                    );
                                }
                            },
                        );
                    }
                }

                if let Err(error) = plot_file.sync_all() {
                    error!("Failed to sync plot file before exit: {}", error);
                }
            }
        });

        let inner = Inner {
            any_requests_sender: Some(any_requests_sender),
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
    pub(crate) fn piece_count(&self) -> u64 {
        self.inner.piece_count.load(Ordering::Acquire)
    }

    /// Whether plot doesn't have anything in it
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.piece_count.load(Ordering::Acquire) == 0
    }

    /// Reads a piece from plot by index
    pub(crate) fn read(&self, index: u64) -> io::Result<Piece> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncoding {
                index,
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
        first_index: u64,
    ) -> io::Result<()> {
        if encodings.is_empty() {
            return Ok(());
        }
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

    pub fn read_piece(&self, piece_index: u64) -> io::Result<Vec<u8>> {
        self.read_pieces(piece_index, 1)
    }

    // TODO: Replace index with offset
    /// Returns pieces packed one after another in contiguous `Vec<u8>`
    pub(crate) fn read_pieces(&self, first_index: u64, count: u64) -> io::Result<Vec<u8>> {
        let (result_sender, result_receiver) = mpsc::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncodings {
                first_index,
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
            io::Error::new(
                io::ErrorKind::Other,
                format!("Read encodings result sender was dropped: {}", error),
            )
        })?
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
