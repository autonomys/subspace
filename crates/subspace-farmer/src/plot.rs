#[cfg(test)]
mod tests;

use async_std::fs::OpenOptions;
use futures::channel::mpsc as async_mpsc;
use futures::channel::oneshot;
use futures::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SinkExt, StreamExt};
use log::error;
use rocksdb::DB;
use std::io;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use subspace_core_primitives::{Piece, RootBlock, PIECE_SIZE};
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
        result_sender: oneshot::Sender<io::Result<Piece>>,
    },
    ReadEncodings {
        first_index: u64,
        count: u64,
        /// Vector containing all of the pieces as contiguous block of memory
        result_sender: oneshot::Sender<io::Result<Vec<u8>>>,
    },
}

#[derive(Debug)]
enum WriteRequests {
    WriteEncodings {
        encodings: Arc<Vec<Piece>>,
        first_index: u64,
        result_sender: oneshot::Sender<io::Result<()>>,
    },
}

struct Inner {
    any_requests_sender: Option<async_mpsc::Sender<()>>,
    read_requests_sender: Option<async_mpsc::Sender<ReadRequests>>,
    write_requests_sender: Option<async_mpsc::Sender<WriteRequests>>,
    plot_metadata_db: Option<Arc<DB>>,
    piece_count: Arc<AtomicU64>,
}

/// `Plot` struct is an abstraction on top of both plot and tags database.
///
/// It converts async requests to internal reads/writes to the plot and tags database. It
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
    pub async fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Plot, PlotError> {
        let mut plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(base_directory.as_ref().join("plot.bin"))
            .await
            .map_err(PlotError::PlotOpen)?;

        let plot_size = plot_file
            .metadata()
            .await
            .map_err(PlotError::PlotOpen)?
            .len();

        let piece_count = Arc::new(AtomicU64::new(plot_size / PIECE_SIZE as u64));

        let plot_metadata_db = tokio::task::spawn_blocking({
            let path = base_directory.as_ref().join("plot-metadata");

            move || DB::open_default(path)
        })
        .await
        .unwrap()
        .map_err(PlotError::MetadataDbOpen)?;

        // Channel with at most single element to throttle loop below if there are no updates
        let (any_requests_sender, mut any_requests_receiver) = async_mpsc::channel::<()>(1);
        let (read_requests_sender, mut read_requests_receiver) =
            async_mpsc::channel::<ReadRequests>(100);
        let (write_requests_sender, mut write_requests_receiver) =
            async_mpsc::channel::<WriteRequests>(100);

        tokio::spawn({
            let piece_count = Arc::clone(&piece_count);

            async move {
                let mut did_nothing = true;
                'outer: loop {
                    if did_nothing {
                        // Wait for stuff to come in
                        if any_requests_receiver.next().await.is_none() {
                            break;
                        }
                    }

                    did_nothing = true;

                    // Process as many read requests as there is
                    while let Ok(read_request) = read_requests_receiver.try_next() {
                        did_nothing = false;

                        match read_request {
                            Some(ReadRequests::ReadEncoding {
                                index,
                                result_sender,
                            }) => {
                                let _ = result_sender.send(
                                    try {
                                        plot_file
                                            .seek(SeekFrom::Start(index * PIECE_SIZE as u64))
                                            .await?;
                                        let mut buffer = Piece::default();
                                        plot_file.read_exact(&mut buffer).await?;
                                        buffer
                                    },
                                );
                            }
                            Some(ReadRequests::ReadEncodings {
                                first_index,
                                count,
                                result_sender,
                            }) => {
                                let _ = result_sender.send(
                                    try {
                                        plot_file
                                            .seek(SeekFrom::Start(first_index * PIECE_SIZE as u64))
                                            .await?;
                                        let mut buffer =
                                            Vec::with_capacity(count as usize * PIECE_SIZE);
                                        buffer.resize(buffer.capacity(), 0);
                                        plot_file.read_exact(&mut buffer).await?;
                                        buffer
                                    },
                                );
                            }
                            None => {
                                break 'outer;
                            }
                        }
                    }

                    let write_request = write_requests_receiver.try_next();
                    if write_request.is_ok() {
                        did_nothing = false;
                    }
                    // Process at most write request since reading is higher priority
                    match write_request {
                        Ok(Some(WriteRequests::WriteEncodings {
                            encodings,
                            first_index,
                            result_sender,
                        })) => {
                            let _ = result_sender.send(
                                try {
                                    plot_file
                                        .seek(SeekFrom::Start(first_index * PIECE_SIZE as u64))
                                        .await?;
                                    {
                                        let mut whole_encoding = Vec::with_capacity(
                                            encodings[0].len() * encodings.len(),
                                        );
                                        for encoding in encodings.iter() {
                                            whole_encoding.extend_from_slice(encoding);
                                        }
                                        plot_file.write_all(&whole_encoding).await?;
                                        piece_count.fetch_max(
                                            first_index + encodings.len() as u64,
                                            Ordering::AcqRel,
                                        );
                                    }
                                },
                            );
                        }
                        Ok(None) => {
                            break 'outer;
                        }
                        Err(_) => {
                            // Ignore
                        }
                    }
                }

                if let Err(error) = plot_file.sync_all().await {
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

    /// Whether plot doesn't have anything in it
    pub(crate) fn piece_count(&self) -> u64 {
        self.inner.piece_count.load(Ordering::Acquire)
    }

    /// Whether plot doesn't have anything in it
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.piece_count.load(Ordering::Acquire) == 0
    }

    /// Reads a piece from plot by index
    pub(crate) async fn read(&self, index: u64) -> io::Result<Piece> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncoding {
                index,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encoding request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Read encoding result sender was dropped: {}", error),
            )
        })?
    }

    /// Writes a piece to the plot by index, will overwrite if piece exists (updates)
    pub(crate) async fn write_many(
        &self,
        encodings: Arc<Vec<Piece>>,
        first_index: u64,
    ) -> io::Result<()> {
        if encodings.is_empty() {
            return Ok(());
        }
        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .write_requests_sender
            .clone()
            .unwrap()
            .send(WriteRequests::WriteEncodings {
                encodings,
                first_index,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending write many request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write many result sender was dropped: {}", error),
            )
        })?
    }

    /// Get last root block
    pub(crate) async fn get_last_root_block(&self) -> Result<Option<RootBlock>, rocksdb::Error> {
        let db = Arc::clone(self.inner.plot_metadata_db.as_ref().unwrap());
        tokio::task::spawn_blocking(move || {
            db.get(LAST_ROOT_BLOCK_KEY).map(|maybe_last_root_block| {
                maybe_last_root_block.as_ref().map(|last_root_block| {
                    serde_json::from_slice(last_root_block)
                        .expect("Database contains incorrect last root block")
                })
            })
        })
        .await
        .unwrap()
    }

    /// Store last root block
    pub(crate) async fn set_last_root_block(
        &self,
        last_root_block: &RootBlock,
    ) -> Result<(), rocksdb::Error> {
        let db = Arc::clone(self.inner.plot_metadata_db.as_ref().unwrap());
        let last_root_block = serde_json::to_vec(&last_root_block).unwrap();
        tokio::task::spawn_blocking(move || db.put(LAST_ROOT_BLOCK_KEY, last_root_block))
            .await
            .unwrap()
    }

    pub(crate) fn downgrade(&self) -> WeakPlot {
        WeakPlot {
            inner: Arc::downgrade(&self.inner),
        }
    }

    // TODO: Replace index with offset
    /// Returns pieces packed one after another in contiguous `Vec<u8>`
    pub(crate) async fn read_pieces(&self, first_index: u64, count: u64) -> io::Result<Vec<u8>> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::ReadEncodings {
                first_index,
                count,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending read encodings request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
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
