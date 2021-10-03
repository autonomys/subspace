mod commitments;

use crate::config::Config;
use crate::plot::commitments::Commitments;
use crate::{crypto, Piece, Salt, Tag, BATCH_SIZE, PIECE_SIZE};
use async_std::fs::OpenOptions;
use futures::channel::mpsc as async_mpsc;
use futures::channel::oneshot;
use futures::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SinkExt, StreamExt};
use log::{error, trace};
use rayon::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::io::SeekFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use thiserror::Error;
use tokio::task::JoinHandle;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
    /// Commitment creation was aborted, waiting for cleanup
    Aborted,
}

#[derive(Debug, Error)]
pub(crate) enum PlotError {
    #[error("Plot open error: {0}")]
    PlotOpen(io::Error),
    #[error("Plot commitments open error: {0}")]
    PlotCommitmentsOpen(io::Error),
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
    FindByRange {
        target: Tag,
        range: u64,
        salt: Salt,
        result_sender: oneshot::Sender<io::Result<Option<(Tag, u64)>>>,
    },
}

#[derive(Debug)]
enum WriteRequests {
    WriteEncodings {
        encodings: Vec<Piece>,
        first_index: u64,
        result_sender: oneshot::Sender<io::Result<()>>,
    },
    WriteTags {
        first_index: u64,
        tags: Vec<Tag>,
        salt: Salt,
        result_sender: oneshot::Sender<io::Result<()>>,
    },
    FinishCommitmentCreation {
        salt: Salt,
        result_sender: oneshot::Sender<()>,
    },
    RemoveCommitment {
        salt: Salt,
        result_sender: oneshot::Sender<()>,
    },
}

struct Inner {
    background_handle: Option<JoinHandle<Commitments>>,
    any_requests_sender: Option<async_mpsc::Sender<()>>,
    read_requests_sender: Option<async_mpsc::Sender<ReadRequests>>,
    write_requests_sender: Option<async_mpsc::Sender<WriteRequests>>,
    piece_count: Arc<AtomicU64>,
    commitment_statuses: Mutex<HashMap<Salt, CommitmentStatus>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Close sending channels so that background future can actually exit
        self.any_requests_sender.take();
        self.read_requests_sender.take();
        self.write_requests_sender.take();

        let background_handle = self.background_handle.take().unwrap();
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { background_handle.await })
                .unwrap();
        });
    }
}

/// `Plot` struct is an abstraction on top of both plot and tags database.
///
/// It converts async requests to internal reads/writes to the plot and tags database. It
/// prioritizes reads over writes by having separate queues for reads and writes requests, read
/// requests are executed until exhausted after which at most 1 write request is handled and the
/// cycle repeats. This allows finding solution with as little delay as possible while introducing
/// changes to the plot at the same time (re-plotting on salt changes or extending plot size).
#[derive(Clone)]
pub(crate) struct Plot {
    inner: Arc<Inner>,
}

impl Plot {
    /// Creates a new plot for persisting encoded pieces to disk
    pub(crate) async fn open_or_create(config: Config) -> Result<Plot, PlotError> {
        let mut plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(config.base_directory().join("plot.bin"))
            .await
            .map_err(PlotError::PlotOpen)?;

        let plot_size = plot_file
            .metadata()
            .await
            .map_err(PlotError::PlotOpen)?
            .len();

        let piece_count = Arc::new(AtomicU64::new(plot_size / PIECE_SIZE as u64));

        // Channel with at most single element to throttle loop below if there are no updates
        let (any_requests_sender, mut any_requests_receiver) = async_mpsc::channel::<()>(1);
        let (read_requests_sender, mut read_requests_receiver) =
            async_mpsc::channel::<ReadRequests>(100);
        let (write_requests_sender, mut write_requests_receiver) =
            async_mpsc::channel::<WriteRequests>(100);

        let commitments_fut = Commitments::new(config.base_directory().join("plot-tags").into());
        let mut commitments = commitments_fut
            .await
            .map_err(PlotError::PlotCommitmentsOpen)?;
        let commitment_statuses: HashMap<Salt, CommitmentStatus> = commitments
            .get_existing_commitments()
            .map(|&salt| (salt, CommitmentStatus::Created))
            .collect();

        let background_handle = tokio::spawn({
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
                                        let mut buffer = [0u8; PIECE_SIZE];
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
                            Some(ReadRequests::FindByRange {
                                target,
                                range,
                                salt,
                                result_sender,
                            }) => {
                                let tags_db = match commitments.get_or_create_db(salt).await {
                                    Ok(tags_db) => tags_db,
                                    Err(error) => {
                                        error!("Failed to open tags database: {}", error);
                                        continue;
                                    }
                                };
                                // TODO: Remove unwrap
                                let solutions_fut = tokio::task::spawn_blocking(move || {
                                    let mut iter = tags_db.raw_iterator();

                                    let mut solutions: Vec<(Tag, u64)> = Vec::new();

                                    let (lower, is_lower_overflowed) =
                                        u64::from_be_bytes(target).overflowing_sub(range / 2);
                                    let (upper, is_upper_overflowed) =
                                        u64::from_be_bytes(target).overflowing_add(range / 2);

                                    trace!(
                                        "{} Lower overflow: {} -- Upper overflow: {}",
                                        u64::from_be_bytes(target),
                                        is_lower_overflowed,
                                        is_upper_overflowed
                                    );

                                    if is_lower_overflowed || is_upper_overflowed {
                                        iter.seek_to_first();
                                        while let Some(tag) = iter.key() {
                                            let tag = tag.try_into().unwrap();
                                            let index = iter.value().unwrap();
                                            if u64::from_be_bytes(tag) <= upper {
                                                solutions.push((
                                                    tag,
                                                    u64::from_le_bytes(index.try_into().unwrap()),
                                                ));
                                                iter.next();
                                            } else {
                                                break;
                                            }
                                        }
                                        iter.seek(lower.to_be_bytes());
                                        while let Some(tag) = iter.key() {
                                            let tag = tag.try_into().unwrap();
                                            let index = iter.value().unwrap();

                                            solutions.push((
                                                tag,
                                                u64::from_le_bytes(index.try_into().unwrap()),
                                            ));
                                            iter.next();
                                        }
                                    } else {
                                        iter.seek(lower.to_be_bytes());
                                        while let Some(tag) = iter.key() {
                                            let tag = tag.try_into().unwrap();
                                            let index = iter.value().unwrap();
                                            if u64::from_be_bytes(tag) <= upper {
                                                solutions.push((
                                                    tag,
                                                    u64::from_le_bytes(index.try_into().unwrap()),
                                                ));
                                                iter.next();
                                            } else {
                                                break;
                                            }
                                        }
                                    }

                                    solutions
                                });

                                let _ = result_sender.send(Ok(solutions_fut
                                    .await
                                    .unwrap()
                                    .into_iter()
                                    .next()));
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
                                        for encoding in &encodings {
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
                        Ok(Some(WriteRequests::WriteTags {
                            first_index,
                            tags,
                            salt,
                            result_sender,
                        })) => {
                            let _ = result_sender.send(
                                try {
                                    let tags_db = match commitments.get_or_create_db(salt).await {
                                        Ok(tags_db) => tags_db,
                                        Err(error) => {
                                            error!("Failed to open tags database: {}", error);
                                            continue;
                                        }
                                    };
                                    // TODO: remove unwrap
                                    tokio::task::spawn_blocking(move || {
                                        for (tag, index) in tags.iter().zip(first_index..) {
                                            tags_db.put(tag, index.to_le_bytes())?;
                                        }

                                        Ok::<(), rocksdb::Error>(())
                                    })
                                    .await
                                    .unwrap()
                                    .unwrap();
                                },
                            );
                        }
                        Ok(Some(WriteRequests::FinishCommitmentCreation {
                            salt,
                            result_sender,
                        })) => {
                            if let Err(error) = commitments.finish_commitment_creation(salt).await {
                                error!("Failed to finish commitment creation: {}", error);
                                continue;
                            }

                            let _ = result_sender.send(());
                        }
                        Ok(Some(WriteRequests::RemoveCommitment {
                            salt,
                            result_sender,
                        })) => {
                            if let Err(error) = commitments.remove_commitment(salt).await {
                                error!("Failed to remove commitment: {}", error);
                                continue;
                            }

                            let _ = result_sender.send(());
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

                commitments
            }
        });

        let inner = Inner {
            background_handle: Some(background_handle),
            any_requests_sender: Some(any_requests_sender),
            read_requests_sender: Some(read_requests_sender),
            write_requests_sender: Some(write_requests_sender),
            piece_count,
            commitment_statuses: Mutex::new(commitment_statuses),
        };

        Ok(Plot {
            inner: Arc::new(inner),
        })
    }

    /// Whether plot doesn't have anything in it
    pub(crate) async fn is_empty(&self) -> bool {
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

    /// Find pieces within specified solution range.
    ///
    /// Returns tag and piece index.
    pub(crate) async fn find_by_range(
        &self,
        target: [u8; 8],
        range: u64,
        salt: Salt,
    ) -> io::Result<Option<(Tag, u64)>> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .read_requests_sender
            .clone()
            .unwrap()
            .send(ReadRequests::FindByRange {
                target,
                range,
                salt,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending get by range request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Get by range result sender was dropped: {}", error),
            )
        })?
    }

    // TODO: This should also update commitment for every piece written
    /// Writes a piece to the plot by index, will overwrite if piece exists (updates)
    pub(crate) async fn write_many(
        &self,
        encodings: Vec<Piece>,
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

    // Remove all commitments for all salts except those in the list
    pub(crate) async fn retain_commitments(&self, salts: Vec<Salt>) -> io::Result<()> {
        let salts: Vec<Salt> = self
            .inner
            .commitment_statuses
            .lock()
            .unwrap()
            .drain_filter(|salt, _status| !salts.contains(salt))
            .map(|(salt, _status)| salt)
            .collect();

        for salt in salts {
            self.remove_commitment(salt).await?;
        }

        Ok(())
    }

    pub(crate) async fn create_commitment(&self, salt: Salt) -> io::Result<()> {
        {
            let mut commitment_statuses = self.inner.commitment_statuses.lock().unwrap();
            if let Some(CommitmentStatus::Created) = commitment_statuses.get(&salt) {
                return Ok(());
            }
            commitment_statuses.insert(salt, CommitmentStatus::InProgress);
        }
        let piece_count = self.inner.piece_count.load(Ordering::Acquire);
        for batch_start in (0..piece_count).step_by(BATCH_SIZE as usize) {
            if let Some(CommitmentStatus::Aborted) =
                self.inner.commitment_statuses.lock().unwrap().get(&salt)
            {
                break;
            }
            let pieces_to_process = (batch_start + BATCH_SIZE).min(piece_count) - batch_start;
            let pieces = self.read_pieces(batch_start, pieces_to_process).await?;

            let tags: Vec<Tag> = tokio::task::spawn_blocking(move || {
                pieces
                    .par_chunks_exact(PIECE_SIZE)
                    .map(|piece| crypto::create_tag(piece, &salt))
                    .collect()
            })
            .await
            .unwrap();

            let (result_sender, result_receiver) = oneshot::channel();

            self.inner
                .write_requests_sender
                .clone()
                .unwrap()
                .send(WriteRequests::WriteTags {
                    first_index: batch_start,
                    tags,
                    salt,
                    result_sender,
                })
                .await
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed sending write tags request: {}", error),
                    )
                })?;

            // If fails - it is either full or disconnected, we don't care either way, so ignore result
            let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

            result_receiver.await.map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Write tags result sender was dropped: {}", error),
                )
            })??;
        }

        let aborted = {
            let mut commitment_statuses = self.inner.commitment_statuses.lock().unwrap();
            if let Some(CommitmentStatus::Aborted) = commitment_statuses.get(&salt) {
                commitment_statuses.remove(&salt);
                true
            } else {
                false
            }
        };

        if aborted {
            self.remove_commitment(salt).await?;

            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Commitment creation was aborted",
            ));
        }

        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .write_requests_sender
            .clone()
            .unwrap()
            .send(WriteRequests::FinishCommitmentCreation {
                salt,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed sending finish commitment creation request: {}",
                        error
                    ),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Finish commitment creation result sender was dropped: {}",
                    error
                ),
            )
        })?;

        let aborted = {
            let mut commitment_statuses = self.inner.commitment_statuses.lock().unwrap();
            if let Some(CommitmentStatus::Aborted) = commitment_statuses.get(&salt) {
                commitment_statuses.remove(&salt);
                true
            } else {
                commitment_statuses.insert(salt, CommitmentStatus::Created);
                false
            }
        };

        if aborted {
            self.remove_commitment(salt).await?;

            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Commitment creation was aborted",
            ));
        }

        Ok(())
    }

    pub(crate) async fn remove_commitment(&self, salt: Salt) -> io::Result<()> {
        {
            let mut commitment_statuses = self.inner.commitment_statuses.lock().unwrap();
            if let Entry::Occupied(mut entry) = commitment_statuses.entry(salt) {
                if matches!(
                    entry.get(),
                    CommitmentStatus::InProgress | CommitmentStatus::Aborted
                ) {
                    entry.insert(CommitmentStatus::Aborted);
                    // In practice deletion will be delayed and will happen from in progress process of
                    // committing when it can be stopped
                    return Ok(());
                }

                entry.remove_entry();
            }
        }

        let (result_sender, result_receiver) = oneshot::channel();

        self.inner
            .write_requests_sender
            .clone()
            .unwrap()
            .send(WriteRequests::RemoveCommitment {
                salt,
                result_sender,
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed sending remove tags request: {}", error),
                )
            })?;

        // If fails - it is either full or disconnected, we don't care either way, so ignore result
        let _ = self.inner.any_requests_sender.clone().unwrap().try_send(());

        result_receiver.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Remove tags result sender was dropped: {}", error),
            )
        })
    }

    pub(crate) fn downgrade(&self) -> WeakPlot {
        WeakPlot {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns pieces packed one after another in contiguous `Vec<u8>`
    async fn read_pieces(&self, first_index: u64, count: u64) -> io::Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use tempfile::TempDir;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn generate_random_piece() -> Piece {
        let mut bytes = [0u8; crate::PIECE_SIZE];
        rand::thread_rng().fill(&mut bytes[..]);
        bytes
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_read_write() {
        init();
        let base_directory = TempDir::new().unwrap();
        let config = Config::open_or_create(base_directory.path().to_path_buf())
            .await
            .unwrap();

        let piece = generate_random_piece();
        let salt: Salt = [1u8; 8];
        let index = 0;

        let plot = Plot::open_or_create(config.clone()).await.unwrap();
        assert_eq!(true, plot.is_empty().await);
        plot.write_many(vec![piece], index).await.unwrap();
        plot.create_commitment(salt).await.unwrap();
        assert_eq!(false, plot.is_empty().await);
        let extracted_piece = plot.read(index).await.unwrap();

        assert_eq!(piece[..], extracted_piece[..]);

        drop(plot);

        // Make sure it is still not empty on reopen
        let plot = Plot::open_or_create(config).await.unwrap();
        assert_eq!(false, plot.is_empty().await);
        drop(plot);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_commitment() {
        init();
        let base_directory = TempDir::new().unwrap();
        let config = Config::open_or_create(base_directory.path().to_path_buf())
            .await
            .unwrap();

        let piece: Piece = [9u8; 4096];
        let salt: Salt = [1u8; 8];
        let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
        let solution_range =
            u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let index = 0;

        let plot = Plot::open_or_create(config).await.unwrap();
        plot.write_many(vec![piece], index).await.unwrap();
        plot.create_commitment(salt).await.unwrap();

        let (tag, _index) = plot
            .find_by_range(correct_tag, solution_range, salt)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(correct_tag, tag);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_by_tag() {
        init();
        let base_directory = TempDir::new().unwrap();
        let config = Config::open_or_create(base_directory.path().to_path_buf())
            .await
            .unwrap();
        let salt: Salt = [1u8; 8];

        let plot = Plot::open_or_create(config).await.unwrap();

        plot.write_many(
            (0..1024_usize).map(|_| generate_random_piece()).collect(),
            0,
        )
        .await
        .unwrap();

        plot.create_commitment(salt).await.unwrap();

        {
            let target = [0u8, 0, 0, 0, 0, 0, 0, 1];
            let solution_range =
                u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            // This is probabilistic, but should be fine most of the time
            let (solution, _) = plot
                .find_by_range(target, solution_range, salt)
                .await
                .unwrap()
                .unwrap();
            // Wraps around
            let lower = u64::from_be_bytes(target).wrapping_sub(solution_range / 2);
            let upper = u64::from_be_bytes(target) + solution_range / 2;
            let solution = u64::from_be_bytes(solution);
            assert!(
                solution >= lower || solution <= upper,
                "Solution {:?} must be over wrapped lower edge {:?} or under upper edge {:?}",
                solution.to_be_bytes(),
                lower.to_be_bytes(),
                upper.to_be_bytes(),
            );
        }

        {
            let target = [0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];
            let solution_range =
                u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            // This is probabilistic, but should be fine most of the time
            let (solution, _) = plot
                .find_by_range(target, solution_range, salt)
                .await
                .unwrap()
                .unwrap();
            // Wraps around
            let lower = u64::from_be_bytes(target) - solution_range / 2;
            let upper = u64::from_be_bytes(target).wrapping_add(solution_range / 2);
            let solution = u64::from_be_bytes(solution);
            assert!(
                solution >= lower || solution <= upper,
                "Solution {:?} must be over lower edge {:?} or under wrapped upper edge {:?}",
                solution.to_be_bytes(),
                lower.to_be_bytes(),
                upper.to_be_bytes(),
            );
        }

        {
            let target = [0xef_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let solution_range =
                u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            // This is probabilistic, but should be fine most of the time
            let (solution, _) = plot
                .find_by_range(target, solution_range, salt)
                .await
                .unwrap()
                .unwrap();
            let lower = u64::from_be_bytes(target) - solution_range / 2;
            let upper = u64::from_be_bytes(target) + solution_range / 2;
            let solution = u64::from_be_bytes(solution);
            assert!(
                solution >= lower && solution <= upper,
                "Solution {:?} must be over lower edge {:?} and under upper edge {:?}",
                solution.to_be_bytes(),
                lower.to_be_bytes(),
                upper.to_be_bytes(),
            );
        }

        drop(plot);
    }
}
