//! Disk piece cache implementation

mod metrics;
#[cfg(test)]
mod tests;

use crate::disk_piece_cache::metrics::DiskPieceCacheMetrics;
use crate::farm;
use crate::farm::{FarmError, PieceCacheId, PieceCacheOffset};
use crate::single_disk_farm::direct_io_file::{DISK_SECTOR_SIZE, DirectIoFile};
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt, stream};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Poll;
use std::{fs, io};
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash_list};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_farmer_components::file_ext::FileExt;
use subspace_networking::utils::AsyncJoinOnDrop;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::task;
use tracing::{Span, debug, info, warn};

/// How many pieces should be skipped before stopping to check the rest of contents, this allows to
/// not miss most of the pieces after one or two corrupted pieces
const CONTENTS_READ_SKIP_LIMIT: usize = 3;
/// How many piece to read from disk at the same time (using tokio thread pool)
const PIECES_READING_CONCURRENCY: usize = 32;

/// Disk piece cache open error
#[derive(Debug, Error)]
pub enum DiskPieceCacheError {
    /// I/O error occurred
    #[error("Disk piece cache I/O error: {0}")]
    Io(#[from] io::Error),
    /// Can't preallocate cache file, probably not enough space on disk
    #[error("Can't preallocate cache file, probably not enough space on disk: {0}")]
    CantPreallocateCacheFile(io::Error),
    /// Offset outsize of range
    #[error("Offset outsize of range: provided {provided}, max {max}")]
    OffsetOutsideOfRange {
        /// Provided offset
        provided: u32,
        /// Max offset
        max: u32,
    },
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

#[derive(Debug)]
struct FilePool {
    files: Box<[DirectIoFile; PIECES_READING_CONCURRENCY]>,
    cursor: AtomicU8,
}

impl FilePool {
    fn open(path: &Path) -> io::Result<Self> {
        let files = (0..PIECES_READING_CONCURRENCY)
            .map(|_| DirectIoFile::open(path))
            .collect::<Result<Box<_>, _>>()?
            .try_into()
            .expect("Statically correct length; qed");
        Ok(Self {
            files,
            cursor: AtomicU8::new(0),
        })
    }

    fn read(&self) -> &DirectIoFile {
        let position = usize::from(self.cursor.fetch_add(1, Ordering::Relaxed));
        &self.files[position % PIECES_READING_CONCURRENCY]
    }

    fn write(&self) -> &DirectIoFile {
        // Always the same file or else overlapping writes will be corrupted due to
        // read/modify/write internals, which are in turn caused by alignment requirements
        &self.files[0]
    }
}

#[derive(Debug)]
struct Inner {
    id: PieceCacheId,
    files: FilePool,
    max_num_elements: u32,
    metrics: Option<DiskPieceCacheMetrics>,
}

/// Dedicated piece cache stored on one disk, is used both to accelerate DSN queries and to plot
/// faster.
///
/// Implementation is backed by a file on disk.
#[derive(Debug, Clone)]
pub struct DiskPieceCache {
    inner: Arc<Inner>,
}

#[async_trait]
impl farm::PieceCache for DiskPieceCache {
    fn id(&self) -> &PieceCacheId {
        &self.inner.id
    }

    #[inline]
    fn max_num_elements(&self) -> u32 {
        self.inner.max_num_elements
    }

    async fn contents(
        &self,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<(PieceCacheOffset, Option<PieceIndex>), FarmError>>
                + Unpin
                + Send
                + '_,
        >,
        FarmError,
    > {
        let this = self.clone();
        let (mut sender, receiver) = mpsc::channel(100_000);
        let span = Span::current();
        let read_contents = task::spawn_blocking(move || {
            let _guard = span.enter();

            let contents = this.contents();
            for (piece_cache_offset, maybe_piece) in contents {
                if let Err(error) =
                    Handle::current().block_on(sender.send(Ok((piece_cache_offset, maybe_piece))))
                {
                    debug!(%error, "Aborting contents iteration due to receiver dropping");
                    break;
                }
            }
        });
        let read_contents = Mutex::new(Some(AsyncJoinOnDrop::new(read_contents, false)));
        // Change order such that in closure below `receiver` is dropped before `read_contents`
        let mut receiver = receiver;

        Ok(Box::new(stream::poll_fn(move |ctx| {
            let poll_result = receiver.poll_next_unpin(ctx);

            if matches!(poll_result, Poll::Ready(None)) {
                read_contents.lock().take();
            }

            poll_result
        })))
    }

    async fn write_piece(
        &self,
        offset: PieceCacheOffset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), FarmError> {
        let piece = piece.clone();
        let piece_cache = self.clone();
        Ok(AsyncJoinOnDrop::new(
            task::spawn_blocking(move || piece_cache.write_piece(offset, piece_index, &piece)),
            false,
        )
        .await??)
    }

    async fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, FarmError> {
        let piece_cache = self.clone();
        let span = Span::current();
        Ok(AsyncJoinOnDrop::new(
            task::spawn_blocking(move || {
                let _guard = span.enter();

                piece_cache.read_piece_index(offset)
            }),
            false,
        )
        .await??)
    }

    async fn read_piece(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<(PieceIndex, Piece)>, FarmError> {
        let span = Span::current();

        // TODO: On Windows spawning blocking task that allows concurrent reads causes huge memory
        //  usage. No idea why it happens, but not spawning anything at all helps for some reason.
        //  Someone at some point should figure it out and fix, but it will probably be not me
        //  (Nazar).
        //  See https://github.com/autonomys/subspace/issues/2813 and linked forum post for details.
        //  This TODO exists in multiple files
        if cfg!(windows) {
            Ok(task::block_in_place(|| {
                let _guard = span.enter();

                self.read_piece(offset)
            })?)
        } else {
            let piece_cache = self.clone();
            Ok(AsyncJoinOnDrop::new(
                task::spawn_blocking(move || {
                    let _guard = span.enter();

                    piece_cache.read_piece(offset)
                }),
                false,
            )
            .await??)
        }
    }

    async fn read_pieces(
        &self,
        offsets: Box<dyn Iterator<Item = PieceCacheOffset> + Send>,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<(PieceCacheOffset, Option<(PieceIndex, Piece)>), FarmError>>
                + Send
                + Unpin
                + '_,
        >,
        FarmError,
    > {
        let iter = offsets.map(move |offset| async move {
            Ok((offset, farm::PieceCache::read_piece(self, offset).await?))
        });
        Ok(Box::new(
            // Constrain concurrency to avoid excessive memory usage, while still getting
            // performance of concurrent reads
            stream::iter(iter).buffer_unordered(PIECES_READING_CONCURRENCY),
        ))
    }
}

impl DiskPieceCache {
    pub(crate) const FILE_NAME: &'static str = "piece_cache.bin";

    /// Open cache, capacity is measured in elements of [`DiskPieceCache::element_size()`] size
    pub fn open(
        directory: &Path,
        capacity: NonZeroU32,
        id: Option<PieceCacheId>,
        registry: Option<&mut Registry>,
    ) -> Result<Self, DiskPieceCacheError> {
        let capacity = capacity.get();
        let files = FilePool::open(&directory.join(Self::FILE_NAME))?;

        let expected_size = u64::from(Self::element_size()) * u64::from(capacity);
        // Align plot file size for disk sector size
        let expected_size =
            expected_size.div_ceil(DISK_SECTOR_SIZE as u64) * DISK_SECTOR_SIZE as u64;
        {
            let file = files.write();
            if file.size()? != expected_size {
                // Allocating the whole file (`set_len` below can create a sparse file, which will cause
                // writes to fail later)
                file.preallocate(expected_size)
                    .map_err(DiskPieceCacheError::CantPreallocateCacheFile)?;
                // Truncating file (if necessary)
                file.set_len(expected_size)?;
            }
        }

        // ID for cache is ephemeral unless provided explicitly
        let id = id.unwrap_or_else(PieceCacheId::new);
        let metrics = registry.map(|registry| DiskPieceCacheMetrics::new(registry, &id, capacity));

        Ok(Self {
            inner: Arc::new(Inner {
                id,
                files,
                max_num_elements: capacity,
                metrics,
            }),
        })
    }

    /// Size of a single piece cache element
    pub const fn element_size() -> u32 {
        (PieceIndex::SIZE + Piece::SIZE + Blake3Hash::SIZE) as u32
    }

    /// Contents of this piece cache
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn contents(
        &self,
    ) -> impl ExactSizeIterator<Item = (PieceCacheOffset, Option<PieceIndex>)> + '_ {
        let mut element = vec![0; Self::element_size() as usize];
        let count_total = self
            .inner
            .metrics
            .as_ref()
            .map(|metrics| {
                metrics.contents.inc();
                metrics.capacity_used.get() == 0
            })
            .unwrap_or_default();
        let mut current_skip = 0;

        // TODO: Parallelize or read in larger batches
        (0..self.inner.max_num_elements).map(move |offset| {
            if current_skip > CONTENTS_READ_SKIP_LIMIT {
                return (PieceCacheOffset(offset), None);
            }

            match self.read_piece_internal(offset, &mut element) {
                Ok(maybe_piece_index) => {
                    if maybe_piece_index.is_none() {
                        current_skip += 1;
                    } else {
                        if count_total && let Some(metrics) = &self.inner.metrics {
                            metrics.capacity_used.inc();
                        }
                        current_skip = 0;
                    }

                    (PieceCacheOffset(offset), maybe_piece_index)
                }
                Err(error) => {
                    warn!(%error, %offset, "Failed to read cache element");

                    current_skip += 1;

                    (PieceCacheOffset(offset), None)
                }
            }
        })
    }

    /// Store piece in cache at specified offset, replacing existing piece if there is any
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn write_piece(
        &self,
        offset: PieceCacheOffset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), DiskPieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
        }

        if let Some(metrics) = &self.inner.metrics {
            metrics.write_piece.inc();
            let capacity_used = i64::from(offset + 1);
            if metrics.capacity_used.get() != capacity_used {
                metrics.capacity_used.set(capacity_used);
            }
        }
        let element_offset = u64::from(offset) * u64::from(Self::element_size());

        let piece_index_bytes = piece_index.to_bytes();
        // File writes are read/write/modify internally, so combine all data here for more efficient
        // write
        let mut bytes = Vec::with_capacity(PieceIndex::SIZE + piece.len() + Blake3Hash::SIZE);
        bytes.extend_from_slice(&piece_index_bytes);
        bytes.extend_from_slice(piece.as_ref());
        bytes.extend_from_slice(blake3_hash_list(&[&piece_index_bytes, piece.as_ref()]).as_ref());
        self.inner
            .files
            .write()
            .write_all_at(&bytes, element_offset)?;

        Ok(())
    }

    /// Read piece index from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
        }

        if let Some(metrics) = &self.inner.metrics {
            metrics.read_piece_index.inc();
        }
        self.read_piece_internal(offset, &mut vec![0; Self::element_size() as usize])
    }

    /// Read piece from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn read_piece(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<(PieceIndex, Piece)>, DiskPieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
        }

        if let Some(metrics) = &self.inner.metrics {
            metrics.read_piece.inc();
        }
        let mut element = BytesMut::zeroed(Self::element_size() as usize);
        if let Some(piece_index) = self.read_piece_internal(offset, &mut element)? {
            let element = element.freeze();
            let piece =
                Piece::try_from(element.slice_ref(&element[PieceIndex::SIZE..][..Piece::SIZE]))
                    .expect("Correct length; qed");
            Ok(Some((piece_index, piece)))
        } else {
            Ok(None)
        }
    }

    fn read_piece_internal(
        &self,
        offset: u32,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        self.inner
            .files
            .read()
            .read_exact_at(element, u64::from(offset) * u64::from(Self::element_size()))?;

        let (piece_index_bytes, remaining_bytes) = element.split_at(PieceIndex::SIZE);
        let (piece_bytes, expected_checksum) = remaining_bytes.split_at(Piece::SIZE);

        // Verify checksum
        let actual_checksum = blake3_hash_list(&[piece_index_bytes, piece_bytes]);
        if *actual_checksum != *expected_checksum {
            if element.iter().all(|&byte| byte == 0) {
                return Ok(None);
            }

            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted piece in cache"
            );

            return Err(DiskPieceCacheError::ChecksumMismatch);
        }

        let piece_index = PieceIndex::from_bytes(
            piece_index_bytes
                .try_into()
                .expect("Statically known to have correct size; qed"),
        );
        Ok(Some(piece_index))
    }

    pub(crate) fn wipe(directory: &Path) -> io::Result<()> {
        let piece_cache = directory.join(Self::FILE_NAME);
        if !piece_cache.exists() {
            return Ok(());
        }
        info!("Deleting piece cache file at {}", piece_cache.display());
        fs::remove_file(piece_cache)
    }
}
