#[cfg(test)]
mod tests;

use crate::farm;
use crate::farm::{FarmError, PieceCacheOffset};
#[cfg(windows)]
use crate::single_disk_farm::unbuffered_io_file_windows::UnbufferedIoFileWindows;
use crate::single_disk_farm::unbuffered_io_file_windows::DISK_SECTOR_SIZE;
use crate::utils::AsyncJoinOnDrop;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{stream, SinkExt, Stream, StreamExt};
use parking_lot::Mutex;
#[cfg(not(windows))]
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use subspace_farmer_components::file_ext::FileExt;
#[cfg(not(windows))]
use subspace_farmer_components::file_ext::OpenOptionsExt;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::task;
use tracing::{debug, info, warn};

/// How many pieces should be skipped before stopping to check the rest of contents, this allows to
/// not miss most of the pieces after one or two corrupted pieces
const CONTENTS_READ_SKIP_LIMIT: usize = 3;

/// Disk piece cache open error
#[derive(Debug, Error)]
pub enum PieceCacheError {
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
    /// Cache size has zero capacity, this is not supported, cache size needs to be larger
    #[error("Cache size has zero capacity, this is not supported, cache size needs to be larger")]
    ZeroCapacity,
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

#[derive(Debug)]
struct Inner {
    #[cfg(not(windows))]
    file: File,
    #[cfg(windows)]
    file: UnbufferedIoFileWindows,
    max_num_elements: u32,
}

/// Dedicated piece cache stored on one disk, is used both to accelerate DSN queries and to plot
/// faster
#[derive(Debug, Clone)]
pub struct PieceCache {
    inner: Arc<Inner>,
}

#[async_trait]
impl farm::PieceCache for PieceCache {
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
        let (mut sender, receiver) = mpsc::channel(1);
        let read_contents = task::spawn_blocking(move || {
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
        Ok(self.write_piece(offset, piece_index, piece)?)
    }

    async fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, FarmError> {
        Ok(self.read_piece_index(offset)?)
    }

    async fn read_piece(&self, offset: PieceCacheOffset) -> Result<Option<Piece>, FarmError> {
        Ok(self.read_piece(offset)?)
    }
}

impl PieceCache {
    pub(crate) const FILE_NAME: &'static str = "piece_cache.bin";

    /// Open cache, capacity is measured in elements of [`PieceCache::element_size()`] size
    pub fn open(directory: &Path, capacity: u32) -> Result<Self, PieceCacheError> {
        if capacity == 0 {
            return Err(PieceCacheError::ZeroCapacity);
        }

        #[cfg(not(windows))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .advise_random_access()
            .open(directory.join(Self::FILE_NAME))?;

        #[cfg(not(windows))]
        file.advise_random_access()?;

        #[cfg(windows)]
        let file = UnbufferedIoFileWindows::open(&directory.join(Self::FILE_NAME))?;

        let expected_size = u64::from(Self::element_size()) * u64::from(capacity);
        // Align plot file size for disk sector size
        let expected_size =
            expected_size.div_ceil(DISK_SECTOR_SIZE as u64) * DISK_SECTOR_SIZE as u64;
        if file.size()? != expected_size {
            // Allocating the whole file (`set_len` below can create a sparse file, which will cause
            // writes to fail later)
            file.preallocate(expected_size)
                .map_err(PieceCacheError::CantPreallocateCacheFile)?;
            // Truncating file (if necessary)
            file.set_len(expected_size)?;
        }

        Ok(Self {
            inner: Arc::new(Inner {
                file,
                max_num_elements: capacity,
            }),
        })
    }

    pub const fn element_size() -> u32 {
        (PieceIndex::SIZE + Piece::SIZE + mem::size_of::<Blake3Hash>()) as u32
    }

    /// Contents of this piece cache
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn contents(
        &self,
    ) -> impl ExactSizeIterator<Item = (PieceCacheOffset, Option<PieceIndex>)> + '_ {
        let mut element = vec![0; Self::element_size() as usize];
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
    ) -> Result<(), PieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            return Err(PieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
        }

        let element_offset = u64::from(offset) * u64::from(Self::element_size());

        let piece_index_bytes = piece_index.to_bytes();
        self.inner
            .file
            .write_all_at(&piece_index_bytes, element_offset)?;
        self.inner
            .file
            .write_all_at(piece.as_ref(), element_offset + PieceIndex::SIZE as u64)?;
        self.inner.file.write_all_at(
            &blake3_hash_list(&[&piece_index_bytes, piece.as_ref()]),
            element_offset + PieceIndex::SIZE as u64 + Piece::SIZE as u64,
        )?;

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
    ) -> Result<Option<PieceIndex>, PieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(PieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
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
    ) -> Result<Option<Piece>, PieceCacheError> {
        let PieceCacheOffset(offset) = offset;
        if offset >= self.inner.max_num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(PieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.max_num_elements - 1,
            });
        }

        let mut element = vec![0; Self::element_size() as usize];
        if self.read_piece_internal(offset, &mut element)?.is_some() {
            let mut piece = Piece::default();
            piece.copy_from_slice(&element[PieceIndex::SIZE..][..Piece::SIZE]);
            Ok(Some(piece))
        } else {
            Ok(None)
        }
    }

    fn read_piece_internal(
        &self,
        offset: u32,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, PieceCacheError> {
        self.inner
            .file
            .read_exact_at(element, u64::from(offset) * u64::from(Self::element_size()))?;

        let (piece_index_bytes, remaining_bytes) = element.split_at(PieceIndex::SIZE);
        let (piece_bytes, expected_checksum) = remaining_bytes.split_at(Piece::SIZE);

        // Verify checksum
        let actual_checksum = blake3_hash_list(&[piece_index_bytes, piece_bytes]);
        if actual_checksum != expected_checksum {
            if element.iter().all(|&byte| byte == 0) {
                return Ok(None);
            }

            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted piece in cache"
            );

            return Err(PieceCacheError::ChecksumMismatch);
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
