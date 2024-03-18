#[cfg(test)]
mod tests;

#[cfg(windows)]
use crate::single_disk_farm::unbuffered_io_file_windows::UnbufferedIoFileWindows;
use crate::single_disk_farm::unbuffered_io_file_windows::DISK_SECTOR_SIZE;
use derive_more::Display;
#[cfg(not(windows))]
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use subspace_farmer_components::file_ext::FileExt;
#[cfg(not(windows))]
use subspace_farmer_components::file_ext::OpenOptionsExt;
use thiserror::Error;
use tracing::{debug, info, warn};

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
    /// Cache size has zero capacity, this is not supported
    #[error("Cache size has zero capacity, this is not supported")]
    ZeroCapacity,
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Offset wrapper for pieces in [`DiskPieceCache`]
#[derive(Debug, Display, Copy, Clone)]
#[repr(transparent)]
pub struct Offset(u32);

#[derive(Debug)]
struct Inner {
    #[cfg(not(windows))]
    file: File,
    #[cfg(windows)]
    file: UnbufferedIoFileWindows,
    num_elements: u32,
}

/// Dedicated piece cache stored on one disk, is used both to accelerate DSN queries and to plot
/// faster
#[derive(Debug, Clone)]
pub struct DiskPieceCache {
    inner: Arc<Inner>,
}

impl DiskPieceCache {
    pub(crate) const FILE_NAME: &'static str = "piece_cache.bin";

    pub(crate) fn open(directory: &Path, capacity: u32) -> Result<Self, DiskPieceCacheError> {
        if capacity == 0 {
            return Err(DiskPieceCacheError::ZeroCapacity);
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
                .map_err(DiskPieceCacheError::CantPreallocateCacheFile)?;
            // Truncating file (if necessary)
            file.set_len(expected_size)?;
        }

        Ok(Self {
            inner: Arc::new(Inner {
                file,
                num_elements: capacity,
            }),
        })
    }

    pub(crate) const fn element_size() -> u32 {
        (PieceIndex::SIZE + Piece::SIZE + mem::size_of::<Blake3Hash>()) as u32
    }

    /// Contents of this disk cache
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn contents(
        &self,
    ) -> impl ExactSizeIterator<Item = (Offset, Option<PieceIndex>)> + '_ {
        let mut element = vec![0; Self::element_size() as usize];
        let mut early_exit = false;

        // TODO: Parallelize or read in larger batches
        (0..self.inner.num_elements).map(move |offset| {
            if early_exit {
                return (Offset(offset), None);
            }

            match self.read_piece_internal(offset, &mut element) {
                Ok(maybe_piece_index) => {
                    if maybe_piece_index.is_none() {
                        // End of stored pieces, no need to read further
                        early_exit = true;
                    }

                    (Offset(offset), maybe_piece_index)
                }
                Err(error) => {
                    warn!(%error, %offset, "Failed to read cache element");
                    (Offset(offset), None)
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
        offset: Offset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), DiskPieceCacheError> {
        let Offset(offset) = offset;
        if offset >= self.inner.num_elements {
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.num_elements - 1,
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
        offset: Offset,
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        let Offset(offset) = offset;
        if offset >= self.inner.num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.num_elements - 1,
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
    pub(crate) fn read_piece(&self, offset: Offset) -> Result<Option<Piece>, DiskPieceCacheError> {
        let Offset(offset) = offset;
        if offset >= self.inner.num_elements {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.num_elements - 1,
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
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
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
