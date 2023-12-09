#[cfg(test)]
mod tests;

use derive_more::Display;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Disk piece cache open error
#[derive(Debug, Error)]
pub enum DiskPieceCacheError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Can't preallocate cache file, probably not enough space on disk
    #[error("Can't preallocate cache file, probably not enough space on disk: {0}")]
    CantPreallocateCacheFile(io::Error),
    /// Offset outsize of range
    #[error("Offset outsize of range: provided {provided}, max {max}")]
    OffsetOutsideOfRange {
        /// Provided offset
        provided: usize,
        /// Max offset
        max: usize,
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
pub struct Offset(usize);

#[derive(Debug)]
struct Inner {
    file: File,
    num_elements: usize,
}

/// Piece cache stored on one disk
#[derive(Debug, Clone)]
pub struct DiskPieceCache {
    inner: Arc<Inner>,
}

impl DiskPieceCache {
    pub(super) const FILE_NAME: &'static str = "piece_cache.bin";

    #[cfg(not(test))]
    pub(super) fn open(directory: &Path, capacity: usize) -> Result<Self, DiskPieceCacheError> {
        Self::open_internal(directory, capacity)
    }

    #[cfg(test)]
    pub(crate) fn open(directory: &Path, capacity: usize) -> Result<Self, DiskPieceCacheError> {
        Self::open_internal(directory, capacity)
    }

    pub(super) fn open_internal(
        directory: &Path,
        capacity: usize,
    ) -> Result<Self, DiskPieceCacheError> {
        if capacity == 0 {
            return Err(DiskPieceCacheError::ZeroCapacity);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .advise_random_access()
            .open(directory.join(Self::FILE_NAME))?;

        file.advise_random_access()?;

        let expected_size = Self::element_size() * capacity;
        // Allocating the whole file (`set_len` below can create a sparse file, which will cause
        // writes to fail later)
        file.preallocate(expected_size as u64)
            .map_err(DiskPieceCacheError::CantPreallocateCacheFile)?;
        // Truncating file (if necessary)
        file.set_len(expected_size as u64)?;

        Ok(Self {
            inner: Arc::new(Inner {
                file,
                num_elements: expected_size / Self::element_size(),
            }),
        })
    }

    pub(super) const fn element_size() -> usize {
        PieceIndex::SIZE + Piece::SIZE + mem::size_of::<Blake3Hash>()
    }

    /// Contents of this disk cache
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn contents(
        &self,
    ) -> impl ExactSizeIterator<Item = (Offset, Option<PieceIndex>)> + '_ {
        let file = &self.inner.file;
        let mut element = vec![0; Self::element_size()];

        (0..self.inner.num_elements).map(move |offset| {
            match Self::read_piece_internal(file, offset, &mut element) {
                Ok(maybe_piece_index) => (Offset(offset), maybe_piece_index),
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

        let element_offset = (offset * Self::element_size()) as u64;

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

        Self::read_piece_internal(&self.inner.file, offset, &mut vec![0; Self::element_size()])
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

        let mut element = vec![0; Self::element_size()];
        if Self::read_piece_internal(&self.inner.file, offset, &mut element)?.is_some() {
            let mut piece = Piece::default();
            piece.copy_from_slice(&element[PieceIndex::SIZE..][..Piece::SIZE]);
            Ok(Some(piece))
        } else {
            Ok(None)
        }
    }

    fn read_piece_internal(
        file: &File,
        offset: usize,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        file.read_exact_at(element, (offset * Self::element_size()) as u64)?;

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
