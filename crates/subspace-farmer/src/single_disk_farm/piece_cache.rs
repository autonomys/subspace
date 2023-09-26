use derive_more::Display;
use memmap2::{Mmap, MmapOptions};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use subspace_farmer_components::file_ext::FileExt;
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
    read_mmap: Mmap,
    file_size: usize,
}

/// Piece cache stored on one disk
#[derive(Debug, Clone)]
pub struct DiskPieceCache {
    inner: Arc<Inner>,
}

impl DiskPieceCache {
    pub(super) const FILE_NAME: &'static str = "piece_cache.bin";

    pub(super) fn open(directory: &Path, capacity: usize) -> Result<Self, DiskPieceCacheError> {
        if capacity == 0 {
            return Err(DiskPieceCacheError::ZeroCapacity);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(Self::FILE_NAME))?;

        let expected_size = Self::element_size() * capacity;
        // Allocating the whole file (`set_len` below can create a sparse file, which will cause
        // writes to fail later)
        file.preallocate(expected_size as u64)
            .map_err(DiskPieceCacheError::CantPreallocateCacheFile)?;
        // Truncating file (if necessary)
        file.set_len(expected_size as u64)?;

        let read_mmap = unsafe { MmapOptions::new().len(expected_size).map(&file)? };
        #[cfg(unix)]
        {
            read_mmap.advise(memmap2::Advice::Random)?;
        }

        Ok(Self {
            inner: Arc::new(Inner {
                file,
                read_mmap,
                file_size: expected_size,
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
        self.inner
            .read_mmap
            .array_chunks::<{ Self::element_size() }>()
            .enumerate()
            .map(|(offset, chunk)| {
                let (piece_index_bytes, piece_bytes) = chunk.split_at(PieceIndex::SIZE);
                let piece_index = PieceIndex::from_bytes(
                    piece_index_bytes
                        .try_into()
                        .expect("Statically known to have correct size; qed"),
                );
                // Piece index zero might mean we have piece index zero or just an empty space
                let piece_index = if piece_index != PieceIndex::ZERO
                    || piece_bytes.iter().any(|&byte| byte != 0)
                {
                    Some(piece_index)
                } else {
                    None
                };

                (Offset(offset), piece_index)
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
        if offset >= self.inner.file_size / Self::element_size() {
            return Err(DiskPieceCacheError::OffsetOutsideOfRange {
                provided: offset,
                max: self.inner.file_size / Self::element_size() - 1,
            });
        }

        let mut write_mmap = unsafe {
            MmapOptions::new()
                .offset((offset * Self::element_size()) as u64)
                .len(Self::element_size())
                .map_mut(&self.inner.file)?
        };

        let (piece_index_bytes, remaining_bytes) = write_mmap.split_at_mut(PieceIndex::SIZE);
        piece_index_bytes.copy_from_slice(&piece_index.to_bytes());
        let (piece_bytes, checksum) = remaining_bytes.split_at_mut(Piece::SIZE);
        piece_bytes.copy_from_slice(piece.as_ref());
        checksum.copy_from_slice(&blake3_hash_list(&[piece_index_bytes, piece.as_ref()]));

        write_mmap.flush()?;

        Ok(())
    }

    /// Read piece index from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn read_piece_index(&self, offset: Offset) -> Option<PieceIndex> {
        let Offset(offset) = offset;
        if offset >= self.inner.file_size / Self::element_size() {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return None;
        }

        Some(PieceIndex::from_bytes(
            self.inner.read_mmap[Self::element_size() * offset..][..PieceIndex::SIZE]
                .try_into()
                .expect("Statically guaranteed to be correct size; qed"),
        ))
    }

    /// Read piece from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    pub(crate) fn read_piece(&self, offset: Offset) -> Result<Option<Piece>, DiskPieceCacheError> {
        let Offset(offset) = offset;
        if offset >= self.inner.file_size / Self::element_size() {
            warn!(%offset, "Trying to read piece out of range, this must be an implementation bug");
            return Ok(None);
        }

        let piece_element_memory =
            &self.inner.read_mmap[offset * Self::element_size()..][..Self::element_size()];
        let (piece_index_bytes, remaining_bytes) = piece_element_memory.split_at(PieceIndex::SIZE);
        let (piece_bytes, expected_checksum) = remaining_bytes.split_at(Piece::SIZE);
        let mut piece = Piece::default();
        piece.copy_from_slice(piece_bytes);

        // Verify checksum
        let actual_checksum = blake3_hash_list(&[piece_index_bytes, piece.as_ref()]);
        if actual_checksum != expected_checksum {
            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted piece in cache"
            );

            return Err(DiskPieceCacheError::ChecksumMismatch);
        }

        Ok(Some(piece))
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
