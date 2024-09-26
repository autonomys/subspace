//! Plot cache for single disk farm

#[cfg(test)]
mod tests;

use crate::farm::{FarmError, MaybePieceStoredResult, PlotCache};
use crate::single_disk_farm::direct_io_file::DirectIoFile;
use crate::utils::AsyncJoinOnDrop;
use async_lock::RwLock as AsyncRwLock;
use async_trait::async_trait;
use bytes::BytesMut;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::{io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex, SectorIndex};
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::utils::multihash::ToMultihash;
use thiserror::Error;
use tokio::task;
use tracing::{debug, info, warn};

/// Disk plot cache open error
#[derive(Debug, Error)]
pub enum DiskPlotCacheError {
    /// I/O error occurred
    #[error("Plot cache I/O error: {0}")]
    Io(#[from] io::Error),
    /// Failed to spawn task for blocking thread
    #[error("Failed to spawn task for blocking thread: {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

#[derive(Debug)]
struct CachedPieces {
    /// Map of piece index into offset
    map: HashMap<RecordKey, u32>,
    next_offset: Option<u32>,
}

/// Additional piece cache that exploit part of the plot that does not contain sectors yet
#[derive(Debug, Clone)]
pub struct DiskPlotCache {
    file: Weak<DirectIoFile>,
    sectors_metadata: Weak<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    cached_pieces: Arc<RwLock<CachedPieces>>,
    target_sector_count: SectorIndex,
    sector_size: u64,
}

#[async_trait]
impl PlotCache for DiskPlotCache {
    async fn is_piece_maybe_stored(
        &self,
        key: &RecordKey,
    ) -> Result<MaybePieceStoredResult, FarmError> {
        Ok(self.is_piece_maybe_stored(key))
    }

    async fn try_store_piece(
        &self,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<bool, FarmError> {
        Ok(self.try_store_piece(piece_index, piece).await?)
    }

    async fn read_piece(&self, key: &RecordKey) -> Result<Option<Piece>, FarmError> {
        Ok(self.read_piece(key).await)
    }
}

impl DiskPlotCache {
    pub(crate) fn new(
        file: &Arc<DirectIoFile>,
        sectors_metadata: &Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
        target_sector_count: SectorIndex,
        sector_size: u64,
    ) -> Self {
        info!("Checking plot cache contents, this can take a while");
        let cached_pieces = {
            let sectors_metadata = sectors_metadata.read_blocking();
            let mut element = vec![0; Self::element_size() as usize];
            // Clippy complains about `RecordKey`, but it is not changing here, so it is fine
            #[allow(clippy::mutable_key_type)]
            let mut map = HashMap::new();
            let mut next_offset = None;

            let file_size = sector_size * u64::from(target_sector_count);
            let plotted_size = sector_size * sectors_metadata.len() as u64;

            // Step over all free potential offsets for pieces that could have been cached
            let from_offset = (plotted_size / Self::element_size() as u64) as u32;
            let to_offset = (file_size / Self::element_size() as u64) as u32;
            // TODO: Parallelize or read in larger batches
            for offset in (from_offset..to_offset).rev() {
                match Self::read_piece_internal(file, offset, &mut element) {
                    Ok(maybe_piece_index) => match maybe_piece_index {
                        Some(piece_index) => {
                            map.insert(RecordKey::from(piece_index.to_multihash()), offset);
                        }
                        None => {
                            next_offset.replace(offset);
                            break;
                        }
                    },
                    Err(DiskPlotCacheError::ChecksumMismatch) => {
                        next_offset.replace(offset);
                        break;
                    }
                    Err(error) => {
                        warn!(%error, %offset, "Failed to read plot cache element");
                        break;
                    }
                }
            }

            CachedPieces { map, next_offset }
        };

        info!("Finished checking plot cache contents");

        Self {
            file: Arc::downgrade(file),
            sectors_metadata: Arc::downgrade(sectors_metadata),
            cached_pieces: Arc::new(RwLock::new(cached_pieces)),
            target_sector_count,
            sector_size,
        }
    }

    /// Size of a single plot cache element
    pub(crate) const fn element_size() -> u32 {
        (PieceIndex::SIZE + Piece::SIZE + Blake3Hash::SIZE) as u32
    }

    /// Check if piece is potentially stored in this cache (not guaranteed to be because it might be
    /// overridden with sector any time)
    pub(crate) fn is_piece_maybe_stored(&self, key: &RecordKey) -> MaybePieceStoredResult {
        let offset = {
            let cached_pieces = self.cached_pieces.read();

            let Some(offset) = cached_pieces.map.get(key).copied() else {
                return if cached_pieces.next_offset.is_some() {
                    MaybePieceStoredResult::Vacant
                } else {
                    MaybePieceStoredResult::No
                };
            };

            offset
        };

        let Some(sectors_metadata) = self.sectors_metadata.upgrade() else {
            return MaybePieceStoredResult::No;
        };

        let element_offset = u64::from(offset) * u64::from(Self::element_size());
        // Blocking read is fine because writes in farmer are very rare and very brief
        let plotted_bytes = self.sector_size * sectors_metadata.read_blocking().len() as u64;

        // Make sure offset is after anything that is already plotted
        if element_offset < plotted_bytes {
            // Remove entry since it was overridden with a sector already
            self.cached_pieces.write().map.remove(key);
            MaybePieceStoredResult::No
        } else {
            MaybePieceStoredResult::Yes
        }
    }

    /// Store piece in cache if there is free space, otherwise `Ok(false)` is returned
    pub(crate) async fn try_store_piece(
        &self,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<bool, DiskPlotCacheError> {
        let offset = {
            let mut cached_pieces = self.cached_pieces.write();
            let Some(next_offset) = cached_pieces.next_offset else {
                return Ok(false);
            };

            let offset = next_offset;
            cached_pieces.next_offset = offset.checked_sub(1);
            offset
        };

        let Some(sectors_metadata) = self.sectors_metadata.upgrade() else {
            return Ok(false);
        };

        let element_offset = u64::from(offset) * u64::from(Self::element_size());
        let sectors_metadata = sectors_metadata.read().await;
        let plotted_sectors_count = sectors_metadata.len() as SectorIndex;
        let plotted_bytes = self.sector_size * u64::from(plotted_sectors_count);

        // Make sure offset is after anything that is already plotted
        if element_offset < plotted_bytes {
            // Just to be safe, avoid any overlap of write locks
            drop(sectors_metadata);
            let mut cached_pieces = self.cached_pieces.write();
            // No space to store more pieces anymore
            cached_pieces.next_offset.take();
            if plotted_sectors_count == self.target_sector_count {
                // Free allocated memory once fully plotted
                mem::take(&mut cached_pieces.map);
            }
            return Ok(false);
        }

        let Some(file) = self.file.upgrade() else {
            return Ok(false);
        };

        let piece_index_bytes = piece_index.to_bytes();
        let write_fut = tokio::task::spawn_blocking({
            let piece = piece.clone();

            move || {
                file.write_all_at(&piece_index_bytes, element_offset)?;
                file.write_all_at(piece.as_ref(), element_offset + PieceIndex::SIZE as u64)?;
                file.write_all_at(
                    blake3_hash_list(&[&piece_index_bytes, piece.as_ref()]).as_ref(),
                    element_offset + PieceIndex::SIZE as u64 + Piece::SIZE as u64,
                )
            }
        });

        AsyncJoinOnDrop::new(write_fut, false).await??;

        // Just to be safe, avoid any overlap of write locks
        drop(sectors_metadata);
        // Store newly written piece in the map
        self.cached_pieces
            .write()
            .map
            .insert(RecordKey::from(piece_index.to_multihash()), offset);

        Ok(true)
    }

    /// Read piece from cache.
    ///
    /// Returns `None` if not cached.
    pub(crate) async fn read_piece(&self, key: &RecordKey) -> Option<Piece> {
        let offset = self.cached_pieces.read().map.get(key).copied()?;

        let file = self.file.upgrade()?;

        let read_fn = move || {
            let mut element = BytesMut::zeroed(Self::element_size() as usize);
            if let Ok(Some(_piece_index)) = Self::read_piece_internal(&file, offset, &mut element) {
                let element = element.freeze();
                let piece =
                    Piece::try_from(element.slice_ref(&element[PieceIndex::SIZE..][..Piece::SIZE]))
                        .expect("Correct length; qed");
                Some(piece)
            } else {
                None
            }
        };
        // TODO: On Windows spawning blocking task that allows concurrent reads causes huge memory
        //  usage. No idea why it happens, but not spawning anything at all helps for some reason.
        //  Someone at some point should figure it out and fix, but it will probably be not me
        //  (Nazar).
        //  See https://github.com/autonomys/subspace/issues/2813 and linked forum post for details.
        //  This TODO exists in multiple files
        let maybe_piece = if cfg!(windows) {
            task::block_in_place(read_fn)
        } else {
            let read_fut = task::spawn_blocking(read_fn);

            AsyncJoinOnDrop::new(read_fut, false)
                .await
                .unwrap_or_default()
        };

        if maybe_piece.is_none()
            && let Some(sectors_metadata) = self.sectors_metadata.upgrade()
        {
            let plotted_sectors_count = sectors_metadata.read().await.len() as SectorIndex;

            let mut cached_pieces = self.cached_pieces.write();
            if plotted_sectors_count == self.target_sector_count {
                // Free allocated memory once fully plotted
                mem::take(&mut cached_pieces.map);
            } else {
                // Remove entry just in case it was overridden with a sector already
                cached_pieces.map.remove(key);
            }
        }

        maybe_piece
    }

    fn read_piece_internal(
        file: &DirectIoFile,
        offset: u32,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, DiskPlotCacheError> {
        file.read_exact_at(element, u64::from(offset) * u64::from(Self::element_size()))?;

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
                "Hash doesn't match, corrupted or overridden piece in cache"
            );

            return Err(DiskPlotCacheError::ChecksumMismatch);
        }

        let piece_index = PieceIndex::from_bytes(
            piece_index_bytes
                .try_into()
                .expect("Statically known to have correct size; qed"),
        );
        Ok(Some(piece_index))
    }
}
