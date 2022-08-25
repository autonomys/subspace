use crate::plot::{PieceDistance, PieceOffset, PlotError};
use anyhow::Context;
use num_traits::{WrappingAdd, WrappingSub};
use parity_db::{ColumnOptions, CompressionType, Db, Options};
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{io, iter};
use subspace_core_primitives::{PieceIndexHash, PublicKey, U256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BidirectionalDistanceSorted<T> {
    distance: T,
    value: T,
}

impl<T: PartialOrd> PartialOrd for BidirectionalDistanceSorted<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.distance.partial_cmp(&other.distance)
    }
}

impl<T: Ord> Ord for BidirectionalDistanceSorted<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance.cmp(&other.distance)
    }
}

impl BidirectionalDistanceSorted<PieceDistance> {
    fn new(value: PieceDistance) -> Self {
        let distance =
            subspace_core_primitives::bidirectional_distance(&value, &PieceDistance::MIDDLE);
        Self { value, distance }
    }
}

/// Mapping from piece index hash to piece offset.
///
/// Piece index hashes are transformed in the following manner:
/// - Assume that farmer public key is the middle (`2 ^ 255`) of the `PieceDistance` field
/// - Move every piece according to that
pub(super) struct IndexHashToOffsetDB {
    inner: Db,
    public_key_as_number: U256,
    max_distance_cache: BTreeSet<BidirectionalDistanceSorted<PieceDistance>>,
    piece_count: Arc<AtomicU64>,
}

impl IndexHashToOffsetDB {
    /// Max distance cache size.
    ///
    /// You can find discussion of derivation of this number here:
    /// https://github.com/subspace/subspace/pull/449
    const MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP: usize = 8000;
    const METADATA_COLUMN: u8 = 0;
    const DATA_COLUMN: u8 = 1;
    const PIECE_COUNT_KEY: &'static [u8] = b"piece_count";

    fn options(path: PathBuf) -> Options {
        Options {
            path,
            columns: vec![
                ColumnOptions {
                    preimage: false,
                    btree_index: false,
                    uniform: false,
                    ref_counted: false,
                    compression: CompressionType::NoCompression,
                    compression_threshold: 4096,
                },
                ColumnOptions {
                    preimage: false,
                    btree_index: true,
                    uniform: true,
                    ref_counted: false,
                    compression: CompressionType::NoCompression,
                    compression_threshold: 4096,
                },
            ],
            stats: false,
            sync_wal: true,
            sync_data: true,
            salt: None,
        }
    }

    fn migrate_rocksdb(path: &Path) -> anyhow::Result<()> {
        let rocksdb_db_path = path
            .parent()
            .expect("Path is always in some directory by construction of the plot")
            .join("rocksdb");
        std::fs::rename(path, &rocksdb_db_path).context("Failed to move rocksdb directory")?;

        let rocksdb =
            rocksdb::DB::open_default(&rocksdb_db_path).context("Failed to open rocksdb")?;

        let db = Db::open_or_create(&Self::options(path.to_owned()))
            .context("Failed to create paritydb")?;

        db.commit(iter::from_fn({
            let mut iter = rocksdb.raw_iterator();
            iter.seek_to_first();
            move || {
                let out = iter
                    .key()
                    .map(<[u8]>::to_vec)
                    .zip(iter.value().map(<[u8]>::to_vec));
                if out.is_some() {
                    iter.next();
                }
                out.map(|(key, value)| (Self::DATA_COLUMN, key, Some(value)))
            }
        }))
        .context("Failed to commit data from rocksdb to paritydb")?;

        let piece_count = iter::from_fn({
            let mut iter = db
                .iter(Self::DATA_COLUMN)
                .expect("Always valid for btree indexed iterations");
            move || iter.next().transpose()
        })
        .try_fold(0u64, |prev, next| next.map(|_| prev + 1))?;

        db.commit(iter::once((
            Self::METADATA_COLUMN,
            Self::PIECE_COUNT_KEY,
            Some(piece_count.to_le_bytes().to_vec()),
        )))
        .context("Failed to commit data to paritydb")?;

        drop(rocksdb);
        drop(db);

        std::fs::remove_dir_all(rocksdb_db_path).context("Failed to remove paritydb")?;

        Ok(())
    }

    pub(super) fn open_default(path: &Path, public_key: PublicKey) -> Result<Self, PlotError> {
        if rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), path, false).is_ok() {
            Self::migrate_rocksdb(path).map_err(PlotError::IndexDbMigration)?;
        }

        let mut me = Self {
            inner: Db::open_or_create(&Self::options(path.to_owned()))
                .map_err(PlotError::IndexDbOpen)?,
            public_key_as_number: U256::from_be_bytes(public_key.into()),
            max_distance_cache: BTreeSet::new(),
            piece_count: Arc::new(AtomicU64::new(0)),
        };

        me.update_max_distance_cache()
            .map_err(PlotError::IndexDbOpen)?;

        let piece_count = match me
            .inner
            .get(Self::METADATA_COLUMN, Self::PIECE_COUNT_KEY)
            .map_err(PlotError::IndexDbOpen)?
        {
            Some(bytes) => u64::from_le_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(Into::into)
                    .map_err(PlotError::PieceCountReadError)?,
            ),
            None => {
                me.inner
                    .commit(iter::once((
                        Self::METADATA_COLUMN,
                        Self::PIECE_COUNT_KEY,
                        Some(0u64.to_le_bytes().to_vec()),
                    )))
                    .map_err(PlotError::IndexDbOpen)?;
                0
            }
        };

        me.piece_count.store(piece_count, Ordering::SeqCst);

        Ok(me)
    }

    pub(super) fn piece_count(&self) -> &Arc<AtomicU64> {
        &self.piece_count
    }

    // TODO: optimize fast path using `max_distance_cache`
    pub(super) fn get_piece_range(
        &self,
    ) -> parity_db::Result<Option<RangeInclusive<PieceIndexHash>>> {
        let mut iter = self.inner.iter(Self::DATA_COLUMN)?;
        iter.seek_to_first()?;
        let start = match iter.next()? {
            Some((key, _)) => key
                .try_into()
                .map(PieceDistance::from_be_bytes)
                .expect("Key read from database must always have correct length; qed"),
            None => return Ok(None),
        };

        iter.seek_to_last()?;
        let end = match iter.prev()? {
            Some((key, _)) => key
                .try_into()
                .map(PieceDistance::from_be_bytes)
                .expect("Key read from database must always have correct length; qed"),
            None => return Ok(None),
        };

        Ok(Some(RangeInclusive::new(
            self.piece_distance_to_hash(start),
            self.piece_distance_to_hash(end),
        )))
    }

    pub(super) fn get(&self, index_hash: PieceIndexHash) -> parity_db::Result<Option<PieceOffset>> {
        self.inner
            .get(
                Self::DATA_COLUMN,
                &self.piece_hash_to_distance(index_hash).to_be_bytes(),
            )
            .map(|opt_val| {
                opt_val
                    .map(|val| <[u8; 8]>::try_from(val).map(PieceOffset::from_le_bytes))
                    .transpose()
                    .expect("Key read from database must always have correct length; qed")
            })
    }

    /// Returns `true` if piece plot will not result in exceeding plot size and doesn't exist
    /// already
    pub(super) fn should_store(&mut self, index_hash: PieceIndexHash) -> parity_db::Result<bool> {
        use subspace_core_primitives::bidirectional_distance as distance;

        Ok(match self.max_distance_key()? {
            Some(max_distance_key) => {
                distance(&max_distance_key, &PieceDistance::MIDDLE)
                    >= distance(&U256::from(index_hash), &self.public_key_as_number)
            }
            None => true,
        })
    }

    pub(super) fn batch_insert(
        &mut self,
        index_hashes: Vec<PieceIndexHash>,
        offset: PieceOffset,
    ) -> parity_db::Result<()> {
        for &index_hash in &index_hashes {
            let key = self.piece_hash_to_distance(index_hash);

            if let Some(first) = self.max_distance_cache.first() {
                let key = BidirectionalDistanceSorted::new(key);
                if key > *first {
                    self.max_distance_cache.insert(key);
                    if self.max_distance_cache.len() > 2 * Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP
                    {
                        self.max_distance_cache.pop_first();
                    }
                }
            }
        }

        let count = index_hashes.len() as u64;
        let piece_count = self.piece_count.fetch_add(count, Ordering::SeqCst) + count;

        self.inner.commit(
            index_hashes
                .into_iter()
                .map(|index_hash| self.piece_hash_to_distance(index_hash))
                .zip(offset..)
                .map(|(index_hash, offset)| {
                    (
                        Self::DATA_COLUMN,
                        index_hash.to_be_bytes(),
                        Some(offset.to_le_bytes().to_vec()),
                    )
                }),
        )?;
        self.inner.commit(iter::once((
            Self::METADATA_COLUMN,
            Self::PIECE_COUNT_KEY,
            Some(piece_count.to_le_bytes().to_vec()),
        )))
    }

    pub(super) fn replace_furthest(
        &mut self,
        index_hash: PieceIndexHash,
    ) -> io::Result<PieceOffset> {
        let (piece_offset, old_max_distance) = {
            let max_distance = match self.max_distance_key().map_err(|err| {
                io::Error::other(format!(
                    "Failed to get max distance key from index hash db: {err}"
                ))
            })? {
                Some(max_distance) => max_distance,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "Database is empty, no furthest piece found",
                    ));
                }
            };

            let piece_offset = self
                .inner
                .get(Self::DATA_COLUMN, &max_distance.to_be_bytes())
                .map_err(|err| {
                    io::Error::other(format!(
                        "Failed to get max distance offset from index hash db: {err}"
                    ))
                })?
                .map(|buffer| *<&[u8; 8]>::try_from(&*buffer).unwrap())
                .map(PieceOffset::from_le_bytes)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "Database is empty, no furthest piece found",
                    )
                })?;

            self.max_distance_cache
                .remove(&BidirectionalDistanceSorted::new(max_distance));

            (piece_offset, max_distance)
        };

        self.inner
            .commit(iter::once((
                Self::DATA_COLUMN,
                old_max_distance.to_be_bytes(),
                None,
            )))
            .map_err(|err| {
                io::Error::other(format!(
                    "Failed to update furthest entry in index hash db: {err}"
                ))
            })?;
        self.piece_count.fetch_sub(1, Ordering::SeqCst);
        self.batch_insert(vec![index_hash], piece_offset)
            .map_err(|err| {
                io::Error::other(format!(
                    "Failed to update furthest entry in index hash db: {err}"
                ))
            })?;

        Ok(piece_offset)
    }

    pub(super) fn get_sequential(
        &self,
        from: PieceIndexHash,
        count: usize,
    ) -> parity_db::Result<Vec<(PieceIndexHash, PieceOffset)>> {
        if count == 0 {
            return Ok(vec![]);
        }

        let mut iter = self.inner.iter(Self::DATA_COLUMN)?;

        let mut piece_index_hashes_and_offsets = Vec::with_capacity(count);

        iter.seek(&self.piece_hash_to_distance(from).to_be_bytes())?;

        while piece_index_hashes_and_offsets.len() < count {
            match iter.next()? {
                Some((key, value)) => {
                    let offset =
                        PieceOffset::from_le_bytes(value.try_into().expect(
                            "Value read from database must always have correct length; qed",
                        ));
                    let index_hash = self.piece_distance_to_hash(PieceDistance::from_be_bytes(
                        key.try_into()
                            .expect("Key read from database must always have correct length; qed"),
                    ));

                    if matches!(piece_index_hashes_and_offsets.last(), Some((last_index_hash, _)) if *last_index_hash > index_hash)
                    {
                        break;
                    }

                    piece_index_hashes_and_offsets.push((index_hash, offset));
                }
                None => {
                    break;
                }
            }
        }

        Ok(piece_index_hashes_and_offsets)
    }

    fn update_max_distance_cache(&mut self) -> parity_db::Result<()> {
        let mut iter = self.inner.iter(Self::DATA_COLUMN)?;

        iter.seek_to_first()?;
        for _ in 0..Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
            let key = if let Some((key, _)) = iter.next()? {
                key
            } else {
                break;
            };
            let piece_index_hash = PieceDistance::from_be_bytes(
                key.try_into()
                    .expect("Key read from database must always have correct length; qed"),
            );
            self.max_distance_cache
                .insert(BidirectionalDistanceSorted::new(piece_index_hash));
        }

        iter.seek_to_last()?;
        for _ in 0..Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
            let key = if let Some((key, _)) = iter.prev()? {
                key
            } else {
                break;
            };
            let piece_index_hash = PieceDistance::from_be_bytes(
                key.try_into()
                    .expect("Key read from database must always have correct length; qed"),
            );
            self.max_distance_cache
                .insert(BidirectionalDistanceSorted::new(piece_index_hash));
        }

        while self.max_distance_cache.len() > Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
            self.max_distance_cache.pop_first();
        }

        Ok(())
    }

    fn max_distance_key(&mut self) -> parity_db::Result<Option<PieceDistance>> {
        if self.max_distance_cache.is_empty() {
            self.update_max_distance_cache()?;
        }
        Ok(self
            .max_distance_cache
            .last()
            .map(|distance| distance.value))
    }

    fn piece_hash_to_distance(&self, index_hash: PieceIndexHash) -> PieceDistance {
        // We permute distance such that if piece index hash is equal to the `self.public_key` then
        // it lands to the `PieceDistance::MIDDLE`
        PieceDistance::from(index_hash)
            .wrapping_sub(&self.public_key_as_number)
            .wrapping_add(&PieceDistance::MIDDLE)
    }

    fn piece_distance_to_hash(&self, distance: PieceDistance) -> PieceIndexHash {
        distance
            .wrapping_sub(&PieceDistance::MIDDLE)
            .wrapping_add(&self.public_key_as_number)
            .into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rocksdb_migration() {
        let base_directory = tempfile::TempDir::new().unwrap();
        let dir = base_directory.as_ref().join("db");

        {
            let db = rocksdb::DB::open_default(&dir).unwrap();
            db.put(PieceDistance::MIDDLE.to_be_bytes(), 10u64.to_le_bytes())
                .unwrap();
        }

        let db = IndexHashToOffsetDB::open_default(&dir, PublicKey::from([0; 32])).unwrap();
        assert_eq!(db.get(PieceIndexHash::from([0; 32])).unwrap(), Some(10));
        assert_eq!(db.piece_count().load(Ordering::SeqCst), 1);
    }
}
