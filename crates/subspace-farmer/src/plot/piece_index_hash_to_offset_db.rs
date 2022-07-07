use crate::plot::{PieceDistance, PieceOffset, PlotError};
use num_traits::{WrappingAdd, WrappingSub};
use rocksdb::{Options, WriteBatch, DB};
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{io, iter};
use subspace_core_primitives::{PieceIndexHash, PublicKey, SHA256_HASH_SIZE};

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
#[derive(Debug)]
pub(super) struct IndexHashToOffsetDB {
    inner: DB,
    public_key: PublicKey,
    max_distance_cache: BTreeSet<BidirectionalDistanceSorted<PieceDistance>>,
    piece_count: Arc<AtomicU64>,
}

impl IndexHashToOffsetDB {
    /// Max distance cache size.
    ///
    /// You can find discussion of derivation of this number here:
    /// https://github.com/subspace/subspace/pull/449
    const MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP: usize = 8000;
    const METADATA_COLUMN_FAMILY: &'static str = "metadata";
    const PIECE_COUNT_KEY: &'static str = "piece_count";

    pub(super) fn open_default(path: &Path, public_key: PublicKey) -> Result<Self, PlotError> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let inner = DB::open_cf(&options, path, &["default", Self::METADATA_COLUMN_FAMILY])
            .map_err(PlotError::IndexDbOpen)?;
        let mut me = Self {
            inner,
            public_key,
            max_distance_cache: BTreeSet::new(),
            piece_count: Arc::new(AtomicU64::new(0)),
        };
        me.update_max_distance_cache();

        let mut piece_count = 0;
        let cf = me
            .inner
            .cf_handle(Self::METADATA_COLUMN_FAMILY)
            .expect("Column name opened in constructor; qed");
        match me
            .inner
            .get_cf(&cf, Self::PIECE_COUNT_KEY)
            .map_err(Into::into)
            .map_err(PlotError::PieceCountReadError)?
        {
            Some(piece_count_bytes) => {
                piece_count = u64::from_le_bytes(
                    piece_count_bytes
                        .as_slice()
                        .try_into()
                        .map_err(Into::into)
                        .map_err(PlotError::PieceCountReadError)?,
                );
            }
            None => {
                if me.max_distance_cache.len() < Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
                    piece_count = me.max_distance_cache.len() as u64;
                } else {
                    let mut iter = me.inner.raw_iterator();
                    while iter.key().is_some() {
                        piece_count += 1;
                        iter.next();
                    }
                }
            }
        }

        me.piece_count.store(piece_count, Ordering::SeqCst);
        me.inner
            .put_cf(&cf, Self::PIECE_COUNT_KEY, piece_count.to_le_bytes())
            .map_err(Into::into)
            .map_err(PlotError::PieceCountReadError)?;

        Ok(me)
    }

    pub(super) fn piece_count(&self) -> &Arc<AtomicU64> {
        &self.piece_count
    }

    // TODO: optimize fast path using `max_distance_cache`
    pub(super) fn get_piece_range(&self) -> io::Result<Option<RangeInclusive<PieceIndexHash>>> {
        let mut iter = self.inner.raw_iterator();

        iter.seek_to_first();
        let start = match iter.key() {
            Some(key) => PieceDistance::from_big_endian(key),
            None => return Ok(None),
        };
        iter.seek_to_last();
        let end = iter
            .key()
            .map(PieceDistance::from_big_endian)
            .expect("Must have at least one key");

        Ok(Some(RangeInclusive::new(
            self.piece_distance_to_hash(start),
            self.piece_distance_to_hash(end),
        )))
    }

    pub(super) fn get(&self, index_hash: &PieceIndexHash) -> io::Result<Option<PieceOffset>> {
        self.inner
            .get(&self.piece_hash_to_distance(index_hash).to_bytes())
            .map_err(io::Error::other)
            .and_then(|opt_val| {
                opt_val
                    .map(|val| <[u8; 8]>::try_from(val).map(PieceOffset::from_le_bytes))
                    .transpose()
                    .map_err(|_| io::Error::other("Offsets in rocksdb supposed to be 8 bytes long"))
            })
    }

    /// Returns `true` if piece plot will not result in exceeding plot size and doesn't exist
    /// already
    pub(super) fn should_store(&mut self, index_hash: &PieceIndexHash) -> bool {
        self.max_distance_key()
            .map(|max_distance_key| {
                subspace_core_primitives::bidirectional_distance(
                    &max_distance_key,
                    &PieceDistance::MIDDLE,
                ) >= PieceDistance::distance(index_hash, self.public_key.as_ref())
            })
            .unwrap_or(true)
    }

    fn remove_furthest(&mut self) -> io::Result<Option<PieceOffset>> {
        let max_distance = match self.max_distance_key() {
            Some(max_distance) => max_distance,
            None => return Ok(None),
        };

        let result = self
            .inner
            .get(&max_distance.to_bytes())
            .map_err(io::Error::other)?
            .map(|buffer| *<&[u8; 8]>::try_from(&*buffer).unwrap())
            .map(PieceOffset::from_le_bytes);
        self.inner
            .delete(&max_distance.to_bytes())
            .map_err(io::Error::other)?;
        self.max_distance_cache
            .remove(&BidirectionalDistanceSorted::new(max_distance));

        Ok(result)
    }

    fn batch_put<'a, I>(&'a mut self, index_hashes: I, offset: PieceOffset) -> io::Result<()>
    where
        I: Iterator<Item = &'a PieceIndexHash>,
    {
        let mut batch = WriteBatch::default();
        for (index_hash, offset) in index_hashes.zip(offset..) {
            let key = self.piece_hash_to_distance(index_hash);
            batch.put(key.to_bytes(), offset.to_le_bytes());

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

        self.inner.write(batch).map_err(|error| {
            // Restore correct cache that was modified above
            self.update_max_distance_cache();

            io::Error::other(error)
        })?;

        Ok(())
    }

    pub(super) fn batch_insert(
        &mut self,
        index_hashes: &[PieceIndexHash],
        offset: PieceOffset,
    ) -> io::Result<()> {
        self.batch_put(index_hashes.iter(), offset)?;

        let count = index_hashes.len() as u64;

        let piece_count = self.piece_count.fetch_add(count, Ordering::SeqCst) + count;
        self.inner
            .put_cf(
                self.inner
                    .cf_handle(Self::METADATA_COLUMN_FAMILY)
                    .expect("Column name opened in constructor; qed"),
                Self::PIECE_COUNT_KEY,
                piece_count.to_le_bytes(),
            )
            .map_err(io::Error::other)?;

        Ok(())
    }

    pub(super) fn replace_furthest(
        &mut self,
        index_hash: &PieceIndexHash,
    ) -> io::Result<PieceOffset> {
        let piece_offset = self.remove_furthest()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Database is empty, no furthest piece found",
            )
        })?;

        self.batch_put(iter::once(index_hash), piece_offset)?;

        Ok(piece_offset)
    }

    pub(super) fn get_sequential(
        &self,
        from: &PieceIndexHash,
        count: usize,
    ) -> Vec<(PieceIndexHash, PieceOffset)> {
        if count == 0 {
            return vec![];
        }

        let mut iter = self.inner.raw_iterator();

        let mut piece_index_hashes_and_offsets = Vec::with_capacity(count);

        iter.seek(self.piece_hash_to_distance(from).to_bytes());

        while piece_index_hashes_and_offsets.len() < count {
            match iter.key() {
                Some(key) => {
                    let offset =
                        PieceOffset::from_le_bytes(iter.value().unwrap().try_into().expect(
                            "Value read from database must always have correct length; qed",
                        ));
                    let index_hash =
                        self.piece_distance_to_hash(PieceDistance::from_big_endian(key));

                    piece_index_hashes_and_offsets.push((index_hash, offset));

                    iter.next();
                }
                None => {
                    break;
                }
            }
        }

        piece_index_hashes_and_offsets
    }

    fn update_max_distance_cache(&mut self) {
        let mut iter = self.inner.raw_iterator();

        iter.seek_to_first();
        self.max_distance_cache.extend(
            std::iter::from_fn(|| {
                let piece_index_hash = iter.key().map(PieceDistance::from_big_endian);
                if piece_index_hash.is_some() {
                    iter.next();
                }
                piece_index_hash
            })
            .take(Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP)
            .map(BidirectionalDistanceSorted::new),
        );

        iter.seek_to_last();
        self.max_distance_cache.extend(
            std::iter::from_fn(|| {
                let piece_index_hash = iter.key().map(PieceDistance::from_big_endian);
                if piece_index_hash.is_some() {
                    iter.prev();
                }
                piece_index_hash
            })
            .take(Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP)
            .map(BidirectionalDistanceSorted::new),
        );
        while self.max_distance_cache.len() > Self::MAX_DISTANCE_CACHE_ONE_SIDE_LOOKUP {
            self.max_distance_cache.pop_first();
        }
    }

    fn max_distance_key(&mut self) -> Option<PieceDistance> {
        if self.max_distance_cache.is_empty() {
            self.update_max_distance_cache();
        }
        self.max_distance_cache
            .last()
            .map(|distance| distance.value)
    }

    fn piece_hash_to_distance(&self, index_hash: &PieceIndexHash) -> PieceDistance {
        // We permute distance such that if piece index hash is equal to the `self.public_key` then
        // it lands to the `PieceDistance::MIDDLE`
        PieceDistance::from_big_endian(&index_hash.0)
            .wrapping_sub(&PieceDistance::from_big_endian(self.public_key.as_ref()))
            .wrapping_add(&PieceDistance::MIDDLE)
    }

    fn piece_distance_to_hash(&self, distance: PieceDistance) -> PieceIndexHash {
        let mut piece_index_hash = PieceIndexHash([0; SHA256_HASH_SIZE]);
        distance
            .wrapping_sub(&PieceDistance::MIDDLE)
            .wrapping_add(&PieceDistance::from_big_endian(self.public_key.as_ref()))
            .to_big_endian(&mut piece_index_hash.0);
        piece_index_hash
    }
}
