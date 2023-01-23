//use crate::behavior::record_binary_heap::RecordBinaryHeap;
use crate::commands::farm::dsn::PieceStorage;
use parity_db::{ColumnOptions, Db, Options};
use std::error::Error;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::{fmt, vec};
use subspace_core_primitives::Piece;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::PeerId;
use subspace_networking::RecordBinaryHeap;
use tracing::{debug, info, trace, warn};

/// Key value store with ParityDB backend
#[derive(Clone)]
pub struct ParityDbStore {
    // Parity DB instance
    db: Arc<Db>,
}

impl ParityDbStore {
    const COLUMN_ID: u8 = 0;

    pub fn new(path: &Path) -> Result<Self, parity_db::Error> {
        let mut options = Options::with_columns(path, 1);
        options.columns = vec![ColumnOptions {
            btree_index: true,
            ..Default::default()
        }];
        // We don't use stats
        options.stats = false;

        let db = Db::open_or_create(&options)?;

        Ok(Self { db: Arc::new(db) })
    }

    pub fn get(&self, key: &Key) -> Option<Piece> {
        let result = self.db.get(Self::COLUMN_ID, key.as_ref());

        match result {
            Ok(Some(data)) => {
                trace!(?key, "Record loaded successfully from DB");

                match data.try_into() {
                    Ok(piece) => Some(piece),
                    Err(err) => {
                        debug!(?key, ?err, "Parity DB record conversion error");

                        None
                    }
                }
            }
            Ok(None) => {
                trace!(?key, "No Parity DB record for given key");

                None
            }
            Err(err) => {
                debug!(?key, ?err, "Parity DB record storage error");

                None
            }
        }
    }

    pub fn update<'a, I>(&'a mut self, values: I) -> bool
    where
        I: IntoIterator<Item = (&'a Key, Option<Vec<u8>>)> + fmt::Debug,
    {
        trace!(?values, "Updating records in DB");

        let tx = values
            .into_iter()
            .map(|(key, value)| (Self::COLUMN_ID, key, value));

        let result = self.db.commit(tx);
        if let Err(error) = &result {
            debug!(%error, "DB saving error.");
        }

        result.is_ok()
    }

    pub fn iter<'a, Value>(
        &'a self,
    ) -> Result<impl Iterator<Item = (Key, Value)> + 'a, Box<dyn Error>>
    where
        Value: TryFrom<Vec<u8>> + 'a,
        Value::Error: fmt::Debug,
    {
        let btree_iter = self.db.iter(Self::COLUMN_ID)?;

        Ok(ParityDbStoreIterator::new(btree_iter)?)
    }
}

/// Parity DB BTree iterator wrapper.
struct ParityDbStoreIterator<'a, Value> {
    iter: parity_db::BTreeIterator<'a>,
    _value: PhantomData<Value>,
}

impl<'a, Value> ParityDbStoreIterator<'a, Value> {
    /// Fallible iterator constructor. It requires inner DB BTreeIterator as a parameter.
    fn new(mut iter: parity_db::BTreeIterator<'a>) -> parity_db::Result<Self> {
        iter.seek_to_first()?;

        Ok(Self {
            iter,
            _value: PhantomData::default(),
        })
    }

    fn next_entry(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self.iter.next() {
            Ok(value) => {
                trace!("Parity DB provider iterator succeeded");

                value
            }
            Err(err) => {
                warn!(?err, "Parity DB provider iterator error");

                None
            }
        }
    }
}

impl<'a, Value> Iterator for ParityDbStoreIterator<'a, Value>
where
    Value: TryFrom<Vec<u8>>,
    Value::Error: fmt::Debug,
{
    type Item = (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.next_entry()?;

        match Value::try_from(value) {
            Ok(piece) => match key.clone().try_into() {
                Ok(key) => Some((key, piece)),
                Err(err) => {
                    debug!(?key, ?err, "Parity DB key conversion error");

                    None
                }
            },
            Err(err) => {
                warn!(?key, ?err, "Parity DB storage piece conversion error");

                None
            }
        }
    }
}

/// Piece storage with limited size.
pub struct LimitedSizeParityDbStore {
    // Underlying unbounded store.
    store: ParityDbStore,
    // Maintains a heap to limit total number of entries.
    heap: RecordBinaryHeap,
}

impl LimitedSizeParityDbStore {
    pub fn new(store: ParityDbStore, max_items_limit: NonZeroUsize, peer_id: PeerId) -> Self {
        let mut heap = RecordBinaryHeap::new(peer_id, max_items_limit.get());

        match store.iter::<Vec<u8>>() {
            Ok(pieces_iter) => {
                for (key, _) in pieces_iter {
                    let _ = heap.insert(key);
                }

                if heap.size() > 0 {
                    info!(size = heap.size(), "Local piece cache loaded.");
                } else {
                    info!("New local piece cache initialized.");
                }
            }
            Err(err) => {
                warn!(?err, "Local pieces from Parity DB iterator failed.");
            }
        }

        Self { store, heap }
    }
}

impl PieceStorage for LimitedSizeParityDbStore {
    fn should_include_in_storage(&self, key: &Key) -> bool {
        self.heap.should_include_key(key)
    }

    fn add_piece(&mut self, key: Key, piece: Piece) {
        self.store.update([(&key, Some(piece.into()))]);

        let evicted_key = self.heap.insert(key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.store.update([(&key, None)]);
        }
    }

    fn get_piece(&self, key: &Key) -> Option<Piece> {
        self.store.get(key)
    }
}
