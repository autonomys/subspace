use super::RecordStorage;
use crate::behavior::record_binary_heap::RecordBinaryHeap;
use libp2p::kad::record::Key;
use libp2p::kad::{store, Record};
use libp2p::PeerId;
use parity_db::{ColumnOptions, Db, Options};
use parity_scale_codec::{Decode, Encode};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::iter::Empty;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::{iter, vec};
use tracing::{debug, error, info, trace};

const PARITY_DB_COLUMN_NAME: u8 = 0;

/// Memory based record storage.
#[derive(Clone, Default)]
pub struct MemoryRecordStorage {
    records: HashMap<Key, Record>,
}

impl<'a> RecordStorage<'a> for MemoryRecordStorage {
    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        self.records.get(key).map(|rec| Cow::Owned(rec.clone()))
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        trace!(
            "New record added: {:?}. Total records: {:?}",
            record.key,
            self.records.len() + 1
        );

        self.records.insert(record.key.clone(), record);

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        trace!(?key, "Record removed.");

        self.records.remove(key);
    }
}

pub trait EnumerableRecordStorage<'a>: RecordStorage<'a> {
    type RecordsIter: Iterator<Item = Cow<'a, Record>>;

    /// Gets an iterator over all (value-) records currently stored.
    fn records(&'a self) -> Self::RecordsIter;
}

/// Defines a stub for record storage with all operations defaulted.
#[derive(Clone, Default)]
pub struct NoRecordStorage;

impl<'a> RecordStorage<'a> for NoRecordStorage {
    fn get(&'a self, _: &Key) -> Option<Cow<'_, Record>> {
        None
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        debug!("Detected an attempt to add a new record: {:?}", record);

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        debug!(?key, "Detected an attempt to remove a record.");
    }
}

impl<'a> EnumerableRecordStorage<'a> for NoRecordStorage {
    type RecordsIter = Empty<Cow<'a, Record>>;

    fn records(&'a self) -> Self::RecordsIter {
        iter::empty()
    }
}

#[derive(Clone, Debug, Decode, Encode)]
struct ParityDbRecord {
    // Key of the record.
    key: Vec<u8>,
    // Value of the record.
    value: Vec<u8>,
    // The (original) publisher of the record.
    publisher: Option<Vec<u8>>,
    // We don't use record expiration in our current caching model.

    // TODO: consider adding expiration field and convert Instant to serializable time-type
    // // The expiration time as measured by a local, monotonic clock.
    // expires: Option<Instant>,
}

impl From<Record> for ParityDbRecord {
    fn from(rec: Record) -> Self {
        Self {
            key: rec.key.to_vec(),
            value: rec.value,
            publisher: rec.publisher.map(|peer_id| peer_id.to_bytes()),
        }
    }
}

impl From<ParityDbRecord> for Record {
    fn from(rec: ParityDbRecord) -> Self {
        Self {
            key: rec.key.into(),
            value: rec.value,
            publisher: rec
                .publisher
                // We don't expect an error here because ParityDbRecord contains a bytes
                // representation of the valid PeerId.
                .map(|peer_id| {
                    PeerId::from_bytes(&peer_id)
                        .expect("Peer ID should be valid in bytes representation.")
                }),
            expires: None,
        }
    }
}

/// Defines record storage with DB persistence
#[derive(Clone)]
pub struct ParityDbRecordStorage {
    // Parity DB instance
    db: Arc<Db>,
}

impl ParityDbRecordStorage {
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

    fn save_data(&mut self, key: &Key, data: Option<Vec<u8>>) -> bool {
        let key: &[u8] = key.borrow();

        let tx = [(PARITY_DB_COLUMN_NAME, key, data)];

        let result = self.db.commit(tx);
        if let Err(ref err) = result {
            debug!(?key, ?err, "DB saving error.");
        }

        result.is_ok()
    }

    fn convert_to_record(data: Vec<u8>) -> Result<Record, parity_scale_codec::Error> {
        ParityDbRecord::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl<'a> RecordStorage<'a> for ParityDbRecordStorage {
    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let result = self.db.get(PARITY_DB_COLUMN_NAME, key.borrow());

        match result {
            Ok(Some(data)) => {
                let db_rec_result = ParityDbRecordStorage::convert_to_record(data);

                match db_rec_result {
                    Ok(db_rec) => {
                        trace!(?key, "Record loaded successfully from DB");

                        Some(Cow::Owned(db_rec))
                    }
                    Err(err) => {
                        debug!(?key, ?err, "Parity DB record deserialization error");

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

    fn put(&mut self, record: Record) -> store::Result<()> {
        let key = record.key.clone();

        debug!("Saving a new record to DB, key: {:?}", key);

        let db_rec = ParityDbRecord::from(record);

        self.save_data(&key, Some(db_rec.encode()));

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        self.save_data(key, None);
    }
}

impl<'a> EnumerableRecordStorage<'a> for ParityDbRecordStorage {
    type RecordsIter = ParityDbRecordIterator<'a>;

    fn records(&'a self) -> Self::RecordsIter {
        let rec_iter_result: Result<ParityDbRecordIterator, parity_db::Error> = try {
            let btree_iter = self.db.iter(PARITY_DB_COLUMN_NAME)?;
            ParityDbRecordIterator::new(btree_iter)?
        };

        match rec_iter_result {
            Ok(rec_iter) => rec_iter,
            Err(err) => {
                error!(?err, "Can't create Parity DB record storage iterator.");

                // TODO: The error handling can be changed:
                // https://github.com/libp2p/rust-libp2p/issues/3035
                ParityDbRecordIterator::empty()
            }
        }
    }
}

/// Parity DB BTree iterator wrapper.
pub struct ParityDbRecordIterator<'a> {
    iter: Option<parity_db::BTreeIterator<'a>>,
}

impl<'a> ParityDbRecordIterator<'a> {
    /// Defines empty iterator, a stub when new() fails.
    pub fn empty() -> Self {
        Self { iter: None }
    }
    /// Fallible iterator constructor. It requires inner DB BTreeIterator as a parameter.
    pub fn new(mut iter: parity_db::BTreeIterator<'a>) -> parity_db::Result<Self> {
        iter.seek_to_first()?;

        Ok(Self { iter: Some(iter) })
    }

    fn next_entry(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(ref mut iter) = self.iter {
            iter.next().ok().flatten()
        } else {
            None
        }
    }
}

impl<'a> Iterator for ParityDbRecordIterator<'a> {
    type Item = Cow<'a, Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().and_then(|(key, value)| {
            let db_rec_result = ParityDbRecordStorage::convert_to_record(value);

            match db_rec_result {
                Ok(db_rec) => Some(Cow::Owned(db_rec)),
                Err(err) => {
                    debug!(?key, ?err, "Parity DB record deserialization error");

                    None
                }
            }
        })
    }
}

/// Record storage decorator. It wraps the inner record storage and monitors items number.
pub struct LimitedSizeRecordStorageWrapper<RC = NoRecordStorage> {
    // Wrapped record storage implementation.
    inner: RC,
    // Maintains a heap to limit total item number.
    heap: RecordBinaryHeap,
}

impl<RC: for<'a> RecordStorage<'a>> LimitedSizeRecordStorageWrapper<RC>
where
    RC: for<'a> EnumerableRecordStorage<'a>,
{
    pub fn new(record_store: RC, max_items_limit: NonZeroUsize, peer_id: PeerId) -> Self {
        let mut heap = RecordBinaryHeap::new(peer_id, max_items_limit.get());

        // Initial cache loading.
        for rec in record_store.records() {
            let _ = heap.insert(rec.key.clone());
        }

        if heap.size() > 0 {
            info!(size = heap.size(), "Record cache loaded.");
        } else {
            info!("New record cache initialized.");
        }

        Self {
            inner: record_store,
            heap,
        }
    }
}

impl<'a, RC: RecordStorage<'a>> RecordStorage<'a> for LimitedSizeRecordStorageWrapper<RC> {
    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        self.inner.get(key)
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        let record_key = record.key.clone();

        self.inner.put(record)?;

        let evicted_key = self.heap.insert(record_key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.inner.remove(&key);
        }

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        self.inner.remove(key);

        self.heap.remove(key);
    }
}

impl<'a, RC> EnumerableRecordStorage<'a> for LimitedSizeRecordStorageWrapper<RC>
where
    RC: EnumerableRecordStorage<'a>,
{
    type RecordsIter = RC::RecordsIter;

    fn records(&'a self) -> Self::RecordsIter {
        self.inner.records()
    }
}
