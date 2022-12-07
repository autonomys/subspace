use super::record_binary_heap::RecordBinaryHeap;
use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::PeerId;
use parity_db::{ColumnOptions, Db, Options};
use parity_scale_codec::{Decode, Encode};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::iter::IntoIterator;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::vec;
use tracing::{debug, error, info, trace};

const PARITY_DB_COLUMN_NAME: u8 = 0;

#[derive(Clone)]
pub struct CustomRecordStore<
    RecordStorage = NoRecordStorage,
    ProviderStorage = MemoryProviderStorage,
> {
    record_storage: RecordStorage,
    provider_storage: ProviderStorage,
}

impl<RecordStorage, ProviderStorage> CustomRecordStore<RecordStorage, ProviderStorage> {
    pub fn new(record_storage: RecordStorage, provider_storage: ProviderStorage) -> Self {
        Self {
            record_storage,
            provider_storage,
        }
    }
}

impl<'a, Rs: RecordStorage<'a>, Ps: ProviderStorage<'a>> RecordStore<'a>
    for CustomRecordStore<Rs, Ps>
{
    type RecordsIter = Rs::RecordsIter;
    type ProvidedIter = Ps::ProvidedIter;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        self.record_storage.get(key)
    }

    fn put(&'a mut self, record: Record) -> store::Result<()> {
        self.record_storage.put(record)
    }

    fn remove(&'a mut self, key: &Key) {
        self.record_storage.remove(key)
    }

    fn records(&'a self) -> Self::RecordsIter {
        self.record_storage.records()
    }

    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()> {
        self.provider_storage.add_provider(record)
    }

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        self.provider_storage.providers(key)
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        self.provider_storage.provided()
    }

    fn remove_provider(&'a mut self, key: &Key, provider: &PeerId) {
        self.provider_storage.remove_provider(key, provider)
    }
}

pub trait ProviderStorage<'a> {
    type ProvidedIter: Iterator<Item = Cow<'a, ProviderRecord>>;

    /// Adds a provider record to the store.
    ///
    /// A record store only needs to store a number of provider records
    /// for a key corresponding to the replication factor and should
    /// store those records whose providers are closest to the key.
    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()>;

    /// Gets a copy of the stored provider records for the given key.
    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord>;

    /// Gets an iterator over all stored provider records for which the
    /// node owning the store is itself the provider.
    fn provided(&'a self) -> Self::ProvidedIter;

    /// Removes a provider record from the store.
    fn remove_provider(&'a mut self, k: &Key, p: &PeerId);
}

/// Memory based provider records storage.
#[derive(Clone, Default)]
pub struct MemoryProviderStorage {
    // TODO: Optimize providers collection, introduce limits and TTL.
    providers: HashMap<Key, Vec<ProviderRecord>>,
}

impl<'a> ProviderStorage<'a> for MemoryProviderStorage {
    type ProvidedIter = vec::IntoIter<Cow<'a, ProviderRecord>>;

    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        let records = self
            .providers
            .entry(record.key.clone())
            .or_insert_with(Default::default);

        records.push(record);

        Ok(())
    }

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        self.providers.get(key).unwrap_or(&Vec::default()).clone()
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        self.providers
            .iter()
            .flat_map(|(_, v)| v)
            .map(|x| Cow::Owned(x.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn remove_provider(&'a mut self, key: &Key, provider: &PeerId) {
        trace!(?key, ?provider, "Provider record removed.");

        let entry = self.providers.entry(key.clone());

        entry.and_modify(|e| e.retain(|rec| rec.provider != *provider));
    }
}
// TODO: Consider adding a generic lifetime when we upgrade the compiler to 1.65 (GAT feature)
// fn records(&'_ self) -> Self::RecordsIter<'_>;
pub trait RecordStorage<'a> {
    type RecordsIter: Iterator<Item = Cow<'a, Record>>;

    /// Gets a record from the store, given its key.
    fn get(&'a self, k: &Key) -> Option<Cow<'_, Record>>;

    /// Puts a record into the store.
    fn put(&mut self, r: Record) -> store::Result<()>;

    /// Removes the record with the given key from the store.
    fn remove(&mut self, k: &Key);

    /// Gets an iterator over all (value-) records currently stored.
    fn records(&'a self) -> Self::RecordsIter;
}

/// Memory based record storage.
#[derive(Clone, Default)]
pub struct MemoryRecordStorage {
    records: HashMap<Key, Record>,
}

impl<'a> RecordStorage<'a> for MemoryRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

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

    fn records(&'a self) -> Self::RecordsIter {
        self.records
            .values()
            .map(|rec| Cow::Owned(rec.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Defines a stub for record storage with all operations defaulted.
#[derive(Clone, Default)]
pub struct NoRecordStorage;

impl<'a> RecordStorage<'a> for NoRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

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

    fn records(&'a self) -> Self::RecordsIter {
        Vec::new().into_iter()
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
    type RecordsIter = ParityDbRecordIterator<'a>;

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
pub struct LimitedSizeRecordStorageWrapper<RC = MemoryRecordStorage> {
    // Wrapped record storage implementation.
    inner: RC,
    // Maintains a heap to limit total item number.
    heap: RecordBinaryHeap,
}

impl<RC: for<'a> RecordStorage<'a>> LimitedSizeRecordStorageWrapper<RC> {
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
    type RecordsIter = RC::RecordsIter;

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

    fn records(&'a self) -> Self::RecordsIter {
        self.inner.records()
    }
}
