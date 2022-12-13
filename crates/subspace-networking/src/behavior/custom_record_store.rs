use super::record_binary_heap::RecordBinaryHeap;
use crate::utils::multihash::MultihashCode;
use libp2p::kad::record::Key;
use libp2p::kad::store::{Error, RecordStore};
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::multihash::Multihash;
use libp2p::PeerId;
use parity_db::{ColumnOptions, Db, Options};
use parity_scale_codec::{Decode, Encode};
use std::borrow::{Borrow, Cow};
use std::collections::{BTreeSet, HashMap};
use std::iter::{Empty, IntoIterator};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::{iter, vec};
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

impl<'a, RS, PS> RecordStore<'a> for CustomRecordStore<RS, PS>
where
    RS: RecordStorage + 'a,
    PS: ProviderStorage + 'a,
{
    type RecordsIter = Empty<Cow<'a, Record>>;
    type ProvidedIter = PS::ProvidedIter<'a>;

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
        // We don't use Kademlia's periodic replication
        iter::empty()
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

pub trait ProviderStorage {
    type ProvidedIter<'a>: Iterator<Item = Cow<'a, ProviderRecord>>
    where
        Self: 'a;

    /// Adds a provider record to the store.
    ///
    /// A record store only needs to store a number of provider records
    /// for a key corresponding to the replication factor and should
    /// store those records whose providers are closest to the key.
    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()>;

    /// Gets a copy of the stored provider records for the given key.
    fn providers(&self, key: &Key) -> Vec<ProviderRecord>;

    /// Gets an iterator over all stored provider records for which the
    /// node owning the store is itself the provider.
    fn provided(&'_ self) -> Self::ProvidedIter<'_>;

    /// Removes a provider record from the store.
    fn remove_provider(&mut self, k: &Key, p: &PeerId);
}

/// Memory based provider records storage.
#[derive(Clone, Default)]
pub struct MemoryProviderStorage {
    // TODO: Optimize providers collection, introduce limits and TTL.
    providers: HashMap<Key, Vec<ProviderRecord>>,
}

impl ProviderStorage for MemoryProviderStorage {
    type ProvidedIter<'a> = vec::IntoIter<Cow<'a, ProviderRecord>>;

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        let records = self
            .providers
            .entry(record.key.clone())
            .or_insert_with(Default::default);

        records.push(record);

        Ok(())
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.providers.get(key).unwrap_or(&Vec::default()).clone()
    }

    fn provided(&'_ self) -> Self::ProvidedIter<'_> {
        self.providers
            .iter()
            .flat_map(|(_, v)| v)
            .map(|x| Cow::Owned(x.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn remove_provider(&mut self, key: &Key, provider: &PeerId) {
        trace!(?key, ?provider, "Provider record removed.");

        let entry = self.providers.entry(key.clone());

        entry.and_modify(|e| e.retain(|rec| rec.provider != *provider));
    }
}
// TODO: Consider adding a generic lifetime when we upgrade the compiler to 1.65 (GAT feature)
// fn records(&'_ self) -> Self::RecordsIter<'_>;
pub trait RecordStorage {
    /// Gets a record from the store, given its key.
    fn get(&'_ self, k: &Key) -> Option<Cow<'_, Record>>;

    /// Puts a record into the store.
    fn put(&mut self, r: Record) -> store::Result<()>;

    /// Removes the record with the given key from the store.
    fn remove(&mut self, k: &Key);
}

pub trait EnumerableRecordStorage: RecordStorage {
    type RecordsIter<'a>: Iterator<Item = Cow<'a, Record>>
    where
        Self: 'a;

    /// Gets an iterator over all (value-) records currently stored.
    fn records(&'_ self) -> Self::RecordsIter<'_>;
}

pub type ValueGetter = Arc<dyn (Fn(&Multihash) -> Option<Vec<u8>>) + Send + Sync + 'static>;

/// Hacky replacement for Kademlia's record store that doesn't store anything and instead proxies
/// gets to externally provided implementation.
#[derive(Clone)]
pub struct GetOnlyRecordStorage {
    value_getter: ValueGetter,
}

impl GetOnlyRecordStorage {
    pub fn new(value_getter: ValueGetter) -> Self {
        Self { value_getter }
    }
}

impl RecordStorage for GetOnlyRecordStorage {
    fn get(&self, key: &Key) -> Option<Cow<'_, Record>> {
        let multihash_key = Multihash::from_bytes(key.as_ref()).ok()?;
        (self.value_getter)(&multihash_key)
            .map(|value| Record {
                key: key.clone(),
                value,
                publisher: None,
                expires: None,
            })
            .map(Cow::Owned)
    }

    fn put(&mut self, _record: Record) -> store::Result<()> {
        // Don't allow to store values.
        Err(Error::MaxRecords)
    }

    fn remove(&mut self, _: &Key) {
        // Nothing to remove
    }
}

/// Memory based record storage.
#[derive(Clone, Default)]
pub struct MemoryRecordStorage {
    records: HashMap<Key, Record>,
}

impl RecordStorage for MemoryRecordStorage {
    fn get(&self, key: &Key) -> Option<Cow<'_, Record>> {
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

impl EnumerableRecordStorage for MemoryRecordStorage {
    type RecordsIter<'a> = vec::IntoIter<Cow<'a, Record>>;

    fn records(&'_ self) -> Self::RecordsIter<'_> {
        self.records
            .values()
            .map(|rec| Cow::Owned(rec.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

// Workaround for Multihash::Sector until we fix https://github.com/libp2p/rust-libp2p/issues/3048
// It returns `new_record` in case of other multihash or non-Set values
fn merge_records_in_case_of_sector_multihash(
    new_record: Record,
    old_record: Option<Record>,
) -> Record {
    let updated_rec = old_record.and_then(|old_record| {
        let key_multihash = old_record.key.to_vec();

        let multihash = Multihash::from_bytes(key_multihash.as_slice())
            .expect("Key should represent a valid multihash");

        if multihash.code() == u64::from(MultihashCode::Sector) {
            let set1 =
                if let Ok(set) = BTreeSet::<Vec<u8>>::decode(&mut old_record.value.as_slice()) {
                    set
                } else {
                    // Value is not a Set
                    return Some(new_record.clone());
                };

            let set2 = if let Ok(set) =
                BTreeSet::<Vec<u8>>::decode(&mut new_record.value.clone().as_slice())
            {
                set
            } else {
                // Value is not a Set
                return Some(new_record.clone());
            };

            let merged_set = set1.union(&set2).collect::<BTreeSet<_>>();

            Some(Record {
                value: merged_set.encode(),
                ..new_record.clone()
            })
        } else {
            None
        }
    });

    updated_rec.unwrap_or(new_record)
}

/// Defines a stub for record storage with all operations defaulted.
#[derive(Clone, Default)]
pub struct NoRecordStorage;

impl RecordStorage for NoRecordStorage {
    fn get(&'_ self, _: &Key) -> Option<Cow<'_, Record>> {
        None
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        debug!(key = ?record.key, "Detected an attempt to add a new record.", );

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        debug!(?key, "Detected an attempt to remove a record.");
    }
}

impl EnumerableRecordStorage for NoRecordStorage {
    type RecordsIter<'a> = Empty<Cow<'a, Record>>;

    fn records(&'_ self) -> Self::RecordsIter<'_> {
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

impl RecordStorage for ParityDbRecordStorage {
    fn get(&'_ self, key: &Key) -> Option<Cow<'_, Record>> {
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
        debug!("Saving a new record to DB, key: {:?}", record.key);

        // Workaround for Multihash::Sector until we fix https://github.com/libp2p/rust-libp2p/issues/3048
        // It returns `new_record` in case of other multihash or non-Set values
        let old_record = self.get(&record.key).map(|item| item.into_owned());
        let actual_record = merge_records_in_case_of_sector_multihash(record.clone(), old_record);

        let db_rec = ParityDbRecord::from(actual_record);

        self.save_data(&record.key, Some(db_rec.encode()));

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        self.save_data(key, None);
    }
}

impl EnumerableRecordStorage for ParityDbRecordStorage {
    type RecordsIter<'a> = ParityDbRecordIterator<'a>;

    fn records(&'_ self) -> Self::RecordsIter<'_> {
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

impl<RC: EnumerableRecordStorage> LimitedSizeRecordStorageWrapper<RC> {
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

impl<RC: RecordStorage> RecordStorage for LimitedSizeRecordStorageWrapper<RC> {
    fn get(&'_ self, key: &Key) -> Option<Cow<'_, Record>> {
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

impl<RC: EnumerableRecordStorage> EnumerableRecordStorage for LimitedSizeRecordStorageWrapper<RC> {
    type RecordsIter<'a> = RC::RecordsIter<'a>
    where RC: 'a;

    fn records(&'_ self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }
}
