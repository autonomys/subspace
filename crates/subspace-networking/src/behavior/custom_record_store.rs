use libp2p::kad::record::Key;
use libp2p::kad::store::{Error, RecordStore};
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::multihash::Multihash;
use libp2p::PeerId;
use parity_db::{ColumnOptions, Db, Options};
use serde::{Deserialize, Serialize};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::iter::IntoIterator;
use std::path::Path;
use std::sync::Arc;
use std::vec;
use tracing::{debug, error, trace};

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

pub trait RecordStorage<'a> {
    type RecordsIter: Iterator<Item = Cow<'a, Record>>;

    /// Gets a record from the store, given its key.
    fn get(&'a self, k: &Key) -> Option<Cow<'_, Record>>;

    /// Puts a record into the store.
    fn put(&'a mut self, r: Record) -> store::Result<()>;

    /// Removes the record with the given key from the store.
    fn remove(&'a mut self, k: &Key);

    /// Gets an iterator over all (value-) records currently stored.
    fn records(&'a self) -> Self::RecordsIter;
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

impl<'a> RecordStorage<'a> for GetOnlyRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
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

    fn put(&'a mut self, _record: Record) -> store::Result<()> {
        // Don't allow to store values.
        Err(Error::MaxRecords)
    }

    fn remove(&'a mut self, _: &Key) {
        // Nothing to remove
    }

    fn records(&'a self) -> Self::RecordsIter {
        // No iteration support for now.
        Vec::new().into_iter()
    }
}

/// Memory based record storage.
#[derive(Clone)]
pub struct MemoryRecordStorage {
    // TODO: Optimize collection, introduce limits and TTL.
    records: HashMap<Key, Record>,
}

impl<'a> RecordStorage<'a> for MemoryRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        self.records.get(key).map(|rec| Cow::Owned(rec.clone()))
    }

    fn put(&'a mut self, record: Record) -> store::Result<()> {
        trace!("New record added: {:?}", record);

        self.records.insert(record.key.clone(), record);

        Ok(())
    }

    fn remove(&'a mut self, key: &Key) {
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
#[derive(Clone)]
pub struct NoRecordStorage;

impl<'a> RecordStorage<'a> for NoRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

    fn get(&'a self, _: &Key) -> Option<Cow<'_, Record>> {
        None
    }

    fn put(&'a mut self, record: Record) -> store::Result<()> {
        debug!("Detected an attempt to add a new record: {:?}", record);

        Ok(())
    }

    fn remove(&'a mut self, key: &Key) {
        debug!(?key, "Detected an attempt to remove a record.");
    }

    fn records(&'a self) -> Self::RecordsIter {
        Vec::new().into_iter()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParityDbRecord {
    /// Key of the record.
    pub key: Key,
    /// Value of the record.
    pub value: Vec<u8>,
    /// The (original) publisher of the record.
    pub publisher: Option<PeerId>,
    // TODO: add expiration field and convert Instant to serializable time-type
    // /// The expiration time as measured by a local, monotonic clock.
    // pub expires: Option<Instant>,
}

impl From<Record> for ParityDbRecord {
    fn from(rec: Record) -> Self {
        Self {
            key: rec.key,
            value: rec.value,
            publisher: rec.publisher,
        }
    }
}

impl From<ParityDbRecord> for Record {
    fn from(rec: ParityDbRecord) -> Self {
        Self {
            key: rec.key,
            value: rec.value,
            publisher: rec.publisher,
            expires: None,
        }
    }
}

/// Defines record storage with DB persistence
#[derive(Clone)]
pub struct ParityDbRecordStorage {
    // Parity DB instance
    db: Arc<Db>,
    // Column ID to persist parameters
    column_id: u8,
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
        let column_id = 0u8;

        Ok(Self {
            db: Arc::new(db),
            column_id,
        })
    }

    fn save_data(&mut self, key: &Key, data: Option<Vec<u8>>) -> bool {
        let key: &[u8] = key.borrow();

        let tx = vec![(self.column_id, key, data)];

        let result = self.db.commit(tx);
        if let Err(ref err) = result {
            debug!(?key, ?err, "DB saving error.");
        }

        result.is_ok()
    }

    fn convert_to_record(data: Vec<u8>) -> Result<Record, serde_json::Error> {
        serde_json::from_slice::<ParityDbRecord>(&data).map(Into::into)
    }
}

impl<'a> RecordStorage<'a> for ParityDbRecordStorage {
    type RecordsIter = ParityDbRecordIterator<'a>;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let result = self.db.get(self.column_id, key.borrow());

        match result {
            Ok(data) => {
                if let Some(data) = data {
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
                } else {
                    trace!(?key, "No Parity DB record for given key");

                    None
                }
            }
            Err(err) => {
                debug!(?key, ?err, "Parity DB record storage error");

                None
            }
        }
    }

    fn put(&'a mut self, record: Record) -> store::Result<()> {
        debug!("Saving a new record to DB: {:?}", record);

        let db_rec: ParityDbRecord = record.clone().into();
        let data = serde_json::to_vec(&db_rec).expect("We don't expect an error here.");

        self.save_data(&record.key, Some(data));

        Ok(())
    }

    fn remove(&'a mut self, key: &Key) {
        self.save_data(key, None);
    }

    fn records(&'a self) -> Self::RecordsIter {
        let rec_iter_result: Result<ParityDbRecordIterator, parity_db::Error> = try {
            let btree_iter = self.db.iter(self.column_id)?;
            ParityDbRecordIterator::new(btree_iter)?
        };

        match rec_iter_result {
            Ok(rec_iter) => rec_iter,
            Err(err) => {
                error!(?err, "Can't create Parity DB record storage iterator.");

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
