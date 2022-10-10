use libp2p::kad::record::Key;
use libp2p::kad::store::{Error, RecordStore};
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::multihash::Multihash;
use libp2p::PeerId;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;
use tracing::{debug, trace};

#[derive(Clone)]
pub(crate) struct CustomRecordStore<
    RecordStorage = GetOnlyRecordStorage,
    ProviderStorage = MemoryProviderStorage,
> {
    record_storage: RecordStorage,
    provider_storage: ProviderStorage,
}

impl<RecordStorage, ProviderStorage> CustomRecordStore<RecordStorage, ProviderStorage> {
    pub(super) fn new(record_storage: RecordStorage, provider_storage: ProviderStorage) -> Self {
        Self {
            record_storage,
            provider_storage,
        }
    }
}

impl<'a> RecordStore<'a> for CustomRecordStore {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;
    type ProvidedIter = vec::IntoIter<Cow<'a, ProviderRecord>>;

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

#[derive(Clone, Default)]
pub(crate) struct MemoryProviderStorage {
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
pub(crate) struct GetOnlyRecordStorage {
    value_getter: ValueGetter,
}

impl GetOnlyRecordStorage {
    pub(super) fn new(value_getter: ValueGetter) -> Self {
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

    fn remove(&'a mut self, _key: &Key) {
        // Nothing to remove
    }

    fn records(&'a self) -> Self::RecordsIter {
        // No iteration support for now.
        Vec::new().into_iter()
    }
}

#[derive(Clone)]
pub(crate) struct MemoryRecordStorage {
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

#[derive(Clone)]
pub struct NoRecordStorage;

impl<'a> RecordStorage<'a> for MemoryRecordStorage {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;

    fn get(&'a self, _: &Key) -> Option<Cow<'_, Record>> {
        None
    }

    fn put(&'a mut self, _: Record) -> store::Result<()> {
        debug!("Detected an attempt to add a new record: {:?}", record);

        Ok(())
    }

    fn remove(&'a mut self, key: &Key) {
        trace!(?key, "Record removed.");

        debug!(?key, "Detected an attempt to remove a record.");
    }

    fn records(&'a self) -> Self::RecordsIter {
        self.records
            .values()
            .map(|rec| Cow::Owned(rec.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
