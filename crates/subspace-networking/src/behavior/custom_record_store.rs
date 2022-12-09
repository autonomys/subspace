mod providers;
mod records;

use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::PeerId;
pub use providers::{MemoryProviderStorage, ParityDbProviderStorage};
pub use records::{
    LimitedSizeRecordStorageWrapper, MemoryRecordStorage, NoRecordStorage, ParityDbRecordStorage,
};
use std::borrow::Cow;

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
