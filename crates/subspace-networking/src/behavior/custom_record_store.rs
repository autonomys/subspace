mod providers;
mod records;

use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::PeerId;
#[cfg(test)]
pub(crate) use providers::{instant_to_micros, micros_to_instant};
pub use providers::{
    LimitedSizeProviderStorageWrapper, MemoryProviderStorage, ParityDbProviderStorage,
};
pub use records::{LimitedSizeRecordStorageWrapper, NoRecordStorage, ParityDbRecordStorage};
use std::borrow::Cow;
use std::iter;
use std::iter::Empty;

pub trait RecordStorage {
    /// Gets a record from the store, given its key.
    fn get(&self, k: &Key) -> Option<Cow<'_, Record>>;

    /// Puts a record into the store.
    fn put(&mut self, r: Record) -> store::Result<()>;

    /// Removes the record with the given key from the store.
    fn remove(&mut self, k: &Key);
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
    fn provided(&self) -> Self::ProvidedIter<'_>;

    /// Removes a provider record from the store.
    fn remove_provider(&mut self, k: &Key, p: &PeerId);
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

impl<Rs: RecordStorage, Ps: ProviderStorage> RecordStore for CustomRecordStore<Rs, Ps> {
    type RecordsIter<'a> = Empty<Cow<'a, Record>> where Self: 'a;
    type ProvidedIter<'a> = Ps::ProvidedIter<'a> where Self: 'a;

    fn get(&self, key: &Key) -> Option<Cow<'_, Record>> {
        self.record_storage.get(key)
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        self.record_storage.put(record)
    }

    fn remove(&mut self, key: &Key) {
        self.record_storage.remove(key)
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        // We don't use Kademlia's periodic replication
        iter::empty()
    }

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        self.provider_storage.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.provider_storage.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.provider_storage.provided()
    }

    fn remove_provider(&mut self, key: &Key, provider: &PeerId) {
        self.provider_storage.remove_provider(key, provider)
    }
}
