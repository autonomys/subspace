mod providers;

use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::PeerId;
#[cfg(test)]
pub(crate) use providers::{instant_to_micros, micros_to_instant};
pub use providers::{MemoryProviderStorage, ParityDbProviderStorage};
use std::borrow::Cow;
use std::iter;
use std::iter::Empty;

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
pub struct CustomRecordStore<ProviderStorage> {
    provider_storage: ProviderStorage,
}

impl<ProviderStorage> CustomRecordStore<ProviderStorage> {
    pub fn new(provider_storage: ProviderStorage) -> Self {
        Self { provider_storage }
    }
}

impl<Ps: ProviderStorage> RecordStore for CustomRecordStore<Ps> {
    type RecordsIter<'a> = Empty<Cow<'a, Record>> where Self: 'a;
    type ProvidedIter<'a> = Ps::ProvidedIter<'a> where Self: 'a;

    fn get(&self, _key: &Key) -> Option<Cow<'_, Record>> {
        // Not supported
        None
    }

    fn put(&mut self, _record: Record) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn remove(&mut self, _key: &Key) {
        // Not supported
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
