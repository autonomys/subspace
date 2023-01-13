mod providers;

use libp2p::kad::record::Key;
use libp2p::kad::{store, ProviderRecord};
use libp2p::PeerId;
#[cfg(test)]
pub(crate) use providers::{instant_to_micros, micros_to_instant};
pub use providers::{MemoryProviderStorage, ParityDbProviderStorage};
use std::borrow::Cow;

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
