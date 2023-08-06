#[cfg(test)]
mod tests;

use super::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::store::{MemoryStoreConfig, RecordStore};
use libp2p::kad::{store, ProviderRecord, K_VALUE};
use libp2p::PeerId;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::iter;
use std::sync::Arc;
use std::vec::IntoIter;
use tracing::trace;

// Defines max provider records number. Each provider record is expected to be less than 1KB.
const MEMORY_STORE_PROVIDED_KEY_LIMIT: usize = 100000; // ~100 MB

/// Stub provider storage implementation.
/// All operations have no effect or return empty collections/iterators.
pub struct VoidProviderStorage;

impl ProviderStorage for VoidProviderStorage {
    type ProvidedIter<'a> = iter::Empty<Cow<'a, ProviderRecord>>;

    fn add_provider(&self, _: ProviderRecord) -> store::Result<()> {
        Ok(())
    }

    fn providers(&self, _: &Key) -> Vec<ProviderRecord> {
        Default::default()
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        iter::empty()
    }

    fn remove_provider(&self, _: &Key, _: &PeerId) {}
}

/// Memory based provider records storage.
#[derive(Clone)]
pub struct MemoryProviderStorage {
    inner: Arc<Mutex<store::MemoryStore>>,
}

impl MemoryProviderStorage {
    /// Create new memory based provider records storage.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            inner: Arc::new(Mutex::new(store::MemoryStore::with_config(
                peer_id,
                MemoryStoreConfig {
                    max_records: 0,
                    max_value_bytes: 0,
                    max_providers_per_key: K_VALUE.get(),
                    max_provided_keys: MEMORY_STORE_PROVIDED_KEY_LIMIT,
                },
            ))),
        }
    }
}

impl ProviderStorage for MemoryProviderStorage {
    type ProvidedIter<'a> = iter::Map<
        IntoIter<ProviderRecord>,
        fn(ProviderRecord) -> Cow<'a, ProviderRecord>,
    > where Self:'a;

    fn add_provider(&self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        self.inner.lock().add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.inner.lock().providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // We copy records here. The downstream usage of this method is a relatively rare periodic job.
        let records = {
            self.inner
                .lock()
                .provided()
                .map(|item| item.into_owned())
                .collect::<Vec<_>>()
        };

        records.into_iter().map(Cow::Owned)
    }

    fn remove_provider(&self, key: &Key, provider: &PeerId) {
        trace!(?key, ?provider, "Provider record removed.");

        self.inner.lock().remove_provider(key, provider)
    }
}
