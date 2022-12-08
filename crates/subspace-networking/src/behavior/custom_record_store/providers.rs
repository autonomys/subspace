use super::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::store::{MemoryStoreConfig, RecordStore};
use libp2p::kad::{store, ProviderRecord, K_VALUE};
use libp2p::PeerId;
use std::borrow::Cow;
use std::collections::hash_set;
use std::iter;
use tracing::trace;

// Defines max provider records number. Each provider record is expected to be less than 1KB.
const MEMORY_STORE_PROVIDED_KEY_LIMIT: usize = 100000; // ~100 MB

/// Memory based provider records storage.
pub struct MemoryProviderStorage {
    inner: store::MemoryStore,
}

impl MemoryProviderStorage {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            inner: store::MemoryStore::with_config(
                peer_id,
                MemoryStoreConfig {
                    max_records: 0,
                    max_value_bytes: 0,
                    max_providers_per_key: K_VALUE.get(),
                    max_provided_keys: MEMORY_STORE_PROVIDED_KEY_LIMIT,
                },
            ),
        }
    }
}

impl<'a> ProviderStorage<'a> for MemoryProviderStorage {
    type ProvidedIter = iter::Map<
        hash_set::Iter<'a, ProviderRecord>,
        fn(&'a ProviderRecord) -> Cow<'a, ProviderRecord>,
    >;

    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        self.inner.add_provider(record)
    }

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        self.inner.provided()
    }

    fn remove_provider(&'a mut self, key: &Key, provider: &PeerId) {
        trace!(?key, ?provider, "Provider record removed.");

        self.inner.remove_provider(key, provider)
    }
}
