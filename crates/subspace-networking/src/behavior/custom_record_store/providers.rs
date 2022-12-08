use super::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::{store, ProviderRecord};
use libp2p::PeerId;
use std::borrow::Cow;
use std::collections::HashMap;
use std::iter::IntoIterator;
use std::vec;
use tracing::trace;

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
