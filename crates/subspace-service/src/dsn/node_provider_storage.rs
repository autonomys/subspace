use std::borrow::Cow;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::ProviderStorage;

pub(crate) struct NodeProviderStorage<FixedProviderStorage, PersistentProviderStorage> {
    /// Provider records from local cache
    implicit_provider_storage: FixedProviderStorage,
    /// External provider records
    persistent_provider_storage: PersistentProviderStorage,
}

impl<FixedProviderStorage, ExternalProviderStorage>
    NodeProviderStorage<FixedProviderStorage, ExternalProviderStorage>
{
    pub(crate) fn new(
        implicit_provider_storage: FixedProviderStorage,
        persistent_provider_storage: ExternalProviderStorage,
    ) -> Self {
        Self {
            implicit_provider_storage,
            persistent_provider_storage,
        }
    }
}

impl<FixedProviderStorage, PersistentProviderStorage> ProviderStorage
    for NodeProviderStorage<FixedProviderStorage, PersistentProviderStorage>
where
    FixedProviderStorage: ProviderStorage,
    PersistentProviderStorage: ProviderStorage,
{
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>> where Self:'a;

    fn add_provider(
        &mut self,
        record: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        // only external provider records
        self.persistent_provider_storage.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let mut local_provider_records = self.implicit_provider_storage.providers(key);
        let mut external_provider_records = self.persistent_provider_storage.providers(key);

        local_provider_records.append(&mut external_provider_records);

        local_provider_records
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // only local cached provider records
        self.implicit_provider_storage.provided()
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        // only external provider records
        self.persistent_provider_storage
            .remove_provider(key, peer_id)
    }
}
