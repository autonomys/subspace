use std::borrow::Cow;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::ProviderStorage;

pub(crate) struct NodeProviderStorage<FixedProviderStorage, PersistentProviderStorage> {
    // provider records from local cache
    fixed_provider_storage: FixedProviderStorage,
    // external provider records
    external_provider_storage: PersistentProviderStorage,
}

impl<FixedProviderStorage, ExternalProviderStorage>
    NodeProviderStorage<FixedProviderStorage, ExternalProviderStorage>
{
    pub(crate) fn new(
        fixed_provider_storage: FixedProviderStorage,
        external_provider_storage: ExternalProviderStorage,
    ) -> Self {
        Self {
            fixed_provider_storage,
            external_provider_storage,
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
        self.external_provider_storage.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let mut local_provider_records = self.fixed_provider_storage.providers(key);
        let mut external_provider_records = self.external_provider_storage.providers(key);

        local_provider_records.append(&mut external_provider_records);

        local_provider_records
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // only local cached provider records
        self.fixed_provider_storage.provided()
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        // only external provider records
        self.external_provider_storage.remove_provider(key, peer_id)
    }
}
