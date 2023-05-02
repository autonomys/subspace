use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::ProviderStorage;

pub struct NodeProviderStorage<ImplicitProviderStorage, PersistentProviderStorage> {
    local_peer_id: PeerId,
    /// Provider records from local cache
    implicit_provider_storage: ImplicitProviderStorage,
    /// External provider records
    persistent_provider_storage: PersistentProviderStorage,
}

impl<ImplicitProviderStorage: Clone, PersistentProviderStorage: Clone> Clone
    for NodeProviderStorage<ImplicitProviderStorage, PersistentProviderStorage>
{
    fn clone(&self) -> Self {
        Self {
            local_peer_id: self.local_peer_id,
            implicit_provider_storage: self.implicit_provider_storage.clone(),
            persistent_provider_storage: self.persistent_provider_storage.clone(),
        }
    }
}

impl<ImplicitProviderStorage, PersistentProviderStorage>
    NodeProviderStorage<ImplicitProviderStorage, PersistentProviderStorage>
where
    PersistentProviderStorage: ProviderStorage,
{
    pub fn new(
        local_peer_id: PeerId,
        implicit_provider_storage: ImplicitProviderStorage,
        persistent_provider_storage: PersistentProviderStorage,
    ) -> Self {
        Self {
            local_peer_id,
            implicit_provider_storage,
            persistent_provider_storage,
        }
    }
}

impl<ImplicitProviderStorage, PersistentProviderStorage> ProviderStorage
    for NodeProviderStorage<ImplicitProviderStorage, PersistentProviderStorage>
where
    ImplicitProviderStorage: ProviderStorage,
    PersistentProviderStorage: ProviderStorage,
{
    type ProvidedIter<'a> = ImplicitProviderStorage::ProvidedIter<'a> where Self:'a;

    fn add_provider(
        &mut self,
        record: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        // Local providers are implicit and should not be put into persistent storage
        if record.provider != self.local_peer_id {
            self.persistent_provider_storage.add_provider(record)
        } else {
            Ok(())
        }
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let mut local_provider_records = self.implicit_provider_storage.providers(key);
        let mut external_provider_records = self.persistent_provider_storage.providers(key);

        local_provider_records.append(&mut external_provider_records);

        local_provider_records
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // Only provider records cached locally
        self.implicit_provider_storage.provided()
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        self.persistent_provider_storage
            .remove_provider(key, peer_id);
    }
}
