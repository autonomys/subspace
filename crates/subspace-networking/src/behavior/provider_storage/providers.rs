use super::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::{store, ProviderRecord};
use libp2p::PeerId;
use std::borrow::Cow;
use std::iter;

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
