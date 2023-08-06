use super::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::ProviderRecord;

/// Stub provider storage implementation.
/// All operations have no effect or return empty collections/iterators.
pub struct VoidProviderStorage;

impl ProviderStorage for VoidProviderStorage {
    fn providers(&self, _: &Key) -> Vec<ProviderRecord> {
        Default::default()
    }
}
