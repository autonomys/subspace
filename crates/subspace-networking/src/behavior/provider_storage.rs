mod providers;

use libp2p::kad::record::Key;
use libp2p::kad::ProviderRecord;
pub use providers::VoidProviderStorage;

/// A trait for providers storages - wrapper around `provider` functions of the libp2p RecordStore.
pub trait ProviderStorage {
    /// Gets a copy of the stored provider records for the given key.
    fn providers(&self, key: &Key) -> Vec<ProviderRecord>;
}
