use libp2p::kad::record::Key;
use libp2p::kad::store::{Error, RecordStore};
use libp2p::kad::{store, ProviderRecord, Record};
use libp2p::multihash::Multihash;
use libp2p::PeerId;
use std::borrow::Cow;
use std::sync::Arc;
use std::vec;

pub type ValueGetter = Arc<dyn (Fn(&Multihash) -> Option<Vec<u8>>) + Send + Sync + 'static>;

/// Hacky replacement for Kademlia's record store that doesn't store anything and instead proxies
/// gets to externally provided implementation.
#[derive(Clone)]
pub(crate) struct CustomRecordStore {
    value_getter: ValueGetter,
}

impl CustomRecordStore {
    pub(super) fn new(value_getter: ValueGetter) -> Self {
        Self { value_getter }
    }
}

impl<'a> RecordStore<'a> for CustomRecordStore {
    type RecordsIter = vec::IntoIter<Cow<'a, Record>>;
    type ProvidedIter = vec::IntoIter<Cow<'a, ProviderRecord>>;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let multihash_key = Multihash::from_bytes(key.as_ref()).ok()?;
        (self.value_getter)(&multihash_key)
            .map(|value| Record {
                key: key.clone(),
                value,
                publisher: None,
                expires: None,
            })
            .map(Cow::Owned)
    }

    fn put(&'a mut self, _record: Record) -> store::Result<()> {
        // Don't allow to store values.
        Err(Error::MaxRecords)
    }

    fn remove(&'a mut self, _key: &Key) {
        // Nothing to remove
    }

    fn records(&'a self) -> Self::RecordsIter {
        // No iteration support for now.
        Vec::new().into_iter()
    }

    fn add_provider(&'a mut self, _record: ProviderRecord) -> store::Result<()> {
        // Don't allow to store providers.
        Err(Error::MaxProvidedKeys)
    }

    fn providers(&'a self, _key: &Key) -> Vec<ProviderRecord> {
        // No providers here.
        Vec::new()
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        // Nothing is provided.
        Vec::new().into_iter()
    }

    fn remove_provider(&'a mut self, _key: &Key, _provider: &PeerId) {}
}
