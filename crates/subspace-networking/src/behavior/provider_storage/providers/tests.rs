use super::MemoryProviderStorage;
use crate::ProviderStorage;
use libp2p::kad::record::Key;
use libp2p::kad::ProviderRecord;
use libp2p::PeerId;
use std::collections::HashSet;

#[allow(clippy::mutable_key_type)] // we use hash set for sorting to compare collections
#[test]
fn memory_storage_provider() {
    let local_peer_id = PeerId::random();
    let mut store = MemoryProviderStorage::new(local_peer_id);

    let key1: Key = b"key1".to_vec().into();
    let provider1 = PeerId::random();
    let rec1 = ProviderRecord {
        provider: provider1,
        key: key1,
        expires: None,
        addresses: Vec::new(),
    };

    let key2: Key = b"key2".to_vec().into();
    let provider2 = local_peer_id;
    let rec2 = ProviderRecord {
        provider: provider2,
        key: key2.clone(),
        expires: None,
        addresses: Vec::new(),
    };

    let provider3 = PeerId::random();
    let rec3 = ProviderRecord {
        provider: provider3,
        key: key2.clone(),
        expires: None,
        addresses: Vec::new(),
    };

    // Check adding
    store.add_provider(rec1).unwrap();
    store.add_provider(rec2.clone()).unwrap();
    store.add_provider(rec3.clone()).unwrap();

    // Check local providers retrieval
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(store.provided().map(|i| i.into_owned()));

    println!("{:?}", store.provided());

    assert_eq!(
        HashSet::from_iter(vec![rec2.clone()].into_iter()),
        provided_collection
    );

    // Check single provider retrieval
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(store.providers(&key2).into_iter());

    assert_eq!(
        HashSet::from_iter(vec![rec2.clone(), rec3].into_iter()),
        provided_collection
    );

    // Remove provider
    store.remove_provider(&key2, &provider3);
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(store.providers(&key2).into_iter());

    assert_eq!(
        HashSet::from_iter(vec![rec2].into_iter()),
        provided_collection
    );
}
