use super::persistent_parameters::remove_known_peer_addresses_internal;
use crate::behavior::custom_record_store::{
    CustomRecordStore, GSet, MemoryProviderStorage, NoRecordStorage,
};
use chrono::Duration;
use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::ProviderRecord;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeSet, HashSet};

#[tokio::test()]
async fn test_address_timed_removal_from_known_peers_cache() {
    // Cache initialization
    let peer_id = PeerId::random();
    let addr1 = Multiaddr::empty().with(Protocol::Memory(0));
    let addr2 = Multiaddr::empty().with(Protocol::Memory(1));
    let addresses = vec![addr1.clone(), addr2.clone()];
    let expiration = Duration::nanoseconds(1);

    let mut peers_cache = LruCache::new(100);
    let mut addresses_cache = LruCache::new(100);

    for addr in addresses.clone() {
        addresses_cache.push(addr, None);
    }

    peers_cache.push(peer_id, addresses_cache);

    //Precondition-check
    assert_eq!(peers_cache.len(), 1);
    let addresses_from_cache = peers_cache.get(&peer_id).expect("PeerId present");
    assert_eq!(addresses_from_cache.len(), 2);
    assert!(addresses_from_cache
        .peek(&addr1)
        .expect("Address present")
        .is_none());
    assert!(addresses_from_cache
        .peek(&addr2)
        .expect("Address present")
        .is_none());

    remove_known_peer_addresses_internal(&mut peers_cache, peer_id, addresses.clone(), expiration);

    // Check after the first run (set the first failure time)
    assert_eq!(peers_cache.len(), 1);
    let addresses_from_cache = peers_cache.get(&peer_id).expect("PeerId present");
    assert_eq!(addresses_from_cache.len(), 2);
    assert!(addresses_from_cache
        .peek(&addr1)
        .expect("Address present")
        .is_some());
    assert!(addresses_from_cache
        .peek(&addr2)
        .expect("Address present")
        .is_some());

    remove_known_peer_addresses_internal(&mut peers_cache, peer_id, addresses, expiration);

    // Check after the second run (clean cache)
    assert_eq!(peers_cache.len(), 0);
}

#[allow(clippy::mutable_key_type)] // we use hash set for sorting to compare collections
#[test]
fn check_custom_store_api() {
    let mut store = CustomRecordStore::new(NoRecordStorage, MemoryProviderStorage::default());

    let key1: Key = b"key1".to_vec().into();
    let provider1 = PeerId::random();
    let rec1 = ProviderRecord {
        provider: provider1,
        key: key1,
        expires: None,
        addresses: Vec::new(),
    };

    let key2: Key = b"key2".to_vec().into();
    let provider2 = PeerId::random();
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
    store.add_provider(rec1.clone()).unwrap();
    store.add_provider(rec2.clone()).unwrap();
    store.add_provider(rec3.clone()).unwrap();

    // Check providers retrieval
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(store.provided().map(|i| i.into_owned()));

    assert_eq!(
        HashSet::from_iter(vec![rec1, rec2.clone(), rec3.clone()].into_iter()),
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

#[test]
fn gset_works_as_expected() {
    let gset1 = GSet::from_single(1);
    let gset2 = GSet::from_single(1);
    let gset3 = GSet::from_single(2);
    let gset4 = GSet::from_single(3);

    let gset13 = gset1.merge(gset3);
    let gset24 = gset2.merge(gset4);

    let merged_gset = gset13.merge(gset24);

    assert_eq!(merged_gset.values(), BTreeSet::from_iter(vec![1, 2, 3]));

    let encoded = merged_gset.encode();

    let decoded_gset = GSet::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(merged_gset, decoded_gset);
}
