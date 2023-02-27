use super::persistent_parameters::remove_known_peer_addresses_internal;
use crate::behavior::provider_storage::{instant_to_micros, micros_to_instant};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant, SystemTime};

#[tokio::test()]
async fn test_address_timed_removal_from_known_peers_cache() {
    // Cache initialization
    let peer_id = PeerId::random();
    let addr1 = Multiaddr::empty().with(Protocol::Memory(0));
    let addr2 = Multiaddr::empty().with(Protocol::Memory(1));
    let addresses = vec![addr1.clone(), addr2.clone()];
    let expiration = chrono::Duration::nanoseconds(1);

    let mut peers_cache = LruCache::new(NonZeroUsize::new(100).unwrap());
    let mut addresses_cache = LruCache::new(NonZeroUsize::new(100).unwrap());

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

#[test]
fn instant_conversion() {
    let inst1 = Instant::now();
    let ms = instant_to_micros(inst1);
    let inst2 = micros_to_instant(ms).unwrap();

    assert!(inst1.saturating_duration_since(inst2) < Duration::from_millis(1));
    assert!(inst2.saturating_duration_since(inst1) < Duration::from_millis(1));
}

#[test]
fn instant_conversion_edge_cases() {
    assert!(micros_to_instant(u64::MAX).is_none());
    assert!(micros_to_instant(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
            * 2
    )
    .is_none());
}
