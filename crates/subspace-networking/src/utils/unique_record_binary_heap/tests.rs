use crate::utils::unique_record_binary_heap::UniqueRecordBinaryHeap;
use libp2p::kad::record::Key;
use libp2p::PeerId;

#[test]
fn binary_heap_insert_works() {
    let peer_id = PeerId::random();
    let mut heap = UniqueRecordBinaryHeap::new(peer_id, 10);

    assert_eq!(heap.size(), 0);

    let key1 = Key::from(vec![1]);
    let key2 = Key::from(vec![2]);

    heap.insert(key1);
    assert_eq!(heap.size(), 1);

    heap.insert(key2.clone());
    assert_eq!(heap.size(), 2);

    // Duplicates are ignored
    heap.insert(key2);
    assert_eq!(heap.size(), 2);
}

#[test]
fn binary_heap_remove_works() {
    let peer_id = PeerId::random();
    let mut heap = UniqueRecordBinaryHeap::new(peer_id, 10);

    let key1 = Key::from(vec![1]);
    let key2 = Key::from(vec![2]);

    heap.insert(key1.clone());
    assert_eq!(heap.size(), 1);

    heap.remove(&key2);
    assert_eq!(heap.size(), 1);

    heap.remove(&key1);
    assert_eq!(heap.size(), 0);
}

#[test]
fn binary_heap_limit_works() {
    let peer_id = PeerId::random();
    let mut heap = UniqueRecordBinaryHeap::new(peer_id, 1);

    let key1 = Key::from(vec![1]);
    let key2 = Key::from(vec![2]);

    let evicted = heap.insert(key1);
    assert!(evicted.is_none());
    assert_eq!(heap.size(), 1);

    let evicted = heap.insert(key2);
    assert!(evicted.is_some());
    assert_eq!(heap.size(), 1);
}

#[test]
fn binary_heap_eviction_works() {
    type KademliaBucketKey<T> = libp2p::kad::KBucketKey<T>;

    let peer_id = PeerId::random();
    let mut heap = UniqueRecordBinaryHeap::new(peer_id, 1);

    let key1 = Key::from(vec![1]);
    let key2 = Key::from(vec![2]);

    heap.insert(key1.clone());
    let should_be_evicted = heap.should_include_key(&key2);
    let evicted = heap.insert(key2.clone());
    assert!(evicted.is_some());

    let bucket_key1: KademliaBucketKey<Key> = KademliaBucketKey::new(key1.clone());
    let bucket_key2: KademliaBucketKey<Key> = KademliaBucketKey::new(key2.clone());

    let evicted = evicted.unwrap();
    if bucket_key1.distance::<KademliaBucketKey<_>>(&KademliaBucketKey::from(peer_id))
        > bucket_key2.distance::<KademliaBucketKey<_>>(&KademliaBucketKey::from(peer_id))
    {
        assert!(should_be_evicted);
        assert_eq!(evicted, key1);
    } else {
        assert!(!should_be_evicted);
        assert_eq!(evicted, key2);
    }
}

#[test]
fn binary_heap_should_include_key_works() {
    let peer_id = PeerId::random();
    let mut heap = UniqueRecordBinaryHeap::new(peer_id, 1);

    // Limit not reached
    let key1 = Key::from(vec![1]);
    assert!(heap.should_include_key(&key1));

    // Limit reached and key is not "less" than top key
    heap.insert(key1.clone());
    assert!(!heap.should_include_key(&key1));

    // Limit reached and key is "less" than top key
    let key2 = Key::from(vec![2]);
    assert!(heap.should_include_key(&key2));
}
